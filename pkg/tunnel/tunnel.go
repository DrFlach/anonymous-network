package tunnel

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"sync"
	"time"

	"network/pkg/crypto"
	"network/pkg/util"
)

// Direction represents tunnel direction
type Direction int

const (
	Inbound  Direction = iota // Tunnel receives data from network toward us
	Outbound                  // Tunnel sends data from us toward network
)

// TunnelID is a unique identifier for a tunnel
type TunnelID uint32

// GenerateTunnelID generates a random tunnel ID
func GenerateTunnelID() TunnelID {
	var buf [4]byte
	rand.Read(buf[:])
	return TunnelID(binary.BigEndian.Uint32(buf[:]))
}

// HopInfo represents one hop in a tunnel
type HopInfo struct {
	RouterHash    [32]byte // Identity of the hop router
	TunnelID      TunnelID // Tunnel ID on this hop
	EncryptionKey [32]byte // Symmetric key for this hop (derived from DH)
	IVKey         [32]byte // IV derivation key for this hop
	NextHop       [32]byte // Next router in the chain (zero for endpoint)
	NextTunnelID  TunnelID // Tunnel ID on the next hop
	IsEndpoint    bool     // True if this is the last hop
}

// Tunnel represents an established tunnel (chain of hops)
type Tunnel struct {
	ID        TunnelID
	Direction Direction
	Hops      []*HopInfo
	CreatedAt time.Time
	ExpiresAt time.Time
	LayerKeys [][32]byte // Encryption keys in order (for onion encrypt/decrypt)
	Gateway   [32]byte   // First hop router hash
	Endpoint  [32]byte   // Last hop router hash
	IsReady   bool
	mu        sync.RWMutex
}

// NewTunnel creates a new tunnel structure
func NewTunnel(direction Direction, hops []*HopInfo, lifetime time.Duration) *Tunnel {
	now := time.Now()

	keys := make([][32]byte, len(hops))
	for i, hop := range hops {
		keys[i] = hop.EncryptionKey
	}

	var gateway, endpoint [32]byte
	if len(hops) > 0 {
		gateway = hops[0].RouterHash
		endpoint = hops[len(hops)-1].RouterHash
	}

	return &Tunnel{
		ID:        GenerateTunnelID(),
		Direction: direction,
		Hops:      hops,
		CreatedAt: now,
		ExpiresAt: now.Add(lifetime),
		LayerKeys: keys,
		Gateway:   gateway,
		Endpoint:  endpoint,
		IsReady:   false,
	}
}

// IsExpired returns true if the tunnel has expired
func (t *Tunnel) IsExpired() bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return time.Now().After(t.ExpiresAt)
}

// EncryptOutbound encrypts data through all tunnel layers (for outbound tunnels)
// Data is encrypted from innermost (endpoint) to outermost (gateway) layer
func (t *Tunnel) EncryptOutbound(data []byte) ([]byte, error) {
	t.mu.RLock()
	defer t.mu.RUnlock()

	return crypto.EncryptLayered(data, t.LayerKeys)
}

// DecryptInbound decrypts one layer of an inbound tunnel message
func (t *Tunnel) DecryptInbound(data []byte, hopIndex int) ([]byte, error) {
	t.mu.RLock()
	defer t.mu.RUnlock()

	if hopIndex >= len(t.LayerKeys) {
		return nil, fmt.Errorf("invalid hop index")
	}

	return crypto.DecryptLayer(data, t.LayerKeys[hopIndex])
}

// TunnelMessage represents data being sent through a tunnel
type TunnelMessage struct {
	TunnelID    TunnelID
	Data        []byte
	FragmentNum uint8
	IsLast      bool
}

// SerializeTunnelMessage converts a tunnel message to bytes
func SerializeTunnelMessage(msg *TunnelMessage) []byte {
	// Format: [TunnelID:4][FragNum:1][Flags:1][DataLen:2][Data:...]
	buf := make([]byte, 8+len(msg.Data))
	binary.BigEndian.PutUint32(buf[0:4], uint32(msg.TunnelID))
	buf[4] = msg.FragmentNum
	flags := byte(0)
	if msg.IsLast {
		flags |= 0x01
	}
	buf[5] = flags
	binary.BigEndian.PutUint16(buf[6:8], uint16(len(msg.Data)))
	copy(buf[8:], msg.Data)
	return buf
}

// DeserializeTunnelMessage parses a tunnel message from bytes
func DeserializeTunnelMessage(data []byte) (*TunnelMessage, error) {
	if len(data) < 8 {
		return nil, fmt.Errorf("tunnel message too short")
	}

	msg := &TunnelMessage{
		TunnelID:    TunnelID(binary.BigEndian.Uint32(data[0:4])),
		FragmentNum: data[4],
		IsLast:      data[5]&0x01 != 0,
	}

	dataLen := binary.BigEndian.Uint16(data[6:8])
	if len(data) < int(8+dataLen) {
		return nil, fmt.Errorf("tunnel message data truncated")
	}

	msg.Data = make([]byte, dataLen)
	copy(msg.Data, data[8:8+dataLen])

	return msg, nil
}

// TunnelParticipant represents this router's role in someone else's tunnel
type TunnelParticipant struct {
	ReceiveTunnelID TunnelID // Tunnel ID we receive on
	SendTunnelID    TunnelID // Tunnel ID we forward to
	NextHop         [32]byte // Next router to forward to
	LayerKey        [32]byte // Our decryption key for this tunnel
	IVKey           [32]byte
	IsEndpoint      bool // True if we are the tunnel endpoint
	IsGateway       bool // True if we are the tunnel gateway
	CreatedAt       time.Time
	ExpiresAt       time.Time
}

// TunnelParticipantStore stores tunnel participations
type TunnelParticipantStore struct {
	participants map[TunnelID]*TunnelParticipant
	mu           sync.RWMutex
	logger       *util.Logger
}

// NewTunnelParticipantStore creates a new store
func NewTunnelParticipantStore() *TunnelParticipantStore {
	return &TunnelParticipantStore{
		participants: make(map[TunnelID]*TunnelParticipant),
		logger:       util.GetLogger(),
	}
}

// Add adds a tunnel participation
func (s *TunnelParticipantStore) Add(p *TunnelParticipant) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.participants[p.ReceiveTunnelID] = p
	s.logger.Debug("Added tunnel participation: recv=%d send=%d endpoint=%v",
		p.ReceiveTunnelID, p.SendTunnelID, p.IsEndpoint)
}

// Get returns a tunnel participation by receive tunnel ID
func (s *TunnelParticipantStore) Get(tunnelID TunnelID) (*TunnelParticipant, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	p, ok := s.participants[tunnelID]
	return p, ok
}

// Remove removes a tunnel participation
func (s *TunnelParticipantStore) Remove(tunnelID TunnelID) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.participants, tunnelID)
}

// CleanExpired removes expired participations
func (s *TunnelParticipantStore) CleanExpired() int {
	s.mu.Lock()
	defer s.mu.Unlock()

	count := 0
	now := time.Now()
	for id, p := range s.participants {
		if now.After(p.ExpiresAt) {
			delete(s.participants, id)
			count++
		}
	}
	return count
}

// ProcessMessage decrypts one layer and determines where to forward
func (s *TunnelParticipantStore) ProcessMessage(tunnelID TunnelID, data []byte) (nextHop [32]byte, nextTunnelID TunnelID, processedData []byte, isEndpoint bool, err error) {
	p, ok := s.Get(tunnelID)
	if !ok {
		return [32]byte{}, 0, nil, false, fmt.Errorf("unknown tunnel ID: %d", tunnelID)
	}

	// Check expiration
	if time.Now().After(p.ExpiresAt) {
		s.Remove(tunnelID)
		return [32]byte{}, 0, nil, false, fmt.Errorf("tunnel expired")
	}

	// Decrypt one layer
	decrypted, err := crypto.DecryptLayer(data, p.LayerKey)
	if err != nil {
		return [32]byte{}, 0, nil, false, fmt.Errorf("failed to decrypt tunnel layer: %w", err)
	}

	if p.IsEndpoint {
		return p.NextHop, p.SendTunnelID, decrypted, true, nil
	}

	return p.NextHop, p.SendTunnelID, decrypted, false, nil
}
