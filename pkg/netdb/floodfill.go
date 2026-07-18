package netdb

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"sync"
	"time"

	"network/pkg/util"
)

// MaxFloodTTL is the maximum number of hops a flooded RouterInfo can travel.
// This prevents infinite propagation across large networks.
const MaxFloodTTL = 4

const (
	maxRouterInfoDataLen = 64 * 1024
	maxRouterAddrs       = 32
	maxRouterHostLen     = 255
	maxRouterCaps        = 64
	maxRouterCapLen      = 64
	maxRouterSignature   = 256
	maxRouterInfoBatch   = 500
)

// FloodfillManager handles the distributed hash table (DHT) for RouterInfo propagation
type FloodfillManager struct {
	store       *Store
	isFloodfill bool
	logger      *util.Logger
	mu          sync.RWMutex
	sendFunc    func(routerHash [32]byte, data []byte) error // Callback to send data to a peer
	knownHashes map[[32]byte]time.Time                       // Track what we've seen to avoid loops
	hashMu      sync.RWMutex
}

// NewFloodfillManager creates a new floodfill manager
func NewFloodfillManager(store *Store, isFloodfill bool) *FloodfillManager {
	return &FloodfillManager{
		store:       store,
		isFloodfill: isFloodfill,
		logger:      util.GetLogger(),
		knownHashes: make(map[[32]byte]time.Time),
	}
}

// SetSendFunc sets the function used to send data to peers
func (fm *FloodfillManager) SetSendFunc(f func(routerHash [32]byte, data []byte) error) {
	fm.mu.Lock()
	defer fm.mu.Unlock()
	fm.sendFunc = f
}

// HandleDatabaseStore processes a received RouterInfo store request (backward compat, TTL=MaxFloodTTL)
func (fm *FloodfillManager) HandleDatabaseStore(data []byte) error {
	return fm.HandleDatabaseStoreWithTTL(data, MaxFloodTTL)
}

// HandleDatabaseStoreWithTTL processes a received RouterInfo store request with a TTL.
// TTL is decremented on each hop; when it reaches 0, propagation stops.
func (fm *FloodfillManager) HandleDatabaseStoreWithTTL(data []byte, ttl int) error {
	ri, err := DeserializeRouterInfo(data)
	if err != nil {
		return fmt.Errorf("failed to deserialize RouterInfo: %w", err)
	}

	// Verify signature
	if !ri.Verify() {
		return fmt.Errorf("invalid RouterInfo signature")
	}

	// Check if expired
	if ri.IsExpired() {
		return fmt.Errorf("RouterInfo is expired")
	}

	// Check if we've seen this recently (flood protection)
	if fm.recentlySeen(ri.RouterHash) {
		return nil // Already processed, silently ignore
	}
	fm.markSeen(ri.RouterHash)

	// Store it
	if err := fm.store.Add(ri); err != nil {
		return fmt.Errorf("failed to store RouterInfo: %w", err)
	}

	// If we're a floodfill router and TTL > 0, propagate to other floodfill routers
	if fm.isFloodfill && ttl > 0 {
		fm.flood(ri, data)
	}

	fm.logger.Debug("Stored RouterInfo for %x from network (TTL=%d)", ri.RouterHash[:8], ttl)
	return nil
}

// HandleDatabaseLookup processes a lookup request for a RouterInfo
func (fm *FloodfillManager) HandleDatabaseLookup(requestData []byte) ([]byte, error) {
	if len(requestData) < 32 {
		return nil, fmt.Errorf("lookup request too short")
	}

	var targetHash [32]byte
	copy(targetHash[:], requestData[:32])

	ri, err := fm.store.Get(targetHash)
	if err != nil {
		// Return list of closest routers instead
		return fm.buildSearchReply(targetHash)
	}

	// Serialize and return the RouterInfo
	return SerializeRouterInfo(ri), nil
}

// PublishRouterInfo publishes our RouterInfo to the network
func (fm *FloodfillManager) PublishRouterInfo(ri *RouterInfo) error {
	data := SerializeRouterInfo(ri)

	// Store locally
	if err := fm.store.Add(ri); err != nil {
		return fmt.Errorf("failed to store local RouterInfo: %w", err)
	}

	// Send to all connected floodfill peers
	floodfills := fm.store.GetFloodfills()
	fm.mu.RLock()
	sendFunc := fm.sendFunc
	fm.mu.RUnlock()

	if sendFunc == nil {
		return nil // No send function set yet
	}

	for _, ff := range floodfills {
		if ff.RouterHash == ri.RouterHash {
			continue // Don't send to ourselves
		}

		if err := sendFunc(ff.RouterHash, data); err != nil {
			fm.logger.Debug("Failed to publish RouterInfo to %x: %v", ff.RouterHash[:8], err)
		}
	}

	fm.logger.Debug("Published RouterInfo to %d floodfill peers", len(floodfills))
	return nil
}

// flood propagates a RouterInfo to other floodfill routers
func (fm *FloodfillManager) flood(ri *RouterInfo, data []byte) {
	floodfills := fm.store.GetFloodfills()
	fm.mu.RLock()
	sendFunc := fm.sendFunc
	fm.mu.RUnlock()

	if sendFunc == nil {
		return
	}

	for _, ff := range floodfills {
		if ff.RouterHash == ri.RouterHash {
			continue
		}

		if err := sendFunc(ff.RouterHash, data); err != nil {
			fm.logger.Debug("Failed to flood RouterInfo to %x: %v", ff.RouterHash[:8], err)
		}
	}
}

// buildSearchReply builds a response with closest known routers
func (fm *FloodfillManager) buildSearchReply(target [32]byte) ([]byte, error) {
	routers := fm.store.GetRandom(3) // Return up to 3 closest routers

	buf := new(bytes.Buffer)
	// Write number of results
	binary.Write(buf, binary.BigEndian, uint8(len(routers)))

	for _, ri := range routers {
		data := SerializeRouterInfo(ri)
		binary.Write(buf, binary.BigEndian, uint16(len(data)))
		buf.Write(data)
	}

	return buf.Bytes(), nil
}

func (fm *FloodfillManager) recentlySeen(hash [32]byte) bool {
	fm.hashMu.RLock()
	defer fm.hashMu.RUnlock()

	seen, ok := fm.knownHashes[hash]
	if !ok {
		return false
	}

	// Consider "recent" if seen in the last 5 minutes
	return time.Since(seen) < 5*time.Minute
}

func (fm *FloodfillManager) markSeen(hash [32]byte) {
	fm.hashMu.Lock()
	defer fm.hashMu.Unlock()
	fm.knownHashes[hash] = time.Now()
}

// CleanSeenHashes removes old entries from the seen hash table
func (fm *FloodfillManager) CleanSeenHashes() {
	fm.hashMu.Lock()
	defer fm.hashMu.Unlock()

	cutoff := time.Now().Add(-10 * time.Minute)
	for hash, seen := range fm.knownHashes {
		if seen.Before(cutoff) {
			delete(fm.knownHashes, hash)
		}
	}
}

// SerializeRouterInfo converts a RouterInfo to bytes for transmission
func SerializeRouterInfo(ri *RouterInfo) []byte {
	data := ri.Serialize()
	// Append signature
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.BigEndian, uint16(len(data)))
	buf.Write(data)
	binary.Write(buf, binary.BigEndian, uint16(len(ri.Signature)))
	buf.Write(ri.Signature)
	return buf.Bytes()
}

// DeserializeRouterInfo parses a RouterInfo from transmission bytes
func DeserializeRouterInfo(data []byte) (*RouterInfo, error) {
	if len(data) < 4 {
		return nil, fmt.Errorf("data too short for RouterInfo")
	}

	buf := bytes.NewReader(data)

	// Read data length
	var dataLen uint16
	if err := binary.Read(buf, binary.BigEndian, &dataLen); err != nil {
		return nil, err
	}

	if dataLen == 0 || int(dataLen) > maxRouterInfoDataLen || int(dataLen) > buf.Len() {
		return nil, fmt.Errorf("RouterInfo data length exceeds available data")
	}

	riData := make([]byte, dataLen)
	if _, err := io.ReadFull(buf, riData); err != nil {
		return nil, fmt.Errorf("RouterInfo data truncated: %w", err)
	}

	// Parse the RouterInfo fields from riData
	ri, err := parseRouterInfoData(riData)
	if err != nil {
		return nil, err
	}

	// Read signature
	var sigLen uint16
	if err := binary.Read(buf, binary.BigEndian, &sigLen); err != nil {
		return nil, err
	}

	if sigLen > 0 {
		if int(sigLen) > maxRouterSignature || int(sigLen) > buf.Len() {
			return nil, fmt.Errorf("RouterInfo signature length invalid")
		}
		ri.Signature = make([]byte, sigLen)
		if _, err := io.ReadFull(buf, ri.Signature); err != nil {
			return nil, fmt.Errorf("RouterInfo signature truncated: %w", err)
		}
	}

	return ri, nil
}

// parseRouterInfoData parses the core RouterInfo data (matching RouterInfo.Serialize format)
func parseRouterInfoData(data []byte) (*RouterInfo, error) {
	if len(data) < 96 { // 32 + 32 + 32 minimum
		return nil, fmt.Errorf("RouterInfo data too short")
	}

	ri := &RouterInfo{
		Capabilities: make(map[string]bool),
	}

	buf := bytes.NewReader(data)

	// Read router hash
	if _, err := io.ReadFull(buf, ri.RouterHash[:]); err != nil {
		return nil, err
	}

	// Read signing public key (32 bytes for Ed25519)
	sigKey := make([]byte, 32)
	if _, err := io.ReadFull(buf, sigKey); err != nil {
		return nil, err
	}
	ri.SigningPublicKey = sigKey

	// Read encryption key
	if _, err := io.ReadFull(buf, ri.EncryptionKey[:]); err != nil {
		return nil, err
	}

	// Read number of addresses
	var numAddrs uint16
	if err := binary.Read(buf, binary.BigEndian, &numAddrs); err != nil {
		return nil, err
	}
	if numAddrs > maxRouterAddrs {
		return nil, fmt.Errorf("RouterInfo has too many addresses: %d", numAddrs)
	}

	ri.Addresses = make([]RouterAddress, numAddrs)
	for i := 0; i < int(numAddrs); i++ {
		var hostLen uint16
		if err := binary.Read(buf, binary.BigEndian, &hostLen); err != nil {
			return nil, err
		}
		if hostLen == 0 || hostLen > maxRouterHostLen || int(hostLen) > buf.Len() {
			return nil, fmt.Errorf("RouterInfo host length invalid")
		}

		hostBytes := make([]byte, hostLen)
		if _, err := io.ReadFull(buf, hostBytes); err != nil {
			return nil, fmt.Errorf("RouterInfo host truncated: %w", err)
		}

		var port uint16
		if err := binary.Read(buf, binary.BigEndian, &port); err != nil {
			return nil, err
		}

		ri.Addresses[i] = RouterAddress{
			Host: string(hostBytes),
			Port: int(port),
		}
	}

	// Read timestamp
	var timestamp int64
	if err := binary.Read(buf, binary.BigEndian, &timestamp); err != nil {
		return nil, err
	}
	ri.Timestamp = time.Unix(timestamp, 0)

	// Read capabilities
	var numCaps uint16
	if err := binary.Read(buf, binary.BigEndian, &numCaps); err != nil {
		return nil, err
	}
	if numCaps > maxRouterCaps {
		return nil, fmt.Errorf("RouterInfo has too many capabilities: %d", numCaps)
	}

	for i := 0; i < int(numCaps); i++ {
		var capLen uint16
		if err := binary.Read(buf, binary.BigEndian, &capLen); err != nil {
			return nil, err
		}
		if capLen == 0 || capLen > maxRouterCapLen || int(capLen) > buf.Len() {
			return nil, fmt.Errorf("RouterInfo capability length invalid")
		}

		capBytes := make([]byte, capLen)
		if _, err := io.ReadFull(buf, capBytes); err != nil {
			return nil, fmt.Errorf("RouterInfo capability truncated: %w", err)
		}

		var enabled byte
		if err := binary.Read(buf, binary.BigEndian, &enabled); err != nil {
			return nil, err
		}

		ri.Capabilities[string(capBytes)] = enabled == 1
	}

	return ri, nil
}

// SerializeRouterInfoBatch serializes multiple RouterInfos for peer exchange.
// Format: [count:2] { [len:2][serialized_routerinfo]... }
func SerializeRouterInfoBatch(infos []*RouterInfo) []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.BigEndian, uint16(len(infos)))
	for _, ri := range infos {
		data := SerializeRouterInfo(ri)
		binary.Write(buf, binary.BigEndian, uint16(len(data)))
		buf.Write(data)
	}
	return buf.Bytes()
}

// DeserializeRouterInfoBatch parses multiple RouterInfos from peer exchange bytes.
func DeserializeRouterInfoBatch(data []byte) ([]*RouterInfo, error) {
	if len(data) < 2 {
		return nil, fmt.Errorf("batch data too short")
	}
	buf := bytes.NewReader(data)
	var count uint16
	binary.Read(buf, binary.BigEndian, &count)

	if count > maxRouterInfoBatch {
		count = maxRouterInfoBatch // safety cap
	}

	result := make([]*RouterInfo, 0, count)
	for i := 0; i < int(count); i++ {
		var riLen uint16
		if err := binary.Read(buf, binary.BigEndian, &riLen); err != nil {
			break
		}
		if riLen == 0 || int(riLen) > maxRouterInfoDataLen || int(riLen) > buf.Len() {
			return result, fmt.Errorf("RouterInfo batch entry length invalid")
		}
		riData := make([]byte, riLen)
		if _, err := io.ReadFull(buf, riData); err != nil {
			break
		}
		ri, err := DeserializeRouterInfo(riData)
		if err != nil {
			continue // skip bad entries
		}
		if ri.Verify() && !ri.IsExpired() {
			result = append(result, ri)
		}
	}
	return result, nil
}

// GetFloodfills returns all floodfill RouterInfos
func (s *Store) GetFloodfills() []*RouterInfo {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]*RouterInfo, 0)
	for _, ri := range s.routers {
		if ri.IsFloodfill() && !ri.IsExpired() {
			result = append(result, ri)
		}
	}

	return result
}
