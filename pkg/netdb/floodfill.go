package netdb

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"sync"
	"time"

	"network/pkg/util"
)

// MaxFloodTTL is the maximum number of hops a flooded RouterInfo can travel.
// This prevents infinite propagation across large networks.
const MaxFloodTTL = 4

// FloodfillManager handles the distributed hash table (DHT) for RouterInfo propagation
type FloodfillManager struct {
	store         *Store
	isFloodfill   bool
	logger        *util.Logger
	mu            sync.RWMutex
	sendFunc      func(routerHash [32]byte, data []byte) error // Callback to send data to a peer
	knownHashes   map[[32]byte]time.Time                       // Track what we've seen to avoid loops
	hashMu        sync.RWMutex
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
	binary.Read(buf, binary.BigEndian, &dataLen)

	if int(dataLen) > buf.Len() {
		return nil, fmt.Errorf("RouterInfo data length exceeds available data")
	}

	riData := make([]byte, dataLen)
	buf.Read(riData)

	// Parse the RouterInfo fields from riData
	ri, err := parseRouterInfoData(riData)
	if err != nil {
		return nil, err
	}

	// Read signature
	var sigLen uint16
	binary.Read(buf, binary.BigEndian, &sigLen)

	if sigLen > 0 {
		ri.Signature = make([]byte, sigLen)
		buf.Read(ri.Signature)
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
	buf.Read(ri.RouterHash[:])

	// Read signing public key (32 bytes for Ed25519)
	sigKey := make([]byte, 32)
	buf.Read(sigKey)
	ri.SigningPublicKey = sigKey

	// Read encryption key
	buf.Read(ri.EncryptionKey[:])

	// Read number of addresses
	var numAddrs uint16
	binary.Read(buf, binary.BigEndian, &numAddrs)

	ri.Addresses = make([]RouterAddress, numAddrs)
	for i := 0; i < int(numAddrs); i++ {
		var hostLen uint16
		binary.Read(buf, binary.BigEndian, &hostLen)

		hostBytes := make([]byte, hostLen)
		buf.Read(hostBytes)

		var port uint16
		binary.Read(buf, binary.BigEndian, &port)

		ri.Addresses[i] = RouterAddress{
			Host: string(hostBytes),
			Port: int(port),
		}
	}

	// Read timestamp
	var timestamp int64
	binary.Read(buf, binary.BigEndian, &timestamp)
	ri.Timestamp = time.Unix(timestamp, 0)

	// Read capabilities
	var numCaps uint16
	binary.Read(buf, binary.BigEndian, &numCaps)

	for i := 0; i < int(numCaps); i++ {
		var capLen uint16
		binary.Read(buf, binary.BigEndian, &capLen)

		capBytes := make([]byte, capLen)
		buf.Read(capBytes)

		var enabled byte
		binary.Read(buf, binary.BigEndian, &enabled)

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

	if count > 500 {
		count = 500 // safety cap
	}

	result := make([]*RouterInfo, 0, count)
	for i := 0; i < int(count); i++ {
		var riLen uint16
		if err := binary.Read(buf, binary.BigEndian, &riLen); err != nil {
			break
		}
		riData := make([]byte, riLen)
		if _, err := buf.Read(riData); err != nil {
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
