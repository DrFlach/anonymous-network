package transport

import (
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"time"

	"network/pkg/router"
	"network/pkg/transport/ntcp2"
	"network/pkg/util"
)

// ─── Relay Circuit Protocol ──────────────────────────────────────────────────
//
// When two clients A and B are both behind NAT, they cannot connect directly.
// A "bridge" node (VPS) with a public IP relays data between them:
//
//   A ←─encrypted─→ VPS ←─encrypted─→ B
//
// The relay is at the transport level — the VPS forwards opaque encrypted
// frames without being able to read the content (each A↔VPS and B↔VPS link
// has its own NTCP2 encryption session).
//
// Protocol flow:
//   1. A sends MsgTypeRelayCircuitOpen { destHash } to VPS
//   2. VPS checks if B is directly connected
//   3. If yes: VPS sends MsgTypeRelayCircuitReady to both A and B
//   4. A sends MsgTypeRelayCircuitData { destHash + payload } to VPS
//   5. VPS forwards payload to B as MsgTypeRelayCircuitData { srcHash + payload }
//
// Additionally, the VPS can initiate hole-punch coordination:
//   1. VPS sends MsgTypeRelayIntro to both A and B with each other's external IP:port
//   2. Both A and B simultaneously attempt TCP connect to each other's external IP
//   3. If simultaneous open succeeds, they have a direct connection and drop the relay

// RelayCircuit represents a relay circuit between two peers through this node.
type RelayCircuit struct {
	PeerA     [32]byte  // router hash of peer A
	PeerB     [32]byte  // router hash of peer B
	CreatedAt time.Time
	LastUsed  time.Time
	BytesAtoB uint64
	BytesBtoA uint64
}

// RelayManager handles relay circuits and hole-punch coordination.
type RelayManager struct {
	mu       sync.RWMutex
	circuits map[[32]byte]map[[32]byte]*RelayCircuit // [peerA][peerB] → circuit
	logger   *util.Logger

	// Pending relay requests: destHash → list of source hashes waiting
	pendingMu sync.Mutex
	pending   map[[32]byte][][32]byte

	// Hole-punch state: tracks peers we've tried to hole-punch with
	holePunchMu    sync.Mutex
	holePunchTried map[string]time.Time // "hashA:hashB" → last attempt time
}

// NewRelayManager creates a new relay manager.
func NewRelayManager() *RelayManager {
	return &RelayManager{
		circuits:       make(map[[32]byte]map[[32]byte]*RelayCircuit),
		pending:        make(map[[32]byte][][32]byte),
		holePunchTried: make(map[string]time.Time),
		logger:         util.GetLogger(),
	}
}

// AddCircuit registers a relay circuit between two peers.
func (rm *RelayManager) AddCircuit(peerA, peerB [32]byte) {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	circuit := &RelayCircuit{
		PeerA:     peerA,
		PeerB:     peerB,
		CreatedAt: time.Now(),
		LastUsed:  time.Now(),
	}

	// Store in both directions for quick lookup
	if _, ok := rm.circuits[peerA]; !ok {
		rm.circuits[peerA] = make(map[[32]byte]*RelayCircuit)
	}
	rm.circuits[peerA][peerB] = circuit

	if _, ok := rm.circuits[peerB]; !ok {
		rm.circuits[peerB] = make(map[[32]byte]*RelayCircuit)
	}
	rm.circuits[peerB][peerA] = circuit
}

// GetCircuit checks if a relay circuit exists from src to dest.
func (rm *RelayManager) GetCircuit(src, dest [32]byte) *RelayCircuit {
	rm.mu.RLock()
	defer rm.mu.RUnlock()

	if dests, ok := rm.circuits[src]; ok {
		return dests[dest]
	}
	return nil
}

// RemoveCircuit removes a relay circuit.
func (rm *RelayManager) RemoveCircuit(peerA, peerB [32]byte) {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	if dests, ok := rm.circuits[peerA]; ok {
		delete(dests, peerB)
		if len(dests) == 0 {
			delete(rm.circuits, peerA)
		}
	}
	if dests, ok := rm.circuits[peerB]; ok {
		delete(dests, peerA)
		if len(dests) == 0 {
			delete(rm.circuits, peerB)
		}
	}
}

// RemoveAllForPeer removes all circuits involving a peer (on disconnect).
func (rm *RelayManager) RemoveAllForPeer(peerHash [32]byte) {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	if dests, ok := rm.circuits[peerHash]; ok {
		for dest := range dests {
			if otherDests, ok2 := rm.circuits[dest]; ok2 {
				delete(otherDests, peerHash)
				if len(otherDests) == 0 {
					delete(rm.circuits, dest)
				}
			}
		}
		delete(rm.circuits, peerHash)
	}
}

// CircuitCount returns the total number of active relay circuits.
func (rm *RelayManager) CircuitCount() int {
	rm.mu.RLock()
	defer rm.mu.RUnlock()

	count := 0
	seen := make(map[[64]byte]bool)
	for a, dests := range rm.circuits {
		for b := range dests {
			var key [64]byte
			if string(a[:]) < string(b[:]) {
				copy(key[:32], a[:])
				copy(key[32:], b[:])
			} else {
				copy(key[:32], b[:])
				copy(key[32:], a[:])
			}
			if !seen[key] {
				seen[key] = true
				count++
			}
		}
	}
	return count
}

// CleanupStale removes relay circuits not used in the last 10 minutes.
func (rm *RelayManager) CleanupStale() {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	cutoff := time.Now().Add(-10 * time.Minute)
	for a, dests := range rm.circuits {
		for b, circuit := range dests {
			if circuit.LastUsed.Before(cutoff) {
				delete(dests, b)
				// Also remove reverse
				if revDests, ok := rm.circuits[b]; ok {
					delete(revDests, a)
					if len(revDests) == 0 {
						delete(rm.circuits, b)
					}
				}
			}
		}
		if len(dests) == 0 {
			delete(rm.circuits, a)
		}
	}
}

// ─── Relay Circuit Wire Format ───────────────────────────────────────────────

// SerializeRelayCircuitOpen creates payload for MsgTypeRelayCircuitOpen.
// Format: destHash(32)
func SerializeRelayCircuitOpen(destHash [32]byte) []byte {
	return destHash[:]
}

// DeserializeRelayCircuitOpen parses a RelayCircuitOpen payload.
func DeserializeRelayCircuitOpen(data []byte) ([32]byte, error) {
	var hash [32]byte
	if len(data) < 32 {
		return hash, fmt.Errorf("relay circuit open: payload too short (%d)", len(data))
	}
	copy(hash[:], data[:32])
	return hash, nil
}

// SerializeRelayCircuitReady creates payload for MsgTypeRelayCircuitReady.
// Format: peerHash(32) + externalAddr (string)
func SerializeRelayCircuitReady(peerHash [32]byte, externalAddr string) []byte {
	addrBytes := []byte(externalAddr)
	buf := make([]byte, 32+2+len(addrBytes))
	copy(buf[:32], peerHash[:])
	binary.BigEndian.PutUint16(buf[32:34], uint16(len(addrBytes)))
	copy(buf[34:], addrBytes)
	return buf
}

// DeserializeRelayCircuitReady parses a RelayCircuitReady payload.
func DeserializeRelayCircuitReady(data []byte) (peerHash [32]byte, externalAddr string, err error) {
	if len(data) < 34 {
		return peerHash, "", fmt.Errorf("relay circuit ready: payload too short (%d)", len(data))
	}
	copy(peerHash[:], data[:32])
	addrLen := binary.BigEndian.Uint16(data[32:34])
	if len(data) < 34+int(addrLen) {
		return peerHash, "", fmt.Errorf("relay circuit ready: addr truncated")
	}
	externalAddr = string(data[34 : 34+addrLen])
	return peerHash, externalAddr, nil
}

// SerializeRelayCircuitData creates payload for MsgTypeRelayCircuitData.
// Format: peerHash(32) + innerData
func SerializeRelayCircuitData(peerHash [32]byte, innerData []byte) []byte {
	buf := make([]byte, 32+len(innerData))
	copy(buf[:32], peerHash[:])
	copy(buf[32:], innerData)
	return buf
}

// DeserializeRelayCircuitData parses a RelayCircuitData payload.
func DeserializeRelayCircuitData(data []byte) (peerHash [32]byte, innerData []byte, err error) {
	if len(data) < 33 {
		return peerHash, nil, fmt.Errorf("relay circuit data: payload too short (%d)", len(data))
	}
	copy(peerHash[:], data[:32])
	innerData = data[32:]
	return peerHash, innerData, nil
}

// ─── Hole-Punch Intro Wire Format ───────────────────────────────────────────

// SerializeRelayIntro creates payload for MsgTypeRelayIntro.
// Tells a peer: "try connecting to peerHash at externalAddr".
// Format: peerHash(32) + addrLen(2) + addr
func SerializeRelayIntro(peerHash [32]byte, externalAddr string) []byte {
	return SerializeRelayCircuitReady(peerHash, externalAddr) // same format
}

// DeserializeRelayIntro parses a RelayIntro payload.
func DeserializeRelayIntro(data []byte) (peerHash [32]byte, externalAddr string, err error) {
	return DeserializeRelayCircuitReady(data) // same format
}

// ─── Manager integration methods ─────────────────────────────────────────────

// HandleRelayCircuitOpen processes a request to open a relay circuit.
// Only bridge nodes should handle this.
func (m *Manager) HandleRelayCircuitOpen(from [32]byte, payload []byte) {
	destHash, err := DeserializeRelayCircuitOpen(payload)
	if err != nil {
		m.logger.Debug("RelayCircuitOpen: %v", err)
		return
	}

	// Check if we have a direct connection to the destination
	m.mu.RLock()
	destPeer, destExists := m.peers[destHash]
	srcPeer, srcExists := m.peers[from]
	m.mu.RUnlock()

	if !srcExists {
		m.logger.Debug("RelayCircuitOpen: source %x not connected", from[:8])
		return
	}

	if !destExists {
		m.logger.Debug("RelayCircuitOpen: destination %x not connected, cannot establish relay", destHash[:8])
		return
	}

	// Register the relay circuit
	m.relayMgr.AddCircuit(from, destHash)

	m.logger.Info("Relay circuit opened: %x ↔ %x", from[:8], destHash[:8])

	// Notify source peer that circuit is ready, include dest's external address
	srcExtAddr := srcPeer.Address
	destExtAddr := destPeer.Address

	readyForSrc := SerializeRelayCircuitReady(destHash, destExtAddr)
	readyMsg := router.NewMessage(router.MsgTypeRelayCircuitReady, readyForSrc)
	readyData, _ := readyMsg.Serialize()
	srcPeer.Conn.SendFrame(readyData)

	// Notify dest peer about the circuit + src's address for potential hole-punch
	readyForDest := SerializeRelayCircuitReady(from, srcExtAddr)
	readyMsg2 := router.NewMessage(router.MsgTypeRelayCircuitReady, readyForDest)
	readyData2, _ := readyMsg2.Serialize()
	destPeer.Conn.SendFrame(readyData2)

	// Initiate hole-punch coordination: tell both peers to try direct connect
	m.initiateHolePunch(from, destHash, srcExtAddr, destExtAddr)
}

// HandleRelayCircuitData processes relay circuit data forwarding.
// VPS receives data from peer A destined for peer B and forwards it.
func (m *Manager) HandleRelayCircuitData(from [32]byte, payload []byte) {
	destHash, innerData, err := DeserializeRelayCircuitData(payload)
	if err != nil {
		m.logger.Debug("RelayCircuitData: %v", err)
		return
	}

	// Verify circuit exists
	circuit := m.relayMgr.GetCircuit(from, destHash)
	if circuit == nil {
		m.logger.Debug("RelayCircuitData: no circuit from %x to %x", from[:8], destHash[:8])
		return
	}
	circuit.LastUsed = time.Now()

	// Check if we have the destination connected
	m.mu.RLock()
	destPeer, exists := m.peers[destHash]
	m.mu.RUnlock()

	if !exists {
		m.logger.Debug("RelayCircuitData: destination %x disconnected", destHash[:8])
		return
	}

	// Forward: wrap innerData with source hash so dest knows who it's from
	fwdPayload := SerializeRelayCircuitData(from, innerData)
	fwdMsg := router.NewMessage(router.MsgTypeRelayCircuitData, fwdPayload)
	fwdData, err := fwdMsg.Serialize()
	if err != nil {
		return
	}

	if err := destPeer.Conn.SendFrame(fwdData); err != nil {
		m.logger.Debug("RelayCircuitData: forward to %x failed: %v", destHash[:8], err)
	}
}

// HandleRelayCircuitReady processes the "circuit ready" notification from VPS.
// The client now knows it can send data through the relay to reach the peer.
func (m *Manager) HandleRelayCircuitReady(from [32]byte, payload []byte) {
	peerHash, extAddr, err := DeserializeRelayCircuitReady(payload)
	if err != nil {
		m.logger.Debug("RelayCircuitReady: %v", err)
		return
	}

	m.logger.Info("Relay circuit ready via %x to peer %x (ext: %s)", from[:8], peerHash[:8], extAddr)

	// Store the relay route: to reach peerHash, send through `from` (the VPS)
	m.relayRoutesMu.Lock()
	m.relayRoutes[peerHash] = from
	m.relayRoutesMu.Unlock()

	// Try hole-punch to the peer's external address
	if extAddr != "" {
		go m.attemptHolePunch(peerHash, extAddr)
	}
}

// HandleRelayIntro processes a hole-punch introduction from VPS.
// VPS tells us: "peer X is at address Y, try to connect directly."
func (m *Manager) HandleRelayIntro(from [32]byte, payload []byte) {
	peerHash, extAddr, err := DeserializeRelayIntro(payload)
	if err != nil {
		m.logger.Debug("RelayIntro: %v", err)
		return
	}

	m.logger.Info("Hole-punch intro from VPS: peer %x at %s", peerHash[:8], extAddr)

	// Attempt hole-punch: try connecting directly to their external address
	go m.attemptHolePunch(peerHash, extAddr)
}

// initiateHolePunch sends hole-punch intro messages to both peers.
// Only called on bridge/VPS nodes.
func (m *Manager) initiateHolePunch(hashA, hashB [32]byte, addrA, addrB string) {
	// Only attempt if we haven't recently tried this pair
	m.relayMgr.holePunchMu.Lock()
	pairKey := fmt.Sprintf("%x:%x", hashA[:8], hashB[:8])
	reversePairKey := fmt.Sprintf("%x:%x", hashB[:8], hashA[:8])
	now := time.Now()
	if last, ok := m.relayMgr.holePunchTried[pairKey]; ok && now.Sub(last) < 5*time.Minute {
		m.relayMgr.holePunchMu.Unlock()
		return
	}
	m.relayMgr.holePunchTried[pairKey] = now
	m.relayMgr.holePunchTried[reversePairKey] = now
	m.relayMgr.holePunchMu.Unlock()

	m.logger.Info("Initiating hole-punch coordination: %x (%s) ↔ %x (%s)", hashA[:8], addrA, hashB[:8], addrB)

	// Send intro to peer A: "try connecting to B at addrB"
	introA := SerializeRelayIntro(hashB, addrB)
	msgA := router.NewMessage(router.MsgTypeRelayIntro, introA)
	dataA, _ := msgA.Serialize()

	// Send intro to peer B: "try connecting to A at addrA"
	introB := SerializeRelayIntro(hashA, addrA)
	msgB := router.NewMessage(router.MsgTypeRelayIntro, introB)
	dataB, _ := msgB.Serialize()

	m.mu.RLock()
	peerA, aOk := m.peers[hashA]
	peerB, bOk := m.peers[hashB]
	m.mu.RUnlock()

	if aOk {
		peerA.Conn.SendFrame(dataA)
	}
	if bOk {
		peerB.Conn.SendFrame(dataB)
	}
}

// attemptHolePunch tries to establish a direct connection to a peer's external address.
// This is called after receiving a RelayIntro or RelayCircuitReady.
// TCP simultaneous open: both sides try to connect at roughly the same time.
func (m *Manager) attemptHolePunch(peerHash [32]byte, extAddr string) {
	// Validate the address
	host, _, err := net.SplitHostPort(extAddr)
	if err != nil {
		return
	}
	ip := net.ParseIP(host)
	if ip == nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return
	}

	// Check if already connected to this peer
	m.mu.RLock()
	if _, exists := m.peers[peerHash]; exists {
		m.mu.RUnlock()
		return
	}
	m.mu.RUnlock()

	// Check backoff
	if m.backoff != nil && !m.backoff.ShouldConnect(host) {
		return
	}

	m.logger.Info("Hole-punch: attempting direct connect to %x at %s", peerHash[:8], extAddr)

	// Attempt TCP connection with short timeout
	// For TCP simultaneous open, we use SO_REUSEADDR and our listen port as source
	dialer := &net.Dialer{
		Timeout:   5 * time.Second,
		LocalAddr: &net.TCPAddr{Port: m.listenPort}, // use our listen port for NAT mapping
	}

	conn, err := dialer.Dial("tcp", extAddr)
	if err != nil {
		m.logger.Debug("Hole-punch to %x at %s failed: %v", peerHash[:8], extAddr, err)
		if m.backoff != nil {
			m.backoff.RecordFailure(host)
		}
		return
	}

	m.logger.Info("Hole-punch SUCCESS: direct connection to %x at %s!", peerHash[:8], extAddr)

	// Perform NTCP2 handshake on the new direct connection
	go func() {
		if err := m.finishDirectConnection(conn, extAddr); err != nil {
			m.logger.Debug("Hole-punch handshake with %s failed: %v", extAddr, err)
			conn.Close()
		} else {
			// Direct connection established — remove relay route
			m.relayRoutesMu.Lock()
			delete(m.relayRoutes, peerHash)
			m.relayRoutesMu.Unlock()
			if m.backoff != nil {
				m.backoff.RecordSuccess(host)
			}
		}
	}()
}

// finishDirectConnection performs NTCP2 handshake and registers the peer.
// Used after hole-punch succeeds.
func (m *Manager) finishDirectConnection(conn net.Conn, address string) error {
	ntcpConn := ntcp2.NewConnection(conn)
	if err := ntcpConn.Handshake(m.identity, true); err != nil {
		return fmt.Errorf("handshake failed: %w", err)
	}

	routerHash := ntcpConn.RemoteRouterHash()

	peer := &PeerConnection{
		Conn:         ntcpConn,
		RouterHash:   routerHash,
		Address:      address,
		ListenAddrs:  []string{address},
		Connected:    time.Now(),
		LastActivity: time.Now(),
	}

	m.mu.Lock()
	if _, exists := m.peers[routerHash]; exists {
		m.mu.Unlock()
		conn.Close()
		return nil // already connected
	}
	m.peers[routerHash] = peer
	m.peersByAddr[address] = peer
	m.mu.Unlock()

	hashStr := fmt.Sprintf("%x", routerHash[:8])
	m.logger.Info("Direct connection via hole-punch: %s [%s] (total: %d)", address, hashStr, m.GetPeerCount())

	m.sendYourIP(peer)
	m.announceSelf(peer)
	m.sendPeerList(peer)
	m.SendInitialPeerExchange(peer)

	// Start receive loop in background
	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		m.receiveLoop(peer)
		m.mu.Lock()
		if existing, ok := m.peers[routerHash]; ok && existing == peer {
			delete(m.peers, routerHash)
		}
		delete(m.peersByAddr, address)
		m.mu.Unlock()
		m.logger.Info("Peer disconnected: %s [%s] (total: %d)", address, hashStr, m.GetPeerCount())
	}()

	return nil
}

// SendViaRelay sends data to a peer through a relay circuit.
// Used when no direct connection exists but a relay route is known.
func (m *Manager) SendViaRelay(destHash [32]byte, data []byte) error {
	m.relayRoutesMu.RLock()
	relayPeer, hasRoute := m.relayRoutes[destHash]
	m.relayRoutesMu.RUnlock()

	if !hasRoute {
		return fmt.Errorf("no relay route to %x", destHash[:8])
	}

	// Check if the relay peer is still connected
	m.mu.RLock()
	peer, exists := m.peers[relayPeer]
	m.mu.RUnlock()
	if !exists {
		return fmt.Errorf("relay peer %x disconnected", relayPeer[:8])
	}

	// Wrap in RelayCircuitData
	payload := SerializeRelayCircuitData(destHash, data)
	msg := router.NewMessage(router.MsgTypeRelayCircuitData, payload)
	msgData, err := msg.Serialize()
	if err != nil {
		return err
	}

	return peer.Conn.SendFrame(msgData)
}

// RequestRelayCircuit asks a bridge peer to set up a relay circuit to destHash.
func (m *Manager) RequestRelayCircuit(bridgeHash, destHash [32]byte) error {
	m.mu.RLock()
	bridge, exists := m.peers[bridgeHash]
	m.mu.RUnlock()

	if !exists {
		return fmt.Errorf("bridge peer %x not connected", bridgeHash[:8])
	}

	payload := SerializeRelayCircuitOpen(destHash)
	msg := router.NewMessage(router.MsgTypeRelayCircuitOpen, payload)
	data, err := msg.Serialize()
	if err != nil {
		return err
	}

	m.logger.Info("Requesting relay circuit to %x through bridge %x", destHash[:8], bridgeHash[:8])
	return bridge.Conn.SendFrame(data)
}
