package transport

import (
    "context"
    "encoding/base64"
    "fmt"
    "net"
    "strings"
    "sync"
    "syscall"
    "time"

    "network/pkg/crypto"
    "network/pkg/router"
    "network/pkg/transport/ntcp2"
    "network/pkg/util"
)

// PeerConnection represents a connection to a peer
type PeerConnection struct {
    Conn         *ntcp2.Connection
    RouterHash   [32]byte
    Address      string
    ListenAddrs  []string // announced reachable listen addresses
    Connected    time.Time
    LastActivity time.Time
}

// Manager manages all transport connections
type Manager struct {
    identity    *crypto.RouterIdentity
    listener    net.Listener
    peers       map[[32]byte]*PeerConnection
    peersByAddr map[string]*PeerConnection
    mu          sync.RWMutex
    maxPeers    int
    logger      *util.Logger
    incomingMsg chan *IncomingMessage
    stopChan    chan struct{}
    wg          sync.WaitGroup

    // Our listen port for self-announcement
    listenPort int

    // Detected external (public) IP from VPS (STUN-like)
    externalIP   string
    externalIPMu sync.RWMutex

    // Known nodes: all addresses ever learned (including unreachable)
    // This tracks the full network size, not just direct connections
    knownNodes   map[string]time.Time
    knownNodesMu sync.RWMutex

    // Auto-reconnect to seeds
    seedAddrs []string
    seedMu    sync.Mutex
}

// IncomingMessage represents a message received from a peer
type IncomingMessage struct {
    From       [32]byte
    Data       []byte
    ReceivedAt time.Time
}

// NewManager creates a new transport manager
func NewManager(identity *crypto.RouterIdentity, maxPeers int) *Manager {
    return &Manager{
        identity:    identity,
        peers:       make(map[[32]byte]*PeerConnection),
        peersByAddr: make(map[string]*PeerConnection),
        knownNodes:  make(map[string]time.Time),
        maxPeers:    maxPeers,
        logger:      util.GetLogger(),
        incomingMsg: make(chan *IncomingMessage, 1000),
        stopChan:    make(chan struct{}),
    }
}

// SetSeeds sets the seed addresses for auto-reconnection
func (m *Manager) SetSeeds(seeds []string) {
    m.seedMu.Lock()
    defer m.seedMu.Unlock()
    m.seedAddrs = seeds
}

// Start starts the transport manager and listens for connections
func (m *Manager) Start(listenAddr string) error {
    // Extract listen port for self-announcement
    if _, portStr, err := net.SplitHostPort(listenAddr); err == nil {
        fmt.Sscanf(portStr, "%d", &m.listenPort)
    }

    lc := net.ListenConfig{
        Control: func(network, address string, c syscall.RawConn) error {
            return c.Control(func(fd uintptr) {
                syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
            })
        },
    }
    listener, err := lc.Listen(context.Background(), "tcp", listenAddr)
    if err != nil {
        return fmt.Errorf("failed to start listener: %w", err)
    }
    
    m.listener = listener
    m.logger.Info("Transport manager listening on %s", listenAddr)
    
    // Start accepting connections
    m.wg.Add(1)
    go m.acceptLoop()
    
    // Start connection monitor
    m.wg.Add(1)
    go m.monitorConnections()

    // Start seed reconnection loop
    m.wg.Add(1)
    go m.seedReconnectLoop()

    // Start periodic peer exchange
    m.wg.Add(1)
    go m.peerExchangeLoop()
    
    return nil
}

// acceptLoop accepts incoming connections
func (m *Manager) acceptLoop() {
    defer m.wg.Done()
    
    for {
        select {
        case <-m.stopChan:
            return
        default:
        }
        
        // Set accept timeout to allow checking stopChan
        m.listener.(*net.TCPListener).SetDeadline(time.Now().Add(1 * time.Second))
        
        conn, err := m.listener.Accept()
        if err != nil {
            if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
                continue
            }
            select {
            case <-m.stopChan:
                return
            default:
                m.logger.Error("Accept error: %v", err)
                continue
            }
        }
        
        m.logger.Debug("Accepted connection from %s", conn.RemoteAddr())
        
        // Handle connection in goroutine
        m.wg.Add(1)
        go m.handleIncoming(conn)
    }
}

// handleIncoming handles an incoming connection
func (m *Manager) handleIncoming(conn net.Conn) {
    defer m.wg.Done()
    defer conn.Close()
    
    // Check if we have capacity
    m.mu.RLock()
    peerCount := len(m.peers)
    m.mu.RUnlock()
    
    if peerCount >= m.maxPeers {
        m.logger.Warn("Rejecting connection from %s: max peers reached", conn.RemoteAddr())
        return
    }
    
    // Create NTCP2 connection and perform handshake (includes identity exchange)
    ntcpConn := ntcp2.NewConnection(conn)
    if err := ntcpConn.Handshake(m.identity, false); err != nil {
        m.logger.Error("Handshake failed with %s: %v", conn.RemoteAddr(), err)
        return
    }

    // Get the real router hash from the handshake identity exchange
    routerHash := ntcpConn.RemoteRouterHash()
    hashStr := base64.RawStdEncoding.EncodeToString(routerHash[:8])

    // Check if already connected (by router hash)
    m.mu.RLock()
    _, exists := m.peers[routerHash]
    m.mu.RUnlock()
    if exists {
        m.logger.Debug("Already connected to peer %s, dropping duplicate", hashStr)
        return
    }

    m.logger.Info("Handshake OK with %s (hash: %s)", conn.RemoteAddr(), hashStr)

    peer := &PeerConnection{
        Conn:         ntcpConn,
        RouterHash:   routerHash,
        Address:      conn.RemoteAddr().String(),
        Connected:    time.Now(),
        LastActivity: time.Now(),
    }

    m.mu.Lock()
    m.peers[routerHash] = peer
    m.peersByAddr[peer.Address] = peer
    m.mu.Unlock()

    m.logger.Info("Peer connected: %s [%s] (total: %d)", peer.Address, hashStr, m.GetPeerCount())

    // Tell the remote peer what their external IP looks like to us (STUN-like)
    m.sendYourIP(peer)

    // Announce our listen addresses and share known peers
    m.announceSelf(peer)
    m.sendPeerList(peer)

    // Receive messages until disconnect
    m.receiveLoop(peer)

    // Cleanup
    m.mu.Lock()
    delete(m.peers, routerHash)
    delete(m.peersByAddr, peer.Address)
    m.mu.Unlock()

    m.logger.Info("Peer disconnected: %s [%s] (total: %d)", peer.Address, hashStr, m.GetPeerCount())
}

// ConnectTo connects to a remote peer
func (m *Manager) ConnectTo(address string) error {
    m.mu.RLock()
    _, exists := m.peersByAddr[address]
    peerCount := len(m.peers)
    m.mu.RUnlock()

    if exists {
        return nil // already connected, not an error
    }

    if peerCount >= m.maxPeers {
        return fmt.Errorf("max peers reached")
    }

    m.logger.Info("Connecting to %s...", address)

    conn, err := net.DialTimeout("tcp", address, 10*time.Second)
    if err != nil {
        return fmt.Errorf("failed to connect to %s: %w", address, err)
    }

    // Create NTCP2 connection and perform handshake (includes identity exchange)
    ntcpConn := ntcp2.NewConnection(conn)
    if err := ntcpConn.Handshake(m.identity, true); err != nil {
        conn.Close()
        return fmt.Errorf("handshake failed with %s: %w", address, err)
    }

    // Get the real router hash from the handshake
    routerHash := ntcpConn.RemoteRouterHash()
    hashStr := base64.RawStdEncoding.EncodeToString(routerHash[:8])

    // Check for duplicate by hash
    m.mu.RLock()
    _, hashExists := m.peers[routerHash]
    m.mu.RUnlock()
    if hashExists {
        conn.Close()
        return nil // already connected via different address
    }

    m.logger.Info("Handshake OK with %s (hash: %s)", address, hashStr)

    peer := &PeerConnection{
        Conn:         ntcpConn,
        RouterHash:   routerHash,
        Address:      address,
        ListenAddrs:  []string{address}, // outbound: we know the real listen address
        Connected:    time.Now(),
        LastActivity: time.Now(),
    }

    m.mu.Lock()
    m.peers[routerHash] = peer
    m.peersByAddr[address] = peer
    m.mu.Unlock()

    m.logger.Info("Peer connected: %s [%s] (total: %d)", address, hashStr, m.GetPeerCount())

    // Tell the remote peer what their external IP looks like to us (STUN-like)
    m.sendYourIP(peer)

    // Announce our listen addresses and share known peers
    m.announceSelf(peer)
    m.sendPeerList(peer)

    // Start receiving messages
    m.wg.Add(1)
    go func() {
        defer m.wg.Done()
        m.receiveLoop(peer)

        m.mu.Lock()
        delete(m.peers, routerHash)
        delete(m.peersByAddr, address)
        m.mu.Unlock()

        m.logger.Info("Peer disconnected: %s [%s] (total: %d)", address, hashStr, m.GetPeerCount())
    }()

    return nil
}

// seedReconnectLoop periodically tries to reconnect to seed nodes
func (m *Manager) seedReconnectLoop() {
    defer m.wg.Done()

    // Initial delay to let startup finish
    select {
    case <-time.After(5 * time.Second):
    case <-m.stopChan:
        return
    }

    ticker := time.NewTicker(15 * time.Second)
    defer ticker.Stop()

    for {
        select {
        case <-m.stopChan:
            return
        case <-ticker.C:
            m.reconnectSeeds()
        }
    }
}

// reconnectSeeds tries to connect to any seeds we're not yet connected to
func (m *Manager) reconnectSeeds() {
    m.seedMu.Lock()
    seeds := make([]string, len(m.seedAddrs))
    copy(seeds, m.seedAddrs)
    m.seedMu.Unlock()

    for _, seed := range seeds {
        if seed == "" {
            continue
        }

        // Extract the host part from the seed address (ip:port -> ip)
        seedHost := seed
        if h, _, err := net.SplitHostPort(seed); err == nil {
            seedHost = h
        }

        // Check if already connected to this seed (exact match or same host)
        m.mu.RLock()
        alreadyConnected := false
        if _, ok := m.peersByAddr[seed]; ok {
            alreadyConnected = true
        } else {
            // Check if any connected peer has the same host IP
            for _, peer := range m.peersByAddr {
                peerHost := peer.Address
                if h, _, err := net.SplitHostPort(peer.Address); err == nil {
                    peerHost = h
                }
                if peerHost == seedHost {
                    alreadyConnected = true
                    break
                }
            }
        }
        m.mu.RUnlock()

        if alreadyConnected {
            continue
        }
        if err := m.ConnectTo(seed); err != nil {
            m.logger.Debug("Seed reconnect to %s: %v", seed, err)
        }
    }
}

// IsConnectedTo checks if already connected to an address
func (m *Manager) IsConnectedTo(address string) bool {
    m.mu.RLock()
    defer m.mu.RUnlock()
    _, exists := m.peersByAddr[address]
    return exists
}

// receiveLoop receives messages from a peer
func (m *Manager) receiveLoop(peer *PeerConnection) {
    for {
        select {
        case <-m.stopChan:
            return
        default:
        }
        
        // Set read deadline
        peer.Conn.SetDeadline(time.Now().Add(65 * time.Second))
        
        data, err := peer.Conn.ReceiveFrame()
        if err != nil {
            select {
            case <-m.stopChan:
                return
            default:
                m.logger.Debug("Receive error from %s: %v", peer.Address, err)
                return
            }
        }
        
        peer.LastActivity = time.Now()
        
        // Send to incoming message channel
        msg := &IncomingMessage{
            From:       peer.RouterHash,
            Data:       data,
            ReceivedAt: time.Now(),
        }
        
        select {
        case m.incomingMsg <- msg:
        case <-m.stopChan:
            return
        default:
            m.logger.Warn("Incoming message queue full, dropping message from %s", peer.Address)
        }
    }
}

// SendTo sends data to a specific peer
func (m *Manager) SendTo(routerHash [32]byte, data []byte) error {
    m.mu.RLock()
    peer, exists := m.peers[routerHash]
    m.mu.RUnlock()
    
    if exists {
        if err := peer.Conn.SendFrame(data); err != nil {
            return fmt.Errorf("failed to send to peer: %w", err)
        }
        peer.LastActivity = time.Now()
        return nil
    }
    
    // No direct connection — try relay through any connected peer
    return m.relaySend(routerHash, data)
}

// SendToAddress sends data to a peer by address
func (m *Manager) SendToAddress(address string, data []byte) error {
    m.mu.RLock()
    peer, exists := m.peersByAddr[address]
    m.mu.RUnlock()
    
    if !exists {
        return fmt.Errorf("peer not connected")
    }
    
    if err := peer.Conn.SendFrame(data); err != nil {
        return fmt.Errorf("failed to send to peer: %w", err)
    }
    
    peer.LastActivity = time.Now()
    return nil
}

// Broadcast sends data to all connected peers
func (m *Manager) Broadcast(data []byte) {
    m.mu.RLock()
    peers := make([]*PeerConnection, 0, len(m.peers))
    for _, peer := range m.peers {
        peers = append(peers, peer)
    }
    m.mu.RUnlock()
    
    for _, peer := range peers {
        if err := peer.Conn.SendFrame(data); err != nil {
            m.logger.Error("Failed to broadcast to %s: %v", peer.Address, err)
        }
    }
}

// GetIncomingMessages returns the channel for incoming messages
func (m *Manager) GetIncomingMessages() <-chan *IncomingMessage {
    return m.incomingMsg
}

// GetPeerCount returns the number of connected peers
func (m *Manager) GetPeerCount() int {
    m.mu.RLock()
    defer m.mu.RUnlock()
    return len(m.peers)
}

// GetPeers returns a list of connected peer addresses
func (m *Manager) GetPeers() []string {
    m.mu.RLock()
    defer m.mu.RUnlock()
    
    addresses := make([]string, 0, len(m.peers))
    for _, peer := range m.peers {
        addresses = append(addresses, peer.Address)
    }
    return addresses
}

// monitorConnections monitors connection health and sends heartbeats
func (m *Manager) monitorConnections() {
    defer m.wg.Done()
    
    ticker := time.NewTicker(20 * time.Second)
    defer ticker.Stop()
    
    for {
        select {
        case <-m.stopChan:
            return
        case <-ticker.C:
            m.checkConnections()
        }
    }
}

// checkConnections checks for dead connections and sends heartbeats
func (m *Manager) checkConnections() {
    m.mu.RLock()
    peers := make([]*PeerConnection, 0, len(m.peers))
    for _, peer := range m.peers {
        peers = append(peers, peer)
    }
    m.mu.RUnlock()
    
    now := time.Now()

    // Build a proper serialized ping message for heartbeats
    pingMsg := router.NewMessage(router.MsgTypePing, []byte("HEARTBEAT"))
    heartbeat, _ := pingMsg.Serialize()

    for _, peer := range peers {
        // Check if connection is alive
        if now.Sub(peer.LastActivity) > 60*time.Second {
            m.logger.Warn("Peer %s inactive for too long, closing", peer.Address)
            peer.Conn.Close()
            continue
        }
        
        // Send heartbeat if needed
        if now.Sub(peer.LastActivity) > 20*time.Second {
            if err := peer.Conn.SendFrame(heartbeat); err != nil {
                m.logger.Error("Failed to send heartbeat to %s: %v", peer.Address, err)
                peer.Conn.Close()
            }
        }
    }
}

// getLocalListenAddrs returns our own reachable listen addresses (all non-loopback IPs + listen port)
func (m *Manager) getLocalListenAddrs() []string {
    if m.listenPort == 0 {
        return nil
    }
    var addrs []string
    ifaces, err := net.Interfaces()
    if err != nil {
        return nil
    }
    for _, iface := range ifaces {
        if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
            continue
        }
        ifAddrs, err := iface.Addrs()
        if err != nil {
            continue
        }
        for _, a := range ifAddrs {
            if ipnet, ok := a.(*net.IPNet); ok {
                ip := ipnet.IP.To4()
                if ip != nil && !ip.IsLoopback() {
                    addrs = append(addrs, fmt.Sprintf("%s:%d", ip.String(), m.listenPort))
                }
            }
        }
    }
    return addrs
}

// announceSelf sends our own listen addresses to a peer (prefixed with @ to distinguish from peer sharing)
func (m *Manager) announceSelf(peer *PeerConnection) {
    ownAddrs := m.getLocalListenAddrs()

    // Also include our detected external IP if we have one
    m.externalIPMu.RLock()
    extIP := m.externalIP
    m.externalIPMu.RUnlock()
    if extIP != "" && m.listenPort > 0 {
        extAddr := fmt.Sprintf("%s:%d", extIP, m.listenPort)
        // Avoid duplicates
        found := false
        for _, a := range ownAddrs {
            if a == extAddr {
                found = true
                break
            }
        }
        if !found {
            ownAddrs = append(ownAddrs, extAddr)
        }
    }

    if len(ownAddrs) == 0 {
        return
    }
    var parts []string
    for _, a := range ownAddrs {
        parts = append(parts, "@"+a)
    }
    payload := []byte(strings.Join(parts, ","))
    msg := router.NewMessage(router.MsgTypePeerList, payload)
    data, err := msg.Serialize()
    if err != nil {
        return
    }
    if err := peer.Conn.SendFrame(data); err != nil {
        m.logger.Debug("Failed to announce self to %s: %v", peer.Address, err)
    }
}

// sendPeerList sends known peer listen addresses to a specific peer
func (m *Manager) sendPeerList(target *PeerConnection) {
    m.mu.RLock()
    var addrs []string
    for _, p := range m.peers {
        if p.RouterHash == target.RouterHash {
            continue
        }
        // Only share peers whose listen addresses we know
        for _, la := range p.ListenAddrs {
            addrs = append(addrs, la)
        }
    }
    m.mu.RUnlock()

    if len(addrs) == 0 {
        return
    }

    payload := []byte(strings.Join(addrs, ","))
    msg := router.NewMessage(router.MsgTypePeerList, payload)
    data, err := msg.Serialize()
    if err != nil {
        return
    }
    if err := target.Conn.SendFrame(data); err != nil {
        m.logger.Debug("Failed to send peer list to %s: %v", target.Address, err)
    } else {
        m.logger.Debug("Sent peer list (%d addrs) to %s", len(addrs), target.Address)
    }
}

// HandlePeerList processes a received peer list message.
// Entries prefixed with '@' are self-announcements (the sender's own listen addresses).
// Regular entries are addresses of other peers to connect to.
func (m *Manager) HandlePeerList(from [32]byte, payload []byte) {
    if len(payload) == 0 {
        return
    }
    parts := strings.Split(string(payload), ",")
    for _, part := range parts {
        part = strings.TrimSpace(part)
        if part == "" {
            continue
        }

        if strings.HasPrefix(part, "@") {
            // Self-announcement: store as the sender's listen address
            listenAddr := strings.TrimPrefix(part, "@")
            m.mu.Lock()
            if peer, ok := m.peers[from]; ok {
                found := false
                for _, la := range peer.ListenAddrs {
                    if la == listenAddr {
                        found = true
                        break
                    }
                }
                if !found {
                    peer.ListenAddrs = append(peer.ListenAddrs, listenAddr)
                    m.logger.Info("Peer %s announced listen addr: %s", peer.Address, listenAddr)
                }
            }
            m.mu.Unlock()
            // Track in known nodes
            m.trackKnownNode(listenAddr)
        } else {
            // Peer address to try connecting to — also track it
            m.trackKnownNode(part)
            m.tryConnectToPeer(part)
        }
    }
}

// tryConnectToPeer attempts to connect to a discovered peer address
func (m *Manager) tryConnectToPeer(addr string) {
    // Skip loopback
    if h, _, err := net.SplitHostPort(addr); err == nil {
        if h == "127.0.0.1" || h == "::1" {
            return
        }
    }

    // Check by IP host — skip if already connected to same host
    addrHost := addr
    if h, _, err := net.SplitHostPort(addr); err == nil {
        addrHost = h
    }

    // Also skip our own addresses
    for _, ownAddr := range m.getLocalListenAddrs() {
        if ownAddr == addr {
            return
        }
    }

    m.mu.RLock()
    alreadyConnected := false
    for _, peer := range m.peersByAddr {
        peerHost := peer.Address
        if h, _, err := net.SplitHostPort(peer.Address); err == nil {
            peerHost = h
        }
        if peerHost == addrHost {
            alreadyConnected = true
            break
        }
    }
    m.mu.RUnlock()

    if alreadyConnected {
        return
    }

    m.logger.Info("Peer exchange: discovered %s, connecting...", addr)
    go func(a string) {
        if err := m.ConnectTo(a); err != nil {
            m.logger.Debug("Peer exchange connect to %s failed: %v", a, err)
        }
    }(addr)
}

// peerExchangeLoop periodically re-broadcasts peer lists and self-announcements
func (m *Manager) peerExchangeLoop() {
    defer m.wg.Done()

    ticker := time.NewTicker(60 * time.Second)
    defer ticker.Stop()

    for {
        select {
        case <-m.stopChan:
            return
        case <-ticker.C:
            m.mu.RLock()
            peers := make([]*PeerConnection, 0, len(m.peers))
            for _, p := range m.peers {
                peers = append(peers, p)
            }
            m.mu.RUnlock()

            for _, p := range peers {
                m.announceSelf(p)
                m.sendPeerList(p)
            }
        }
    }
}

// ─── External IP discovery (STUN-like) ────────────────────────────────────────

// sendYourIP tells a connecting peer what their external IP address is.
// This acts like a simple STUN — the peer can then announce this public IP
// so that nodes from other networks can connect to it.
func (m *Manager) sendYourIP(peer *PeerConnection) {
    remoteAddr := peer.Conn.RemoteAddr()
    if remoteAddr == nil {
        return
    }
    host, _, err := net.SplitHostPort(remoteAddr.String())
    if err != nil {
        return
    }
    // Only send if it looks like a real external IP (not loopback or link-local)
    ip := net.ParseIP(host)
    if ip == nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
        return
    }
    msg := router.NewMessage(router.MsgTypeYourIP, []byte(host))
    data, err := msg.Serialize()
    if err != nil {
        return
    }
    if err := peer.Conn.SendFrame(data); err != nil {
        m.logger.Debug("Failed to send YourIP to %s: %v", peer.Address, err)
    } else {
        m.logger.Debug("Sent YourIP=%s to %s", host, peer.Address)
    }
}

// HandleYourIP processes an external IP notification from a peer (VPS tells us our public IP)
func (m *Manager) HandleYourIP(payload []byte) {
    if len(payload) == 0 {
        return
    }
    ipStr := strings.TrimSpace(string(payload))
    ip := net.ParseIP(ipStr)
    if ip == nil || ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() {
        return // only accept real public IPs
    }

    m.externalIPMu.Lock()
    old := m.externalIP
    m.externalIP = ipStr
    m.externalIPMu.Unlock()

    if old != ipStr {
        m.logger.Info("Discovered external IP: %s (reported by peer)", ipStr)
        // Re-announce to all peers with the new external IP
        m.mu.RLock()
        peers := make([]*PeerConnection, 0, len(m.peers))
        for _, p := range m.peers {
            peers = append(peers, p)
        }
        m.mu.RUnlock()
        for _, p := range peers {
            m.announceSelf(p)
        }
    }
}

// ─── Relay forwarding ─────────────────────────────────────────────────────────

// relaySend wraps a message in MsgTypeRelayRequest and sends through any connected peer.
// Format: destHash(32) + originalData
func (m *Manager) relaySend(destHash [32]byte, data []byte) error {
    relayPayload := make([]byte, 32+len(data))
    copy(relayPayload[:32], destHash[:])
    copy(relayPayload[32:], data)

    relayMsg := router.NewMessage(router.MsgTypeRelayRequest, relayPayload)
    relayData, err := relayMsg.Serialize()
    if err != nil {
        return fmt.Errorf("relay serialize: %w", err)
    }

    // Try to send through any connected peer (prefer seeds / floodfill)
    m.mu.RLock()
    var relayPeer *PeerConnection
    for _, p := range m.peers {
        relayPeer = p
        break // pick first available; TODO: prefer floodfill
    }
    m.mu.RUnlock()

    if relayPeer == nil {
        return fmt.Errorf("no peers available for relay")
    }

    m.logger.Debug("Relay send to %x via %s", destHash[:8], relayPeer.Address)
    return relayPeer.Conn.SendFrame(relayData)
}

// HandleRelayRequest processes an incoming relay request.
// A peer asks us to forward a message to destHash.
// Format: destHash(32) + innerData
func (m *Manager) HandleRelayRequest(from [32]byte, payload []byte) {
    if len(payload) < 33 { // at least 32-byte hash + 1 byte data
        return
    }

    var destHash [32]byte
    copy(destHash[:], payload[:32])
    innerData := payload[32:]

    // Check if we have a direct connection to the destination
    m.mu.RLock()
    destPeer, exists := m.peers[destHash]
    m.mu.RUnlock()

    if !exists {
        m.logger.Debug("Relay: destination %x not connected, dropping", destHash[:8])
        return
    }

    // Build MsgTypeRelayResponse for the destination: srcHash(32) + innerData
    responsePayload := make([]byte, 32+len(innerData))
    copy(responsePayload[:32], from[:])
    copy(responsePayload[32:], innerData)

    responseMsg := router.NewMessage(router.MsgTypeRelayResponse, responsePayload)
    responseData, err := responseMsg.Serialize()
    if err != nil {
        return
    }

    if err := destPeer.Conn.SendFrame(responseData); err != nil {
        m.logger.Debug("Relay forward to %x failed: %v", destHash[:8], err)
    } else {
        m.logger.Info("Relayed %d bytes: %x → %x", len(innerData), from[:8], destHash[:8])
    }
}

// HandleRelayResponse processes a relayed message that was forwarded to us.
// Format: srcHash(32) + innerData
// We re-inject the innerData as if it came from srcHash.
func (m *Manager) HandleRelayResponse(payload []byte) {
    if len(payload) < 33 {
        return
    }

    var srcHash [32]byte
    copy(srcHash[:], payload[:32])
    innerData := payload[32:]

    m.logger.Debug("Received relayed message from %x (%d bytes)", srcHash[:8], len(innerData))

    // Inject into incoming message queue as if from srcHash
    msg := &IncomingMessage{
        From:       srcHash,
        Data:       innerData,
        ReceivedAt: time.Now(),
    }

    select {
    case m.incomingMsg <- msg:
    default:
        m.logger.Warn("Incoming queue full, dropping relayed message from %x", srcHash[:8])
    }
}

// HasPeer checks if we have a direct connection to a router hash
func (m *Manager) HasPeer(routerHash [32]byte) bool {
    m.mu.RLock()
    defer m.mu.RUnlock()
    _, exists := m.peers[routerHash]
    return exists
}

// ─── Known nodes tracking ─────────────────────────────────────────────────────

// trackKnownNode adds an address to the known nodes map
func (m *Manager) trackKnownNode(addr string) {
    if addr == "" {
        return
    }
    // Skip loopback
    if h, _, err := net.SplitHostPort(addr); err == nil {
        if h == "127.0.0.1" || h == "::1" {
            return
        }
    }
    m.knownNodesMu.Lock()
    m.knownNodes[addr] = time.Now()
    m.knownNodesMu.Unlock()
}

// GetKnownNodeCount returns the number of unique known nodes in the network
func (m *Manager) GetKnownNodeCount() int {
    m.knownNodesMu.RLock()
    defer m.knownNodesMu.RUnlock()
    // Deduplicate by host IP (different ports on same host = same node)
    hosts := make(map[string]bool)
    for addr := range m.knownNodes {
        if h, _, err := net.SplitHostPort(addr); err == nil {
            hosts[h] = true
        } else {
            hosts[addr] = true
        }
    }
    return len(hosts)
}

// GetKnownNodes returns all known node addresses
func (m *Manager) GetKnownNodes() []string {
    m.knownNodesMu.RLock()
    defer m.knownNodesMu.RUnlock()
    addrs := make([]string, 0, len(m.knownNodes))
    for addr := range m.knownNodes {
        addrs = append(addrs, addr)
    }
    return addrs
}

// Stop stops the transport manager
func (m *Manager) Stop() {
    m.logger.Info("Stopping transport manager...")
    
    close(m.stopChan)
    
    if m.listener != nil {
        m.listener.Close()
    }
    
    // Close all peer connections
    m.mu.Lock()
    for _, peer := range m.peers {
        peer.Conn.Close()
    }
    m.mu.Unlock()
    
    // Close incoming message channel so consumers unblock
    close(m.incomingMsg)
    
    m.logger.Info("Transport manager stopped")
}