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

    // Send our peer list to the new peer so they can discover others
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
        Connected:    time.Now(),
        LastActivity: time.Now(),
    }

    m.mu.Lock()
    m.peers[routerHash] = peer
    m.peersByAddr[address] = peer
    m.mu.Unlock()

    m.logger.Info("Peer connected: %s [%s] (total: %d)", address, hashStr, m.GetPeerCount())

    // Send our peer list to the new peer so they can discover others
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
    
    if !exists {
        return fmt.Errorf("peer not connected")
    }
    
    if err := peer.Conn.SendFrame(data); err != nil {
        return fmt.Errorf("failed to send to peer: %w", err)
    }
    
    peer.LastActivity = time.Now()
    return nil
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

// sendPeerList sends our current peer list to a specific peer
func (m *Manager) sendPeerList(target *PeerConnection) {
    m.mu.RLock()
    var addrs []string
    for _, p := range m.peers {
        if p.RouterHash != target.RouterHash && p.Address != "" {
            addrs = append(addrs, p.Address)
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
        m.logger.Debug("Sent peer list (%d peers) to %s", len(addrs), target.Address)
    }
}

// HandlePeerList processes a received peer list and connects to unknown peers
func (m *Manager) HandlePeerList(payload []byte) {
    if len(payload) == 0 {
        return
    }
    addrs := strings.Split(string(payload), ",")
    for _, addr := range addrs {
        addr = strings.TrimSpace(addr)
        if addr == "" {
            continue
        }

        // Skip if it looks like our own listener
        if h, _, err := net.SplitHostPort(addr); err == nil {
            if h == "127.0.0.1" || h == "::1" {
                continue
            }
        }

        // Check by IP host — skip if already connected to same host
        addrHost := addr
        if h, _, err := net.SplitHostPort(addr); err == nil {
            addrHost = h
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
            continue
        }

        m.logger.Info("Peer exchange: discovered %s, connecting...", addr)
        go func(a string) {
            if err := m.ConnectTo(a); err != nil {
                m.logger.Debug("Peer exchange connect to %s failed: %v", a, err)
            }
        }(addr)
    }
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