package transport

import (
    "fmt"
    "net"
    "sync"
    "time"

    "network/pkg/crypto"
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

// Start starts the transport manager and listens for connections
func (m *Manager) Start(listenAddr string) error {
    listener, err := net.Listen("tcp", listenAddr)
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
            m.logger.Error("Accept error: %v", err)
            continue
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
    
    // Create NTCP2 connection
    ntcpConn := ntcp2.NewConnection(conn)
    
    // Perform handshake as responder
    if err := ntcpConn.Handshake(m.identity, false); err != nil {
        m.logger.Error("Handshake failed with %s: %v", conn.RemoteAddr(), err)
        return
    }
    
    m.logger.Info("Handshake completed with %s", conn.RemoteAddr())
    
    // For now, we'll use a placeholder router hash
    // In full implementation, this would be exchanged during handshake
    var routerHash [32]byte
    copy(routerHash[:], []byte(conn.RemoteAddr().String())) // Temporary placeholder
    
    // Add to peer list
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
    
    m.logger.Info("Peer connected: %s (total: %d)", peer.Address, len(m.peers))
    
    // Start receiving messages from this peer
    m.receiveLoop(peer)
    
    // Cleanup on disconnect
    m.mu.Lock()
    delete(m.peers, routerHash)
    delete(m.peersByAddr, peer.Address)
    m.mu.Unlock()
    
    m.logger.Info("Peer disconnected: %s (total: %d)", peer.Address, len(m.peers))
}

// ConnectTo connects to a remote peer
func (m *Manager) ConnectTo(address string) error {
    m.mu.RLock()
    _, exists := m.peersByAddr[address]
    peerCount := len(m.peers)
    m.mu.RUnlock()
    
    if exists {
        return fmt.Errorf("already connected to %s", address)
    }
    
    if peerCount >= m.maxPeers {
        return fmt.Errorf("max peers reached")
    }
    
    m.logger.Info("Connecting to %s...", address)
    
    conn, err := net.DialTimeout("tcp", address, 10*time.Second)
    if err != nil {
        return fmt.Errorf("failed to connect to %s: %w", address, err)
    }
    
    // Create NTCP2 connection
    ntcpConn := ntcp2.NewConnection(conn)
    
    // Perform handshake as initiator
    if err := ntcpConn.Handshake(m.identity, true); err != nil {
        conn.Close()
        return fmt.Errorf("handshake failed with %s: %w", address, err)
    }
    
    m.logger.Info("Handshake completed with %s", address)
    
    // Placeholder router hash
    var routerHash [32]byte
    copy(routerHash[:], []byte(address))
    
    // Add to peer list
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
    
    m.logger.Info("Peer connected: %s (total: %d)", address, len(m.peers))
    
    // Start receiving messages
    m.wg.Add(1)
    go func() {
        defer m.wg.Done()
        m.receiveLoop(peer)
        
        // Cleanup on disconnect
        m.mu.Lock()
        delete(m.peers, routerHash)
        delete(m.peersByAddr, address)
        m.mu.Unlock()
        
        m.logger.Info("Peer disconnected: %s (total: %d)", address, len(m.peers))
    }()
    
    return nil
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
            m.logger.Debug("Receive error from %s: %v", peer.Address, err)
            return
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
    heartbeat := []byte("PING")
    
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
    
    m.wg.Wait()
    
    m.logger.Info("Transport manager stopped")
}