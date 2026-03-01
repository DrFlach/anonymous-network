package ntcp2

import (
    "encoding/binary"
    "fmt"
    "io"
    "net"
    "sync"
    "time"

    "network/pkg/crypto"
)

// Connection represents an encrypted NTCP2 connection
type Connection struct {
    conn          net.Conn
    session       *crypto.EncryptionSession
    remotePubKey  [32]byte
    remoteHash    [32]byte // Remote peer's router hash
    mu            sync.Mutex
    lastActivity  time.Time
    closed        bool
}

// NewConnection creates a new NTCP2 connection
func NewConnection(conn net.Conn) *Connection {
    return &Connection{
        conn:         conn,
        lastActivity: time.Now(),
        closed:       false,
    }
}

// Handshake performs the NTCP2 handshake and identity exchange
func (c *Connection) Handshake(identity *crypto.RouterIdentity, isInitiator bool) error {
    if isInitiator {
        return c.initiatorHandshake(identity)
    }
    return c.responderHandshake(identity)
}

// RemoteRouterHash returns the router hash of the remote peer (available after handshake)
func (c *Connection) RemoteRouterHash() [32]byte {
    return c.remoteHash
}

// initiatorHandshake performs handshake as initiator
func (c *Connection) initiatorHandshake(identity *crypto.RouterIdentity) error {
    c.conn.SetDeadline(time.Now().Add(15 * time.Second))
    defer c.conn.SetDeadline(time.Time{})

    // Generate ephemeral key
    hs, err := NewHandshake(true, identity.EncryptionPrivateKey)
    if err != nil {
        return fmt.Errorf("failed to create handshake: %w", err)
    }
    
    // Send ephemeral public key
    ephemPub := hs.GetEphemeralPublic()
    if _, err := c.conn.Write(ephemPub[:]); err != nil {
        return fmt.Errorf("failed to send ephemeral key: %w", err)
    }
    
    // Receive responder's ephemeral key
    var remoteEphem [32]byte
    if _, err := io.ReadFull(c.conn, remoteEphem[:]); err != nil {
        return fmt.Errorf("failed to receive ephemeral key: %w", err)
    }
    hs.RemoteEphemeral = remoteEphem
    
    // Perform DH(e, re)
    sharedSecret, err := PerformDH(hs.LocalEphemeral, hs.RemoteEphemeral)
    if err != nil {
        return fmt.Errorf("failed to perform DH: %w", err)
    }
    
    // Derive session keys
    context := []byte("NTCP2-Session")
    c.session, err = crypto.DeriveSessionKeys(sharedSecret, context)
    if err != nil {
        return fmt.Errorf("failed to derive session keys: %w", err)
    }

    // --- Identity exchange (over encrypted channel) ---
    // Send our router hash
    if err := c.SendFrame(identity.RouterHash[:]); err != nil {
        return fmt.Errorf("failed to send identity: %w", err)
    }

    // Receive remote router hash
    remoteHashData, err := c.ReceiveFrame()
    if err != nil {
        return fmt.Errorf("failed to receive remote identity: %w", err)
    }
    if len(remoteHashData) != 32 {
        return fmt.Errorf("invalid remote identity length: %d", len(remoteHashData))
    }
    copy(c.remoteHash[:], remoteHashData)

    c.lastActivity = time.Now()
    return nil
}

// responderHandshake performs handshake as responder
func (c *Connection) responderHandshake(identity *crypto.RouterIdentity) error {
    c.conn.SetDeadline(time.Now().Add(15 * time.Second))
    defer c.conn.SetDeadline(time.Time{})

    // Generate ephemeral key
    hs, err := NewHandshake(false, identity.EncryptionPrivateKey)
    if err != nil {
        return fmt.Errorf("failed to create handshake: %w", err)
    }
    
    // Receive initiator's ephemeral key
    var remoteEphem [32]byte
    if _, err := io.ReadFull(c.conn, remoteEphem[:]); err != nil {
        return fmt.Errorf("failed to receive ephemeral key: %w", err)
    }
    hs.RemoteEphemeral = remoteEphem
    
    // Send our ephemeral public key
    ephemPub := hs.GetEphemeralPublic()
    if _, err := c.conn.Write(ephemPub[:]); err != nil {
        return fmt.Errorf("failed to send ephemeral key: %w", err)
    }
    
    // Perform DH(e, re)
    sharedSecret, err := PerformDH(hs.LocalEphemeral, hs.RemoteEphemeral)
    if err != nil {
        return fmt.Errorf("failed to perform DH: %w", err)
    }
    
    // Derive session keys (swap send/recv for responder)
    context := []byte("NTCP2-Session")
    session, err := crypto.DeriveSessionKeys(sharedSecret, context)
    if err != nil {
        return fmt.Errorf("failed to derive session keys: %w", err)
    }
    
    // Swap ciphers for responder
    c.session = &crypto.EncryptionSession{
        SendCipher:    session.ReceiveCipher,
        ReceiveCipher: session.SendCipher,
        SharedSecret:  session.SharedSecret,
    }

    // --- Identity exchange (over encrypted channel) ---
    // Receive initiator's router hash first
    remoteHashData, err := c.ReceiveFrame()
    if err != nil {
        return fmt.Errorf("failed to receive remote identity: %w", err)
    }
    if len(remoteHashData) != 32 {
        return fmt.Errorf("invalid remote identity length: %d", len(remoteHashData))
    }
    copy(c.remoteHash[:], remoteHashData)

    // Send our router hash
    if err := c.SendFrame(identity.RouterHash[:]); err != nil {
        return fmt.Errorf("failed to send identity: %w", err)
    }

    c.lastActivity = time.Now()
    return nil
}

// SendFrame sends an encrypted frame
func (c *Connection) SendFrame(data []byte) error {
    c.mu.Lock()
    defer c.mu.Unlock()
    
    if c.closed {
        return fmt.Errorf("connection closed")
    }
    
    // Encrypt data
    encrypted, err := c.session.Encrypt(data)
    if err != nil {
        return fmt.Errorf("failed to encrypt frame: %w", err)
    }
    
    // Send length prefix (4 bytes for larger frames)
    lengthBuf := make([]byte, 4)
    binary.BigEndian.PutUint32(lengthBuf, uint32(len(encrypted)))
    
    if _, err := c.conn.Write(lengthBuf); err != nil {
        return fmt.Errorf("failed to write frame length: %w", err)
    }
    
    // Send encrypted data
    if _, err := c.conn.Write(encrypted); err != nil {
        return fmt.Errorf("failed to write frame data: %w", err)
    }
    
    c.lastActivity = time.Now()
    return nil
}

// ReceiveFrame receives and decrypts a frame
func (c *Connection) ReceiveFrame() ([]byte, error) {
    if c.closed {
        return nil, fmt.Errorf("connection closed")
    }
    
    // Read length prefix (4 bytes)
    lengthBuf := make([]byte, 4)
    if _, err := io.ReadFull(c.conn, lengthBuf); err != nil {
        return nil, fmt.Errorf("failed to read frame length: %w", err)
    }
    
    length := binary.BigEndian.Uint32(lengthBuf)
    if length > 1<<20 { // 1MB max
        return nil, fmt.Errorf("invalid frame length: %d", length)
    }
    
    // Read encrypted data
    encrypted := make([]byte, length)
    if _, err := io.ReadFull(c.conn, encrypted); err != nil {
        return nil, fmt.Errorf("failed to read frame data: %w", err)
    }
    
    // Decrypt
    decrypted, err := c.session.Decrypt(encrypted)
    if err != nil {
        return nil, fmt.Errorf("failed to decrypt frame: %w", err)
    }
    
    c.lastActivity = time.Now()
    return decrypted, nil
}

// Close closes the connection
func (c *Connection) Close() error {
    c.mu.Lock()
    defer c.mu.Unlock()
    
    if c.closed {
        return nil
    }
    
    c.closed = true
    return c.conn.Close()
}

// IsAlive checks if connection is still active (heartbeat)
func (c *Connection) IsAlive() bool {
    return time.Since(c.lastActivity) < 60*time.Second
}

// SetDeadline sets the read/write deadline for the underlying connection
func (c *Connection) SetDeadline(t time.Time) error {
    return c.conn.SetDeadline(t)
}

// RemoteAddr returns the remote address
func (c *Connection) RemoteAddr() net.Addr {
    return c.conn.RemoteAddr()
}