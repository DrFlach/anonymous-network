package ntcp2

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"network/pkg/crypto"
)

// Connection represents an encrypted NTCP2 connection
type Connection struct {
	conn          net.Conn
	session       *crypto.EncryptionSession
	remotePubKey  [32]byte
	remoteSignKey ed25519.PublicKey
	remoteHash    [32]byte // Remote peer's router hash
	mu            sync.Mutex
	lastActivity  time.Time
	closed        atomic.Bool
	closeOnce     sync.Once
}

const (
	authProofSize = 32 + 32 + ed25519.SignatureSize // signPub + encPub + signature
)

// NewConnection creates a new NTCP2 connection
func NewConnection(conn net.Conn) *Connection {
	return &Connection{
		conn:         conn,
		lastActivity: time.Now(),
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

	// Auth proof exchange: initiator sends first, then receives responder proof.
	proof := buildAuthProof(identity, ephemPub, remoteEphem)
	if err := c.SendFrame(proof); err != nil {
		return fmt.Errorf("failed to send auth proof: %w", err)
	}

	remoteProof, err := c.ReceiveFrame()
	if err != nil {
		return fmt.Errorf("failed to receive auth proof: %w", err)
	}
	if err := c.verifyRemoteProof(remoteProof, ephemPub, remoteEphem); err != nil {
		return fmt.Errorf("remote auth proof invalid: %w", err)
	}

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

	// Auth proof exchange: responder receives first, then sends own proof.
	remoteProof, err := c.ReceiveFrame()
	if err != nil {
		return fmt.Errorf("failed to receive auth proof: %w", err)
	}
	if err := c.verifyRemoteProof(remoteProof, remoteEphem, ephemPub); err != nil {
		return fmt.Errorf("remote auth proof invalid: %w", err)
	}

	proof := buildAuthProof(identity, remoteEphem, ephemPub)
	if err := c.SendFrame(proof); err != nil {
		return fmt.Errorf("failed to send auth proof: %w", err)
	}

	c.lastActivity = time.Now()
	return nil
}

func buildAuthProof(identity *crypto.RouterIdentity, initiatorEphem, responderEphem [32]byte) []byte {
	payload := buildAuthPayload(initiatorEphem, responderEphem, identity.RouterHash, identity.EncryptionPublicKey)
	sig := ed25519.Sign(identity.SigningPrivateKey, payload)

	out := make([]byte, authProofSize)
	copy(out[:32], identity.SigningPublicKey)
	copy(out[32:64], identity.EncryptionPublicKey[:])
	copy(out[64:], sig)
	return out
}

func buildAuthPayload(initiatorEphem, responderEphem, routerHash, encPub [32]byte) []byte {
	buf := make([]byte, 0, 16+32+32+32+32)
	buf = append(buf, []byte("ANON-NTCP2-AUTH")...)
	buf = append(buf, initiatorEphem[:]...)
	buf = append(buf, responderEphem[:]...)
	buf = append(buf, routerHash[:]...)
	buf = append(buf, encPub[:]...)
	return buf
}

func (c *Connection) verifyRemoteProof(proof []byte, initiatorEphem, responderEphem [32]byte) error {
	if len(proof) != authProofSize {
		return fmt.Errorf("invalid auth proof size: %d", len(proof))
	}

	var signingPub [32]byte
	copy(signingPub[:], proof[:32])
	copy(c.remotePubKey[:], proof[32:64])
	signature := proof[64:]

	hash := sha256.Sum256(signingPub[:])
	if hash != c.remoteHash {
		return fmt.Errorf("router hash mismatch with signing key")
	}

	payload := buildAuthPayload(initiatorEphem, responderEphem, c.remoteHash, c.remotePubKey)
	if !ed25519.Verify(ed25519.PublicKey(signingPub[:]), payload, signature) {
		return fmt.Errorf("invalid auth signature")
	}

	c.remoteSignKey = make(ed25519.PublicKey, 32)
	copy(c.remoteSignKey, signingPub[:])
	return nil
}

// SendFrame sends an encrypted frame
func (c *Connection) SendFrame(data []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed.Load() {
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
	if c.closed.Load() {
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
	var err error
	c.closeOnce.Do(func() {
		c.closed.Store(true)
		err = c.conn.Close()
	})
	return err
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
