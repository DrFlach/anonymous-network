package tunnel

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"time"

	"network/pkg/crypto"
	"network/pkg/util"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
)

// BuildRequestRecord represents a tunnel build request for one hop
type BuildRequestRecord struct {
	ReceiveTunnelID TunnelID // Tunnel ID this hop will receive on
	NextIdent       [32]byte // Router hash of next hop (zero if endpoint)
	NextTunnelID    TunnelID // Tunnel ID for next hop
	LayerKey        [32]byte // Symmetric key for layer encryption
	IVKey           [32]byte // IV key for layer encryption
	IsEndpoint      bool     // True if this is the last hop
	RequestTime     uint32   // Build request timestamp
	SendMessageID   uint32   // Message ID for response
}

// BuildResponseRecord represents a response to a build request
type BuildResponseRecord struct {
	Reply byte // 0 = accept, 1 = reject, 2 = busy
}

const (
	BuildAccept byte = 0
	BuildReject byte = 1
	BuildBusy   byte = 2
)

// SerializeBuildRequest serializes a build request record
func SerializeBuildRequest(rec *BuildRequestRecord) []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.BigEndian, uint32(rec.ReceiveTunnelID))
	buf.Write(rec.NextIdent[:])
	binary.Write(buf, binary.BigEndian, uint32(rec.NextTunnelID))
	buf.Write(rec.LayerKey[:])
	buf.Write(rec.IVKey[:])
	if rec.IsEndpoint {
		buf.WriteByte(1)
	} else {
		buf.WriteByte(0)
	}
	binary.Write(buf, binary.BigEndian, rec.RequestTime)
	binary.Write(buf, binary.BigEndian, rec.SendMessageID)
	return buf.Bytes()
}

// DeserializeBuildRequest parses a build request record
func DeserializeBuildRequest(data []byte) (*BuildRequestRecord, error) {
	if len(data) < 109 { // 4+32+4+32+32+1+4+4 = 113, but at minimum ~109
		return nil, fmt.Errorf("build request too short: %d", len(data))
	}

	rec := &BuildRequestRecord{}
	buf := bytes.NewReader(data)

	var tid uint32
	binary.Read(buf, binary.BigEndian, &tid)
	rec.ReceiveTunnelID = TunnelID(tid)

	io.ReadFull(buf, rec.NextIdent[:])

	var ntid uint32
	binary.Read(buf, binary.BigEndian, &ntid)
	rec.NextTunnelID = TunnelID(ntid)

	io.ReadFull(buf, rec.LayerKey[:])
	io.ReadFull(buf, rec.IVKey[:])

	var ep byte
	binary.Read(buf, binary.BigEndian, &ep)
	rec.IsEndpoint = ep == 1

	binary.Read(buf, binary.BigEndian, &rec.RequestTime)
	binary.Read(buf, binary.BigEndian, &rec.SendMessageID)

	return rec, nil
}

// EncryptBuildRequestForHop encrypts a build request for a specific hop using their public key
func EncryptBuildRequestForHop(request []byte, recipientPubKey [32]byte) ([]byte, error) {
	// Generate ephemeral key pair for this request
	var ephPriv, ephPub [32]byte
	if _, err := io.ReadFull(rand.Reader, ephPriv[:]); err != nil {
		return nil, fmt.Errorf("failed to generate ephemeral key: %w", err)
	}
	curve25519.ScalarBaseMult(&ephPub, &ephPriv)

	// Derive shared secret
	shared, err := crypto.DeriveSharedSecret(ephPriv, recipientPubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to derive shared secret: %w", err)
	}

	// Encrypt with ChaCha20-Poly1305
	aead, err := chacha20poly1305.New(shared[:])
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	ciphertext := aead.Seal(nil, nonce, request, nil)

	// Result: [ephemeral_pub:32][nonce:12][ciphertext+tag]
	result := make([]byte, 32+len(nonce)+len(ciphertext))
	copy(result[0:32], ephPub[:])
	copy(result[32:32+len(nonce)], nonce)
	copy(result[32+len(nonce):], ciphertext)

	return result, nil
}

// DecryptBuildRequest decrypts a build request using our private key
func DecryptBuildRequest(data []byte, privateKey [32]byte) ([]byte, error) {
	if len(data) < 44 { // 32 + 12 minimum
		return nil, fmt.Errorf("encrypted build request too short")
	}

	// Extract ephemeral public key
	var ephPub [32]byte
	copy(ephPub[:], data[0:32])

	// Derive shared secret
	shared, err := crypto.DeriveSharedSecret(privateKey, ephPub)
	if err != nil {
		return nil, fmt.Errorf("failed to derive shared secret: %w", err)
	}

	// Decrypt
	aead, err := chacha20poly1305.New(shared[:])
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	nonceSize := aead.NonceSize()
	nonce := data[32 : 32+nonceSize]
	ciphertext := data[32+nonceSize:]

	plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt build request: %w", err)
	}

	return plaintext, nil
}

// TunnelBuilder handles building new tunnels
type TunnelBuilder struct {
	identity       *crypto.RouterIdentity
	logger         *util.Logger
	tunnelLifetime time.Duration
}

// NewTunnelBuilder creates a new tunnel builder
func NewTunnelBuilder(identity *crypto.RouterIdentity, tunnelLifetime time.Duration) *TunnelBuilder {
	return &TunnelBuilder{
		identity:       identity,
		logger:         util.GetLogger(),
		tunnelLifetime: tunnelLifetime,
	}
}

// BuildTunnel creates a new tunnel through the specified hops
// peerKeys maps router hash -> encryption public key
func (tb *TunnelBuilder) BuildTunnel(direction Direction, hopRouters [][32]byte, peerKeys map[[32]byte][32]byte) (*Tunnel, [][]byte, error) {
	if len(hopRouters) == 0 {
		return nil, nil, fmt.Errorf("need at least one hop")
	}

	hops := make([]*HopInfo, len(hopRouters))
	buildRequests := make([][]byte, len(hopRouters))

	for i, routerHash := range hopRouters {
		// Generate random keys for this hop
		var layerKey, ivKey [32]byte
		if _, err := io.ReadFull(rand.Reader, layerKey[:]); err != nil {
			return nil, nil, fmt.Errorf("failed to generate layer key: %w", err)
		}
		if _, err := io.ReadFull(rand.Reader, ivKey[:]); err != nil {
			return nil, nil, fmt.Errorf("failed to generate IV key: %w", err)
		}

		tunnelID := GenerateTunnelID()
		isEndpoint := i == len(hopRouters)-1

		var nextHop [32]byte
		var nextTunnelID TunnelID
		if !isEndpoint {
			nextHop = hopRouters[i+1]
			nextTunnelID = GenerateTunnelID() // Will be overwritten when we set up next hop
		}

		hops[i] = &HopInfo{
			RouterHash:    routerHash,
			TunnelID:      tunnelID,
			EncryptionKey: layerKey,
			IVKey:         ivKey,
			NextHop:       nextHop,
			NextTunnelID:  nextTunnelID,
			IsEndpoint:    isEndpoint,
		}

		// Fix previous hop's NextTunnelID to point to this hop's receive ID
		if i > 0 {
			hops[i-1].NextTunnelID = tunnelID
		}

		// Create build request record
		req := &BuildRequestRecord{
			ReceiveTunnelID: tunnelID,
			NextIdent:       nextHop,
			NextTunnelID:    nextTunnelID,
			LayerKey:        layerKey,
			IVKey:           ivKey,
			IsEndpoint:      isEndpoint,
			RequestTime:     uint32(time.Now().Unix()),
			SendMessageID:   uint32(tunnelID),
		}

		// Also fix the NextTunnelID in the request for non-last hops
		if i > 0 {
			buildRequests[i-1] = nil // Will rebuild
		}

		// Serialize and encrypt the build request for this hop
		serialized := SerializeBuildRequest(req)

		pubKey, ok := peerKeys[routerHash]
		if !ok {
			return nil, nil, fmt.Errorf("no public key for router %x", routerHash[:8])
		}

		encrypted, err := EncryptBuildRequestForHop(serialized, pubKey)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to encrypt build request for hop %d: %w", i, err)
		}

		buildRequests[i] = encrypted
	}

	// Rebuild any requests that had their NextTunnelID updated
	for i := 0; i < len(hops)-1; i++ {
		req := &BuildRequestRecord{
			ReceiveTunnelID: hops[i].TunnelID,
			NextIdent:       hops[i].NextHop,
			NextTunnelID:    hops[i].NextTunnelID,
			LayerKey:        hops[i].EncryptionKey,
			IVKey:           hops[i].IVKey,
			IsEndpoint:      false,
			RequestTime:     uint32(time.Now().Unix()),
			SendMessageID:   uint32(hops[i].TunnelID),
		}

		serialized := SerializeBuildRequest(req)
		pubKey := peerKeys[hops[i].RouterHash]

		encrypted, err := EncryptBuildRequestForHop(serialized, pubKey)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to encrypt build request for hop %d: %w", i, err)
		}
		buildRequests[i] = encrypted
	}

	tunnel := NewTunnel(direction, hops, tb.tunnelLifetime)
	tb.logger.Info("Built %s tunnel with %d hops, ID=%d",
		directionString(direction), len(hops), tunnel.ID)

	return tunnel, buildRequests, nil
}

func directionString(d Direction) string {
	if d == Inbound {
		return "inbound"
	}
	return "outbound"
}
