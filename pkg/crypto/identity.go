package crypto

import (
    "crypto/ed25519"
    "crypto/rand"
    "crypto/sha256"
    "encoding/base64"
    "fmt"
    "io"

    "golang.org/x/crypto/curve25519"
)

// RouterIdentity represents a node's cryptographic identity
type RouterIdentity struct {
    SigningPublicKey    ed25519.PublicKey  // 32 bytes
    SigningPrivateKey   ed25519.PrivateKey // 64 bytes
    EncryptionPublicKey [32]byte           // X25519 public key
    EncryptionPrivateKey [32]byte          // X25519 private key
    RouterHash          [32]byte           // SHA-256 of signing public key
}

// GenerateIdentity creates a new router identity with signing and encryption keys
func GenerateIdentity() (*RouterIdentity, error) {
    // Generate Ed25519 signing key pair
    sigPubKey, sigPrivKey, err := ed25519.GenerateKey(rand.Reader)
    if err != nil {
        return nil, fmt.Errorf("failed to generate signing keys: %w", err)
    }

    // Generate X25519 encryption key pair
    var encPrivKey, encPubKey [32]byte
    if _, err := io.ReadFull(rand.Reader, encPrivKey[:]); err != nil {
        return nil, fmt.Errorf("failed to generate encryption private key: %w", err)
    }
    curve25519.ScalarBaseMult(&encPubKey, &encPrivKey)

    // Calculate router hash (SHA-256 of signing public key)
    routerHash := sha256.Sum256(sigPubKey)

    return &RouterIdentity{
        SigningPublicKey:     sigPubKey,
        SigningPrivateKey:    sigPrivKey,
        EncryptionPublicKey:  encPubKey,
        EncryptionPrivateKey: encPrivKey,
        RouterHash:           routerHash,
    }, nil
}

// Sign signs data with the router's signing key
func (ri *RouterIdentity) Sign(data []byte) []byte {
    return ed25519.Sign(ri.SigningPrivateKey, data)
}

// Verify verifies a signature against this router's public key
func (ri *RouterIdentity) Verify(data, signature []byte) bool {
    return ed25519.Verify(ri.SigningPublicKey, data, signature)
}

// GetRouterHashString returns base64-encoded router hash for display
func (ri *RouterIdentity) GetRouterHashString() string {
    return base64.RawStdEncoding.EncodeToString(ri.RouterHash[:])
}

// VerifySignature verifies a signature using the provided public key
func VerifySignature(pubKey ed25519.PublicKey, data, signature []byte) bool {
    return ed25519.Verify(pubKey, data, signature)
}