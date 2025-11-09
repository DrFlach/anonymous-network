package ntcp2

import (
    "crypto/rand"
    "fmt"
    "io"

    "golang.org/x/crypto/curve25519"
)

// HandshakeState represents the state of a Noise handshake
type HandshakeState struct {
    LocalEphemeral  [32]byte
    RemoteEphemeral [32]byte
    LocalStatic     [32]byte
    RemoteStatic    [32]byte
    ChainingKey     [32]byte
    Hash            [32]byte
    IsInitiator     bool
}

// NewHandshake creates a new handshake state
func NewHandshake(isInitiator bool, localStatic [32]byte) (*HandshakeState, error) {
    hs := &HandshakeState{
        LocalStatic: localStatic,
        IsInitiator: isInitiator,
    }
    
    // Generate ephemeral key pair
    if _, err := io.ReadFull(rand.Reader, hs.LocalEphemeral[:]); err != nil {
        return nil, fmt.Errorf("failed to generate ephemeral key: %w", err)
    }
    
    return hs, nil
}

// GetEphemeralPublic returns the ephemeral public key
func (hs *HandshakeState) GetEphemeralPublic() [32]byte {
    var pub [32]byte
    curve25519.ScalarBaseMult(&pub, &hs.LocalEphemeral)
    return pub
}

// GetStaticPublic returns the static public key
func (hs *HandshakeState) GetStaticPublic() [32]byte {
    var pub [32]byte
    curve25519.ScalarBaseMult(&pub, &hs.LocalStatic)
    return pub
}

// PerformDH performs Diffie-Hellman between private and public keys
func PerformDH(privateKey, publicKey [32]byte) ([32]byte, error) {
    var sharedSecret [32]byte
    curve25519.ScalarMult(&sharedSecret, &privateKey, &publicKey)
    
    // Check for weak shared secret
    var zero [32]byte
    if sharedSecret == zero {
        return zero, fmt.Errorf("weak shared secret")
    }
    
    return sharedSecret, nil
}