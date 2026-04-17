package crypto

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/crypto/curve25519"
)

// PersistedIdentity is the JSON-serializable form of RouterIdentity
type PersistedIdentity struct {
	SigningPublicKey     []byte `json:"signing_public_key"`
	SigningPrivateKey    []byte `json:"signing_private_key"`
	EncryptionPublicKey  []byte `json:"encryption_public_key"`
	EncryptionPrivateKey []byte `json:"encryption_private_key"`
	RouterHash           []byte `json:"router_hash"`
}

// SaveIdentity saves a RouterIdentity to a file (encrypted with a passphrase in future)
func SaveIdentity(identity *RouterIdentity, path string) error {
	persisted := &PersistedIdentity{
		SigningPublicKey:     identity.SigningPublicKey,
		SigningPrivateKey:    identity.SigningPrivateKey,
		EncryptionPublicKey:  identity.EncryptionPublicKey[:],
		EncryptionPrivateKey: identity.EncryptionPrivateKey[:],
		RouterHash:           identity.RouterHash[:],
	}

	data, err := json.MarshalIndent(persisted, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal identity: %w", err)
	}

	// Write atomically with restrictive permissions (owner read/write only)
	tmpPath := path + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0600); err != nil {
		return fmt.Errorf("failed to write identity temp file: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("failed to atomically replace identity file: %w", err)
	}
	if err := os.Chmod(path, 0600); err != nil {
		return fmt.Errorf("failed to write identity file: %w", err)
	}

	return nil
}

// LoadIdentity loads a RouterIdentity from a file
func LoadIdentity(path string) (*RouterIdentity, error) {
	if err := validateIdentityFilePerms(path); err != nil {
		return nil, err
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read identity file: %w", err)
	}

	var persisted PersistedIdentity
	if err := json.Unmarshal(data, &persisted); err != nil {
		return nil, fmt.Errorf("failed to parse identity: %w", err)
	}

	identity := &RouterIdentity{
		SigningPublicKey:  ed25519.PublicKey(persisted.SigningPublicKey),
		SigningPrivateKey: ed25519.PrivateKey(persisted.SigningPrivateKey),
	}

	copy(identity.EncryptionPublicKey[:], persisted.EncryptionPublicKey)
	copy(identity.EncryptionPrivateKey[:], persisted.EncryptionPrivateKey)
	copy(identity.RouterHash[:], persisted.RouterHash)

	// Verify the identity is valid
	if !identity.verifyIntegrity() {
		return nil, fmt.Errorf("identity integrity check failed")
	}

	return identity, nil
}

func validateIdentityFilePerms(path string) error {
	st, err := os.Stat(path)
	if err != nil {
		return err
	}
	if st.IsDir() {
		return fmt.Errorf("identity path is a directory: %s", path)
	}

	perm := st.Mode().Perm()
	if perm&0o077 != 0 {
		return fmt.Errorf("identity file %s has insecure permissions %s (required: 0600)", filepath.Base(path), perm.String())
	}
	return nil
}

// LoadOrCreateIdentity loads an existing identity or creates a new one
func LoadOrCreateIdentity(path string) (*RouterIdentity, bool, error) {
	// Try to load existing identity
	identity, err := LoadIdentity(path)
	if err == nil {
		return identity, false, nil
	}

	// Create new identity
	identity, err = GenerateIdentity()
	if err != nil {
		return nil, false, fmt.Errorf("failed to generate identity: %w", err)
	}

	// Save it
	if err := SaveIdentity(identity, path); err != nil {
		return nil, false, fmt.Errorf("failed to save identity: %w", err)
	}

	return identity, true, nil
}

// verifyIntegrity verifies that the keys in the identity are consistent
func (ri *RouterIdentity) verifyIntegrity() bool {
	// Verify signing key pair
	testData := []byte("integrity-check")
	sig := ed25519.Sign(ri.SigningPrivateKey, testData)
	if !ed25519.Verify(ri.SigningPublicKey, testData, sig) {
		return false
	}

	// Verify encryption key pair
	var derivedPub [32]byte
	curve25519.ScalarBaseMult(&derivedPub, &ri.EncryptionPrivateKey)
	if derivedPub != ri.EncryptionPublicKey {
		return false
	}

	return true
}
