package crypto

import (
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

// EncryptionSession represents an encrypted session between two routers
type EncryptionSession struct {
	SendCipher    cipher.AEAD
	ReceiveCipher cipher.AEAD
	SharedSecret  [32]byte
}

// DeriveSharedSecret performs X25519 ECDH key exchange
func DeriveSharedSecret(privateKey, publicKey [32]byte) ([32]byte, error) {
	var sharedSecret [32]byte
	curve25519.ScalarMult(&sharedSecret, &privateKey, &publicKey)

	// Check for weak shared secret (all zeros)
	var zero [32]byte
	if sharedSecret == zero {
		return zero, fmt.Errorf("weak shared secret derived")
	}

	return sharedSecret, nil
}

// DeriveSessionKeys derives encryption keys from shared secret using HKDF
func DeriveSessionKeys(sharedSecret [32]byte, context []byte) (*EncryptionSession, error) {
	// Use HKDF to derive two 32-byte keys for bidirectional communication
	kdf := hkdf.New(sha256.New, sharedSecret[:], nil, context)

	sendKey := make([]byte, chacha20poly1305.KeySize)
	if _, err := io.ReadFull(kdf, sendKey); err != nil {
		return nil, fmt.Errorf("failed to derive send key: %w", err)
	}

	recvKey := make([]byte, chacha20poly1305.KeySize)
	if _, err := io.ReadFull(kdf, recvKey); err != nil {
		return nil, fmt.Errorf("failed to derive receive key: %w", err)
	}

	// Create ChaCha20-Poly1305 AEAD ciphers
	sendCipher, err := chacha20poly1305.New(sendKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create send cipher: %w", err)
	}

	recvCipher, err := chacha20poly1305.New(recvKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create receive cipher: %w", err)
	}

	return &EncryptionSession{
		SendCipher:    sendCipher,
		ReceiveCipher: recvCipher,
		SharedSecret:  sharedSecret,
	}, nil
}

// Encrypt encrypts plaintext using the send cipher
// Returns: [nonce][ciphertext+tag]
func (es *EncryptionSession) Encrypt(plaintext []byte) ([]byte, error) {
	nonce := make([]byte, es.SendCipher.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	ciphertext := es.SendCipher.Seal(nil, nonce, plaintext, nil)

	// Prepend nonce to ciphertext
	result := make([]byte, len(nonce)+len(ciphertext))
	copy(result, nonce)
	copy(result[len(nonce):], ciphertext)

	return result, nil
}

// Decrypt decrypts ciphertext using the receive cipher
// Expects: [nonce][ciphertext+tag]
func (es *EncryptionSession) Decrypt(data []byte) ([]byte, error) {
	nonceSize := es.ReceiveCipher.NonceSize()
	if len(data) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce := data[:nonceSize]
	ciphertext := data[nonceSize:]

	plaintext, err := es.ReceiveCipher.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}

	return plaintext, nil
}

// EncryptLayered encrypts data with multiple layers for tunnel routing
// Each layer is encrypted with a different key
func EncryptLayered(plaintext []byte, keys [][32]byte) ([]byte, error) {
	data := plaintext

	// Encrypt from innermost to outermost layer (reverse order)
	for i := len(keys) - 1; i >= 0; i-- {
		cipher, err := chacha20poly1305.New(keys[i][:])
		if err != nil {
			return nil, fmt.Errorf("failed to create cipher for layer %d: %w", i, err)
		}

		nonce := make([]byte, cipher.NonceSize())
		if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
			return nil, fmt.Errorf("failed to generate nonce for layer %d: %w", i, err)
		}

		ciphertext := cipher.Seal(nil, nonce, data, nil)

		// Prepend nonce
		result := make([]byte, len(nonce)+len(ciphertext))
		copy(result, nonce)
		copy(result[len(nonce):], ciphertext)

		data = result
	}

	return data, nil
}

// DecryptLayer removes one layer of encryption
func DecryptLayer(data []byte, key [32]byte) ([]byte, error) {
	cipher, err := chacha20poly1305.New(key[:])
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	nonceSize := cipher.NonceSize()
	if len(data) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce := data[:nonceSize]
	ciphertext := data[nonceSize:]

	plaintext, err := cipher.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}

	return plaintext, nil
}
