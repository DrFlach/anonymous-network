package garlic

import (
	"bytes"
	"testing"
	"time"

	"network/pkg/crypto"
)

func TestGarlicEncryptDecryptRoundTrip(t *testing.T) {
	recipient, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}

	var dest [32]byte
	copy(dest[:], []byte("destination-hash-for-test-000001"))
	payload := []byte("hello through garlic")

	msg := NewGarlicMessage([]*Clove{
		NewClove(DeliveryRouter, dest, payload),
	})

	encrypted, err := msg.Encrypt(recipient.EncryptionPublicKey)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	decrypted, err := DecryptGarlic(encrypted, recipient.EncryptionPrivateKey)
	if err != nil {
		t.Fatalf("DecryptGarlic: %v", err)
	}

	if decrypted.MessageID != msg.MessageID {
		t.Fatalf("MessageID mismatch: got %d want %d", decrypted.MessageID, msg.MessageID)
	}
	if len(decrypted.Cloves) != 1 {
		t.Fatalf("expected one clove, got %d", len(decrypted.Cloves))
	}
	if decrypted.Cloves[0].DeliveryType != DeliveryRouter {
		t.Fatalf("DeliveryType mismatch: got %d", decrypted.Cloves[0].DeliveryType)
	}
	if decrypted.Cloves[0].Destination != dest {
		t.Fatal("Destination mismatch")
	}
	if !bytes.Equal(decrypted.Cloves[0].Data, payload) {
		t.Fatalf("payload mismatch: got %q want %q", decrypted.Cloves[0].Data, payload)
	}
	if time.Until(decrypted.Expiration) <= 0 {
		t.Fatal("decrypted message is expired")
	}
}
