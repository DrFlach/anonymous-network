package garlic

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"time"

	"network/pkg/crypto"
)

// CloveDeliveryType defines how a garlic clove should be delivered
type CloveDeliveryType uint8

const (
	DeliveryLocal       CloveDeliveryType = 0 // Deliver to local router
	DeliveryDestination CloveDeliveryType = 1 // Deliver to a destination (e.g., outproxy)
	DeliveryRouter      CloveDeliveryType = 2 // Deliver to a specific router
	DeliveryTunnel      CloveDeliveryType = 3 // Deliver into a tunnel
)

// Clove represents a single message within a garlic bundle
type Clove struct {
	ID           uint32
	DeliveryType CloveDeliveryType
	Destination  [32]byte // Router hash or destination hash depending on DeliveryType
	TunnelID     uint32   // Tunnel ID if DeliveryType is tunnel
	Expiration   time.Time
	Data         []byte
}

// GarlicMessage represents a garlic-encrypted message containing multiple cloves
type GarlicMessage struct {
	MessageID   uint32
	Cloves      []*Clove
	Certificate []byte // Optional certificate (signing, etc.)
	Expiration  time.Time
}

// NewGarlicMessage creates a new garlic message
func NewGarlicMessage(cloves []*Clove) *GarlicMessage {
	var id [4]byte
	rand.Read(id[:])

	return &GarlicMessage{
		MessageID:  binary.BigEndian.Uint32(id[:]),
		Cloves:     cloves,
		Expiration: time.Now().Add(60 * time.Second),
	}
}

// NewClove creates a new clove
func NewClove(deliveryType CloveDeliveryType, dest [32]byte, data []byte) *Clove {
	var id [4]byte
	rand.Read(id[:])

	return &Clove{
		ID:           binary.BigEndian.Uint32(id[:]),
		DeliveryType: deliveryType,
		Destination:  dest,
		Expiration:   time.Now().Add(60 * time.Second),
		Data:         data,
	}
}

// Serialize converts garlic message to bytes
func (gm *GarlicMessage) Serialize() ([]byte, error) {
	buf := new(bytes.Buffer)

	// Message ID
	binary.Write(buf, binary.BigEndian, gm.MessageID)

	// Expiration
	binary.Write(buf, binary.BigEndian, uint32(gm.Expiration.Unix()))

	// Number of cloves
	binary.Write(buf, binary.BigEndian, uint8(len(gm.Cloves)))

	// Serialize each clove
	for _, clove := range gm.Cloves {
		cloveData, err := serializeClove(clove)
		if err != nil {
			return nil, fmt.Errorf("failed to serialize clove: %w", err)
		}
		binary.Write(buf, binary.BigEndian, uint16(len(cloveData)))
		buf.Write(cloveData)
	}

	// Certificate length and data
	binary.Write(buf, binary.BigEndian, uint16(len(gm.Certificate)))
	if len(gm.Certificate) > 0 {
		buf.Write(gm.Certificate)
	}

	return buf.Bytes(), nil
}

// Deserialize parses a garlic message from bytes
func Deserialize(data []byte) (*GarlicMessage, error) {
	buf := bytes.NewReader(data)
	gm := &GarlicMessage{}

	// Message ID
	if err := binary.Read(buf, binary.BigEndian, &gm.MessageID); err != nil {
		return nil, err
	}

	// Expiration
	var exp uint32
	if err := binary.Read(buf, binary.BigEndian, &exp); err != nil {
		return nil, err
	}
	gm.Expiration = time.Unix(int64(exp), 0)

	// Number of cloves
	var numCloves uint8
	if err := binary.Read(buf, binary.BigEndian, &numCloves); err != nil {
		return nil, err
	}

	gm.Cloves = make([]*Clove, numCloves)
	for i := 0; i < int(numCloves); i++ {
		var cloveLen uint16
		if err := binary.Read(buf, binary.BigEndian, &cloveLen); err != nil {
			return nil, err
		}

		cloveData := make([]byte, cloveLen)
		if _, err := io.ReadFull(buf, cloveData); err != nil {
			return nil, err
		}

		clove, err := deserializeClove(cloveData)
		if err != nil {
			return nil, fmt.Errorf("failed to deserialize clove %d: %w", i, err)
		}
		gm.Cloves[i] = clove
	}

	// Certificate
	var certLen uint16
	if err := binary.Read(buf, binary.BigEndian, &certLen); err != nil {
		return nil, err
	}
	if certLen > 0 {
		gm.Certificate = make([]byte, certLen)
		if _, err := io.ReadFull(buf, gm.Certificate); err != nil {
			return nil, err
		}
	}

	return gm, nil
}

func serializeClove(c *Clove) ([]byte, error) {
	buf := new(bytes.Buffer)

	binary.Write(buf, binary.BigEndian, c.ID)
	binary.Write(buf, binary.BigEndian, uint8(c.DeliveryType))
	buf.Write(c.Destination[:])
	binary.Write(buf, binary.BigEndian, c.TunnelID)
	binary.Write(buf, binary.BigEndian, uint32(c.Expiration.Unix()))
	binary.Write(buf, binary.BigEndian, uint16(len(c.Data)))
	buf.Write(c.Data)

	return buf.Bytes(), nil
}

func deserializeClove(data []byte) (*Clove, error) {
	buf := bytes.NewReader(data)
	c := &Clove{}

	binary.Read(buf, binary.BigEndian, &c.ID)

	var dt uint8
	binary.Read(buf, binary.BigEndian, &dt)
	c.DeliveryType = CloveDeliveryType(dt)

	io.ReadFull(buf, c.Destination[:])
	binary.Read(buf, binary.BigEndian, &c.TunnelID)

	var exp uint32
	binary.Read(buf, binary.BigEndian, &exp)
	c.Expiration = time.Unix(int64(exp), 0)

	var dataLen uint16
	binary.Read(buf, binary.BigEndian, &dataLen)
	c.Data = make([]byte, dataLen)
	io.ReadFull(buf, c.Data)

	return c, nil
}

// Encrypt encrypts a garlic message for a specific recipient
func (gm *GarlicMessage) Encrypt(recipientPubKey [32]byte) ([]byte, error) {
	plaintext, err := gm.Serialize()
	if err != nil {
		return nil, fmt.Errorf("failed to serialize garlic message: %w", err)
	}

	// Generate ephemeral key for this message
	var ephPriv, ephPub [32]byte
	if _, err := io.ReadFull(rand.Reader, ephPriv[:]); err != nil {
		return nil, err
	}

	// Use DeriveSharedSecret from crypto package
	shared, err := crypto.DeriveSharedSecret(ephPriv, recipientPubKey)
	if err != nil {
		return nil, err
	}

	// Derive session keys and encrypt
	session, err := crypto.DeriveSessionKeys(shared, []byte("garlic-message"))
	if err != nil {
		return nil, err
	}

	ciphertext, err := session.Encrypt(plaintext)
	if err != nil {
		return nil, err
	}

	// Prepend ephemeral public key
	result := make([]byte, 32+len(ciphertext))
	copy(result[0:32], ephPub[:])
	copy(result[32:], ciphertext)

	return result, nil
}

// DecryptGarlic decrypts a garlic message using our private key
func DecryptGarlic(data []byte, privateKey [32]byte) (*GarlicMessage, error) {
	if len(data) < 32 {
		return nil, fmt.Errorf("garlic message too short")
	}

	var ephPub [32]byte
	copy(ephPub[:], data[0:32])

	shared, err := crypto.DeriveSharedSecret(privateKey, ephPub)
	if err != nil {
		return nil, err
	}

	session, err := crypto.DeriveSessionKeys(shared, []byte("garlic-message"))
	if err != nil {
		return nil, err
	}

	// For garlic decryption, we use the "receive" cipher since we are receiving
	// But session derives send/receive based on direction. We swap for receiver.
	swapped := &crypto.EncryptionSession{
		SendCipher:    session.ReceiveCipher,
		ReceiveCipher: session.SendCipher,
		SharedSecret:  session.SharedSecret,
	}

	plaintext, err := swapped.Decrypt(data[32:])
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt garlic: %w", err)
	}

	return Deserialize(plaintext)
}
