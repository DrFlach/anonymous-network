package router

import (
    "bytes"
    "encoding/binary"
    "fmt"
    "time"
)

// MessageType represents the type of network message
type MessageType uint8

const (
    MsgTypePing MessageType = iota
    MsgTypePong
    MsgTypeDatabaseStore
    MsgTypeDatabaseLookup
    MsgTypeDatabaseSearchReply
    MsgTypeTunnelBuild
    MsgTypeTunnelBuildReply
    MsgTypeTunnelData
    MsgTypeDeliveryStatus
)

// Message represents a network protocol message
type Message struct {
    Type       MessageType
    ID         uint32
    Expiration time.Time
    Payload    []byte
}

// NewMessage creates a new message
func NewMessage(msgType MessageType, payload []byte) *Message {
    return &Message{
        Type:       msgType,
        ID:         uint32(time.Now().UnixNano() & 0xFFFFFFFF),
        Expiration: time.Now().Add(60 * time.Second),
        Payload:    payload,
    }
}

// Serialize converts message to bytes
func (m *Message) Serialize() ([]byte, error) {
    buf := new(bytes.Buffer)
    
    // Write type
    if err := binary.Write(buf, binary.BigEndian, uint8(m.Type)); err != nil {
        return nil, err
    }
    
    // Write ID
    if err := binary.Write(buf, binary.BigEndian, m.ID); err != nil {
        return nil, err
    }
    
    // Write expiration (Unix timestamp)
    if err := binary.Write(buf, binary.BigEndian, uint32(m.Expiration.Unix())); err != nil {
        return nil, err
    }
    
    // Write payload length
    if err := binary.Write(buf, binary.BigEndian, uint16(len(m.Payload))); err != nil {
        return nil, err
    }
    
    // Write payload
    if _, err := buf.Write(m.Payload); err != nil {
        return nil, err
    }
    
    return buf.Bytes(), nil
}

// Deserialize parses a message from bytes
func Deserialize(data []byte) (*Message, error) {
    if len(data) < 11 { // type(1) + id(4) + exp(4) + len(2)
        return nil, fmt.Errorf("message too short")
    }
    
    buf := bytes.NewReader(data)
    msg := &Message{}
    
    // Read type
    var msgType uint8
    if err := binary.Read(buf, binary.BigEndian, &msgType); err != nil {
        return nil, err
    }
    msg.Type = MessageType(msgType)
    
    // Read ID
    if err := binary.Read(buf, binary.BigEndian, &msg.ID); err != nil {
        return nil, err
    }
    
    // Read expiration
    var exp uint32
    if err := binary.Read(buf, binary.BigEndian, &exp); err != nil {
        return nil, err
    }
    msg.Expiration = time.Unix(int64(exp), 0)
    
    // Read payload length
    var payloadLen uint16
    if err := binary.Read(buf, binary.BigEndian, &payloadLen); err != nil {
        return nil, err
    }
    
    // Read payload
    msg.Payload = make([]byte, payloadLen)
    if _, err := buf.Read(msg.Payload); err != nil {
        return nil, err
    }
    
    return msg, nil
}

// IsExpired checks if the message has expired
func (m *Message) IsExpired() bool {
    return time.Now().After(m.Expiration)
}

// String returns a string representation of the message
func (m *Message) String() string {
    return fmt.Sprintf("Message{Type=%d, ID=%d, PayloadLen=%d}", m.Type, m.ID, len(m.Payload))
}