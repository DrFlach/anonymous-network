package netdb

import (
    "bytes"
    "crypto/ed25519"
    "encoding/binary"
    "fmt"
    "sort"
    "time"
)

// RouterAddress represents a network address for reaching a router
type RouterAddress struct {
    Host string
    Port int
}

// RouterInfo contains all information about a router
type RouterInfo struct {
    RouterHash       [32]byte
    SigningPublicKey ed25519.PublicKey
    EncryptionKey    [32]byte
    Addresses        []RouterAddress
    Timestamp        time.Time
    Capabilities     map[string]bool // "floodfill", "reachable", etc.
    Signature        []byte
}

// NewRouterInfo creates a new RouterInfo
func NewRouterInfo(routerHash [32]byte, signingKey ed25519.PublicKey, encKey [32]byte) *RouterInfo {
    return &RouterInfo{
        RouterHash:       routerHash,
        SigningPublicKey: signingKey,
        EncryptionKey:    encKey,
        Addresses:        []RouterAddress{},
        Timestamp:        time.Now(),
        Capabilities:     make(map[string]bool),
    }
}

// AddAddress adds a network address to the router info
func (ri *RouterInfo) AddAddress(host string, port int) {
    ri.Addresses = append(ri.Addresses, RouterAddress{
        Host: host,
        Port: port,
    })
}

// SetCapability sets a router capability
func (ri *RouterInfo) SetCapability(cap string, enabled bool) {
    ri.Capabilities[cap] = enabled
}

// IsFloodfill returns true if router is a floodfill node
func (ri *RouterInfo) IsFloodfill() bool {
    return ri.Capabilities["floodfill"]
}

// Serialize converts RouterInfo to bytes for signing/transmission
func (ri *RouterInfo) Serialize() []byte {
    buf := new(bytes.Buffer)
    
    // Write router hash
    buf.Write(ri.RouterHash[:])
    
    // Write signing public key
    buf.Write(ri.SigningPublicKey)
    
    // Write encryption key
    buf.Write(ri.EncryptionKey[:])
    
    // Write number of addresses
    binary.Write(buf, binary.BigEndian, uint16(len(ri.Addresses)))
    
    // Write addresses
    for _, addr := range ri.Addresses {
        hostBytes := []byte(addr.Host)
        binary.Write(buf, binary.BigEndian, uint16(len(hostBytes)))
        buf.Write(hostBytes)
        binary.Write(buf, binary.BigEndian, uint16(addr.Port))
    }
    
    // Write timestamp
    binary.Write(buf, binary.BigEndian, ri.Timestamp.Unix())
    
    // Write capabilities (sorted keys for deterministic serialization)
    binary.Write(buf, binary.BigEndian, uint16(len(ri.Capabilities)))
    capKeys := make([]string, 0, len(ri.Capabilities))
    for cap := range ri.Capabilities {
        capKeys = append(capKeys, cap)
    }
    sort.Strings(capKeys)
    for _, cap := range capKeys {
        enabled := ri.Capabilities[cap]
        capBytes := []byte(cap)
        binary.Write(buf, binary.BigEndian, uint16(len(capBytes)))
        buf.Write(capBytes)
        if enabled {
            buf.WriteByte(1)
        } else {
            buf.WriteByte(0)
        }
    }
    
    return buf.Bytes()
}

// Sign signs the RouterInfo with the provided private key
func (ri *RouterInfo) Sign(privateKey ed25519.PrivateKey) {
    data := ri.Serialize()
    ri.Signature = ed25519.Sign(privateKey, data)
}

// Verify verifies the RouterInfo signature
func (ri *RouterInfo) Verify() bool {
    data := ri.Serialize()
    return ed25519.Verify(ri.SigningPublicKey, data, ri.Signature)
}

// IsExpired checks if RouterInfo is too old (>24 hours)
func (ri *RouterInfo) IsExpired() bool {
    return time.Since(ri.Timestamp) > 24*time.Hour
}

// GetPrimaryAddress returns the first address or empty if none
func (ri *RouterInfo) GetPrimaryAddress() (string, error) {
    if len(ri.Addresses) == 0 {
        return "", fmt.Errorf("no addresses available")
    }
    return fmt.Sprintf("%s:%d", ri.Addresses[0].Host, ri.Addresses[0].Port), nil
}