package garlic

import (
	"crypto/ed25519"
	"fmt"
	"sync"
	"time"

	"network/pkg/tunnel"
)

// LeaseSet represents a set of tunnel entry points for a destination
// This allows others to reach a destination through its inbound tunnels
type LeaseSet struct {
	Destination     [32]byte           // Destination hash (SHA-256 of signing key)
	EncryptionKey   [32]byte           // Public encryption key for garlic messages
	SigningKey      ed25519.PublicKey   // Public signing key for verification
	Leases          []*Lease           // Active tunnel entry points
	Expiration      time.Time
	Signature       []byte             // Ed25519 signature over the lease set
}

// Lease represents a single tunnel entry point
type Lease struct {
	Gateway     [32]byte        // Router hash of tunnel gateway
	TunnelID    tunnel.TunnelID // Tunnel ID at the gateway
	Expiration  time.Time       // When this lease expires
}

// NewLeaseSet creates a new lease set
func NewLeaseSet(destination [32]byte, encKey [32]byte, sigKey ed25519.PublicKey) *LeaseSet {
	return &LeaseSet{
		Destination:   destination,
		EncryptionKey: encKey,
		SigningKey:    sigKey,
		Leases:        make([]*Lease, 0),
		Expiration:    time.Now().Add(10 * time.Minute),
	}
}

// AddLease adds a tunnel lease
func (ls *LeaseSet) AddLease(gateway [32]byte, tunnelID tunnel.TunnelID, expiration time.Time) {
	ls.Leases = append(ls.Leases, &Lease{
		Gateway:    gateway,
		TunnelID:   tunnelID,
		Expiration: expiration,
	})
}

// GetActiveLease returns a non-expired lease
func (ls *LeaseSet) GetActiveLease() (*Lease, error) {
	now := time.Now()
	for _, l := range ls.Leases {
		if now.Before(l.Expiration) {
			return l, nil
		}
	}
	return nil, fmt.Errorf("no active leases")
}

// IsExpired returns true if the lease set is expired
func (ls *LeaseSet) IsExpired() bool {
	return time.Now().After(ls.Expiration)
}

// Sign signs the lease set with the given private key
func (ls *LeaseSet) Sign(privateKey ed25519.PrivateKey) {
	data := ls.serializeForSigning()
	ls.Signature = ed25519.Sign(privateKey, data)
}

// Verify verifies the lease set signature
func (ls *LeaseSet) Verify() bool {
	data := ls.serializeForSigning()
	return ed25519.Verify(ls.SigningKey, data, ls.Signature)
}

func (ls *LeaseSet) serializeForSigning() []byte {
	// Serialize all fields except signature
	var data []byte
	data = append(data, ls.Destination[:]...)
	data = append(data, ls.EncryptionKey[:]...)
	data = append(data, []byte(ls.SigningKey)...)
	for _, l := range ls.Leases {
		data = append(data, l.Gateway[:]...)
		// Tunnel ID as 4 bytes
		tid := uint32(l.TunnelID)
		data = append(data, byte(tid>>24), byte(tid>>16), byte(tid>>8), byte(tid))
	}
	return data
}

// LeaseSetStore stores lease sets for destinations
type LeaseSetStore struct {
	leaseSets map[[32]byte]*LeaseSet
	mu        sync.RWMutex
}

// NewLeaseSetStore creates a new lease set store
func NewLeaseSetStore() *LeaseSetStore {
	return &LeaseSetStore{
		leaseSets: make(map[[32]byte]*LeaseSet),
	}
}

// Store stores a lease set
func (s *LeaseSetStore) Store(ls *LeaseSet) error {
	if !ls.Verify() {
		return fmt.Errorf("invalid lease set signature")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.leaseSets[ls.Destination] = ls
	return nil
}

// Get retrieves a lease set by destination hash
func (s *LeaseSetStore) Get(destination [32]byte) (*LeaseSet, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	ls, ok := s.leaseSets[destination]
	if !ok {
		return nil, fmt.Errorf("lease set not found for destination")
	}

	if ls.IsExpired() {
		return nil, fmt.Errorf("lease set expired")
	}

	return ls, nil
}

// Remove removes a lease set
func (s *LeaseSetStore) Remove(destination [32]byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.leaseSets, destination)
}

// CleanExpired removes expired lease sets
func (s *LeaseSetStore) CleanExpired() int {
	s.mu.Lock()
	defer s.mu.Unlock()

	count := 0
	for dest, ls := range s.leaseSets {
		if ls.IsExpired() {
			delete(s.leaseSets, dest)
			count++
		}
	}
	return count
}
