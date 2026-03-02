package netdb

import (
	"crypto/sha256"
	"encoding/binary"
)

// BloomFilter is a simple bloom filter for efficient set membership testing.
// Used during peer exchange to avoid sending RouterInfos the remote already has.
type BloomFilter struct {
	bits    []byte
	numBits uint32
	numHash uint8
}

// NewBloomFilter creates a new bloom filter.
// size is the number of bytes (filter capacity = size * 8 bits).
// numHash is the number of hash functions (typically 3-5).
func NewBloomFilter(size int, numHash uint8) *BloomFilter {
	if size < 1 {
		size = 1
	}
	if numHash < 1 {
		numHash = 3
	}
	return &BloomFilter{
		bits:    make([]byte, size),
		numBits: uint32(size) * 8,
		numHash: numHash,
	}
}

// NewBloomFilterForCount creates a bloom filter sized for n expected items
// with approximately 1% false positive rate.
func NewBloomFilterForCount(n int) *BloomFilter {
	if n < 1 {
		n = 10
	}
	// Optimal: m = -n*ln(p) / (ln2)^2 ≈ n * 9.6 bits for p=0.01
	// We round up to bytes and use 4 hash functions (optimal k ≈ m/n * ln2 ≈ 6.6)
	bits := uint32(n) * 10 // ~10 bits per element for ~1% FPR
	size := (bits + 7) / 8 // round up to bytes
	if size > 8192 {
		size = 8192 // cap at 8KB
	}
	return NewBloomFilter(int(size), 4)
}

// Add adds a 32-byte hash to the bloom filter.
func (bf *BloomFilter) Add(hash [32]byte) {
	for i := uint8(0); i < bf.numHash; i++ {
		idx := bf.hashIndex(hash, i)
		bf.bits[idx/8] |= 1 << (idx % 8)
	}
}

// Contains checks if a 32-byte hash might be in the filter.
// False positives are possible; false negatives are not.
func (bf *BloomFilter) Contains(hash [32]byte) bool {
	for i := uint8(0); i < bf.numHash; i++ {
		idx := bf.hashIndex(hash, i)
		if bf.bits[idx/8]&(1<<(idx%8)) == 0 {
			return false
		}
	}
	return true
}

// Serialize encodes the bloom filter for network transmission.
// Format: [numBits:4][numHash:1][bits...]
func (bf *BloomFilter) Serialize() []byte {
	result := make([]byte, 5+len(bf.bits))
	binary.BigEndian.PutUint32(result[0:4], bf.numBits)
	result[4] = bf.numHash
	copy(result[5:], bf.bits)
	return result
}

// DeserializeBloomFilter parses a bloom filter from network bytes.
func DeserializeBloomFilter(data []byte) (*BloomFilter, error) {
	if len(data) < 6 {
		// Return empty filter (accepts everything)
		return NewBloomFilter(1, 3), nil
	}
	numBits := binary.BigEndian.Uint32(data[0:4])
	numHash := data[4]
	bitsLen := (numBits + 7) / 8
	if uint32(len(data)-5) < bitsLen {
		return NewBloomFilter(1, 3), nil
	}
	bits := make([]byte, bitsLen)
	copy(bits, data[5:5+bitsLen])
	return &BloomFilter{
		bits:    bits,
		numBits: numBits,
		numHash: numHash,
	}, nil
}

// hashIndex computes the bit index for a given hash and hash function index.
// Uses different 4-byte windows of SHA-256(hash || index) for each hash function.
func (bf *BloomFilter) hashIndex(hash [32]byte, idx uint8) uint32 {
	// Create a seed by appending the index byte
	var seed [33]byte
	copy(seed[:32], hash[:])
	seed[32] = idx
	h := sha256.Sum256(seed[:])
	return binary.BigEndian.Uint32(h[:4]) % bf.numBits
}
