package netdb

import (
	"testing"
	"time"
)

func TestBloomFilter_BasicOperations(t *testing.T) {
	bf := NewBloomFilterForCount(100)

	var hash1, hash2, hash3 [32]byte
	hash1[0] = 1
	hash2[0] = 2
	hash3[0] = 3

	// Before adding, should not contain
	if bf.Contains(hash1) {
		t.Error("Empty bloom filter should not contain hash1")
	}

	// Add hash1 and hash2
	bf.Add(hash1)
	bf.Add(hash2)

	// Should contain added hashes
	if !bf.Contains(hash1) {
		t.Error("Bloom filter should contain hash1 after Add")
	}
	if !bf.Contains(hash2) {
		t.Error("Bloom filter should contain hash2 after Add")
	}

	// hash3 was never added — may false-positive but unlikely with only 2 items
	// We don't assert !Contains(hash3) since false positives are allowed,
	// but with 100-capacity filter and 2 items, probability is ~0.00004%
}

func TestBloomFilter_SerializeDeserialize(t *testing.T) {
	bf := NewBloomFilterForCount(50)

	var hashes [10][32]byte
	for i := range hashes {
		hashes[i][0] = byte(i * 17)
		hashes[i][1] = byte(i * 31)
		bf.Add(hashes[i])
	}

	// Serialize
	data := bf.Serialize()
	if len(data) < 6 {
		t.Fatalf("Serialized bloom filter too short: %d bytes", len(data))
	}

	// Deserialize
	bf2, err := DeserializeBloomFilter(data)
	if err != nil {
		t.Fatal(err)
	}

	// Check all added hashes are present in deserialized filter
	for i, h := range hashes {
		if !bf2.Contains(h) {
			t.Errorf("Deserialized filter missing hash %d", i)
		}
	}
}

func TestBloomFilter_FalsePositiveRate(t *testing.T) {
	n := 1000
	bf := NewBloomFilterForCount(n)

	// Add n items
	for i := 0; i < n; i++ {
		var h [32]byte
		h[0] = byte(i)
		h[1] = byte(i >> 8)
		h[2] = byte(i >> 16)
		h[3] = 0xAA // marker for "added" set
		bf.Add(h)
	}

	// Test n items NOT in the filter
	falsePositives := 0
	testN := 10000
	for i := 0; i < testN; i++ {
		var h [32]byte
		h[0] = byte(i)
		h[1] = byte(i >> 8)
		h[2] = byte(i >> 16)
		h[3] = 0xBB // different marker = different set
		if bf.Contains(h) {
			falsePositives++
		}
	}

	fpRate := float64(falsePositives) / float64(testN)
	t.Logf("False positive rate: %.4f%% (%d / %d)", fpRate*100, falsePositives, testN)

	// Should be well under 5% for our parameters
	if fpRate > 0.05 {
		t.Errorf("False positive rate too high: %.2f%% (expected < 5%%)", fpRate*100)
	}
}

func TestStore_BuildBloomFilter(t *testing.T) {
	store := NewStore()

	// Create and add some RouterInfos
	var hashes [][32]byte
	for i := 0; i < 5; i++ {
		ri := &RouterInfo{
			Capabilities: make(map[string]bool),
			Timestamp:    time.Now(),
		}
		ri.RouterHash[0] = byte(i * 41)
		ri.RouterHash[1] = byte(i * 67)
		// Can't call store.Add() because it verifies signatures,
		// so insert directly for testing
		store.mu.Lock()
		store.routers[ri.RouterHash] = ri
		store.mu.Unlock()
		hashes = append(hashes, ri.RouterHash)
	}

	bloom := store.BuildBloomFilter()

	for i, h := range hashes {
		if !bloom.Contains(h) {
			t.Errorf("Bloom filter should contain stored hash %d", i)
		}
	}
}

func TestStore_GetRandomFiltered(t *testing.T) {
	store := NewStore()

	// Insert 10 RouterInfos directly (with valid timestamp so they aren't expired)
	var allHashes [][32]byte
	for i := 0; i < 10; i++ {
		ri := &RouterInfo{
			Capabilities: make(map[string]bool),
			Timestamp:    time.Now(),
		}
		ri.RouterHash[0] = byte(i)
		store.mu.Lock()
		store.routers[ri.RouterHash] = ri
		store.mu.Unlock()
		allHashes = append(allHashes, ri.RouterHash)
	}

	// Build a bloom filter with the first 5 hashes
	bloom := NewBloomFilterForCount(10)
	for i := 0; i < 5; i++ {
		bloom.Add(allHashes[i])
	}

	// GetRandomFiltered should return only items NOT in bloom
	result := store.GetRandomFiltered(20, bloom)

	for _, ri := range result {
		if bloom.Contains(ri.RouterHash) {
			t.Errorf("GetRandomFiltered returned hash that IS in bloom: %x", ri.RouterHash[:4])
		}
	}

	// Should get approximately 5 results (those not in bloom)
	if len(result) < 3 || len(result) > 7 {
		t.Errorf("Expected ~5 results, got %d", len(result))
	}
}

func TestSerializeDeserializeRouterInfoBatch(t *testing.T) {
	// Create a few simple RouterInfos with valid structure
	var infos []*RouterInfo
	for i := 0; i < 3; i++ {
		ri := NewRouterInfo([32]byte{byte(i)}, make([]byte, 32), [32]byte{byte(i + 100)})
		ri.AddAddress("10.0.0.1", 7656+i)
		ri.SetCapability("reachable", true)
		// We won't sign them (no private key in test), so deserialization
		// will skip them due to Verify(). This tests the serialization format.
		infos = append(infos, ri)
	}

	data := SerializeRouterInfoBatch(infos)
	if len(data) < 10 {
		t.Fatalf("Batch data too short: %d bytes", len(data))
	}

	// Deserialize — entries won't pass Verify() since they aren't signed,
	// so result will be empty. This just tests that parsing doesn't crash.
	result, err := DeserializeRouterInfoBatch(data)
	if err != nil {
		t.Fatalf("DeserializeRouterInfoBatch error: %v", err)
	}
	t.Logf("Deserialized %d valid RouterInfos from batch (unsigned entries skipped)", len(result))
}
