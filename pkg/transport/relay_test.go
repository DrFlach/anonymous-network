package transport

import (
	"testing"
	"time"
)

func TestRelayManager_AddAndGetCircuit(t *testing.T) {
	rm := NewRelayManager()

	var hashA, hashB [32]byte
	hashA[0] = 1
	hashB[0] = 2

	// No circuit initially
	if c := rm.GetCircuit(hashA, hashB); c != nil {
		t.Fatal("expected no circuit")
	}

	// Add circuit
	rm.AddCircuit(hashA, hashB)

	// Should find in both directions
	c := rm.GetCircuit(hashA, hashB)
	if c == nil {
		t.Fatal("expected circuit A→B")
	}

	c2 := rm.GetCircuit(hashB, hashA)
	if c2 == nil {
		t.Fatal("expected circuit B→A")
	}

	if rm.CircuitCount() != 1 {
		t.Fatalf("expected 1 circuit, got %d", rm.CircuitCount())
	}
}

func TestRelayManager_RemoveCircuit(t *testing.T) {
	rm := NewRelayManager()

	var hashA, hashB, hashC [32]byte
	hashA[0] = 1
	hashB[0] = 2
	hashC[0] = 3

	rm.AddCircuit(hashA, hashB)
	rm.AddCircuit(hashA, hashC)

	if rm.CircuitCount() != 2 {
		t.Fatalf("expected 2 circuits, got %d", rm.CircuitCount())
	}

	rm.RemoveCircuit(hashA, hashB)

	if rm.CircuitCount() != 1 {
		t.Fatalf("expected 1 circuit after remove, got %d", rm.CircuitCount())
	}

	// A→B should be gone
	if c := rm.GetCircuit(hashA, hashB); c != nil {
		t.Fatal("circuit A→B should be removed")
	}

	// A→C should remain
	if c := rm.GetCircuit(hashA, hashC); c == nil {
		t.Fatal("circuit A→C should still exist")
	}
}

func TestRelayManager_RemoveAllForPeer(t *testing.T) {
	rm := NewRelayManager()

	var hashA, hashB, hashC [32]byte
	hashA[0] = 1
	hashB[0] = 2
	hashC[0] = 3

	rm.AddCircuit(hashA, hashB)
	rm.AddCircuit(hashA, hashC)
	rm.AddCircuit(hashB, hashC)

	if rm.CircuitCount() != 3 {
		t.Fatalf("expected 3 circuits, got %d", rm.CircuitCount())
	}

	// Remove all for A
	rm.RemoveAllForPeer(hashA)

	if rm.CircuitCount() != 1 {
		t.Fatalf("expected 1 circuit after removing A, got %d", rm.CircuitCount())
	}

	// Only B→C should remain
	if c := rm.GetCircuit(hashB, hashC); c == nil {
		t.Fatal("B→C should still exist")
	}
}

func TestRelayManager_CleanupStale(t *testing.T) {
	rm := NewRelayManager()

	var hashA, hashB [32]byte
	hashA[0] = 1
	hashB[0] = 2

	rm.AddCircuit(hashA, hashB)

	// Make it stale
	rm.mu.Lock()
	rm.circuits[hashA][hashB].LastUsed = time.Now().Add(-15 * time.Minute)
	rm.circuits[hashB][hashA].LastUsed = time.Now().Add(-15 * time.Minute)
	rm.mu.Unlock()

	rm.CleanupStale()

	if rm.CircuitCount() != 0 {
		t.Fatalf("expected 0 circuits after cleanup, got %d", rm.CircuitCount())
	}
}

func TestRelayCircuitSerialization(t *testing.T) {
	// Test RelayCircuitOpen
	var destHash [32]byte
	destHash[0] = 0xAA
	destHash[31] = 0xBB

	data := SerializeRelayCircuitOpen(destHash)
	parsed, err := DeserializeRelayCircuitOpen(data)
	if err != nil {
		t.Fatalf("DeserializeRelayCircuitOpen: %v", err)
	}
	if parsed != destHash {
		t.Fatal("RelayCircuitOpen: hash mismatch")
	}

	// Test RelayCircuitReady
	var peerHash [32]byte
	peerHash[0] = 0xCC
	extAddr := "31.183.137.59:7656"

	readyData := SerializeRelayCircuitReady(peerHash, extAddr)
	parsedHash, parsedAddr, err := DeserializeRelayCircuitReady(readyData)
	if err != nil {
		t.Fatalf("DeserializeRelayCircuitReady: %v", err)
	}
	if parsedHash != peerHash {
		t.Fatal("RelayCircuitReady: hash mismatch")
	}
	if parsedAddr != extAddr {
		t.Fatalf("RelayCircuitReady: addr mismatch: got %s", parsedAddr)
	}

	// Test RelayCircuitData
	var srcHash [32]byte
	srcHash[0] = 0xDD
	innerData := []byte("encrypted tunnel data payload")

	circuitData := SerializeRelayCircuitData(srcHash, innerData)
	parsedSrc, parsedInner, err := DeserializeRelayCircuitData(circuitData)
	if err != nil {
		t.Fatalf("DeserializeRelayCircuitData: %v", err)
	}
	if parsedSrc != srcHash {
		t.Fatal("RelayCircuitData: hash mismatch")
	}
	if string(parsedInner) != string(innerData) {
		t.Fatal("RelayCircuitData: data mismatch")
	}
}
