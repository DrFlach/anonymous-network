package ntcp2

import (
	"testing"

	"network/pkg/crypto"
)

func TestAuthProofVerifySuccess(t *testing.T) {
	id, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}

	var iEphem, rEphem [32]byte
	iEphem[0] = 1
	rEphem[0] = 2

	proof := buildAuthProof(id, iEphem, rEphem)
	conn := &Connection{remoteHash: id.RouterHash}
	if err := conn.verifyRemoteProof(proof, iEphem, rEphem); err != nil {
		t.Fatalf("expected proof to verify, got error: %v", err)
	}
}

func TestAuthProofVerifyRejectsHashMismatch(t *testing.T) {
	id, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}

	var iEphem, rEphem [32]byte
	iEphem[0] = 7
	rEphem[0] = 8

	proof := buildAuthProof(id, iEphem, rEphem)
	conn := &Connection{}
	conn.remoteHash = id.RouterHash
	conn.remoteHash[0] ^= 0xFF

	if err := conn.verifyRemoteProof(proof, iEphem, rEphem); err == nil {
		t.Fatal("expected hash mismatch error, got nil")
	}
}
