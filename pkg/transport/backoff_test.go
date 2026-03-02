package transport

import (
	"testing"
	"time"
)

func TestConnectionBackoff_Basic(t *testing.T) {
	cb := NewConnectionBackoff()
	cb.initialBackoff = 100 * time.Millisecond

	host := "192.168.1.1"

	if !cb.ShouldConnect(host) {
		t.Fatal("should allow first connection attempt")
	}

	cb.RecordFailure(host)

	if cb.ShouldConnect(host) {
		t.Fatal("should not allow connection during backoff")
	}

	time.Sleep(150 * time.Millisecond)

	if !cb.ShouldConnect(host) {
		t.Fatal("should allow retry after backoff expires")
	}
}

func TestConnectionBackoff_ExponentialGrowth(t *testing.T) {
	cb := NewConnectionBackoff()
	cb.initialBackoff = 10 * time.Millisecond

	host := "10.0.0.1"

	cb.RecordFailure(host)
	cb.RecordFailure(host)
	cb.RecordFailure(host)

	failures, retryIn := cb.GetBackoffInfo(host)
	if failures != 3 {
		t.Fatalf("expected 3 failures, got %d", failures)
	}
	if retryIn < 30*time.Millisecond {
		t.Fatalf("expected backoff >= 30ms, got %v", retryIn)
	}
}

func TestConnectionBackoff_SuccessClears(t *testing.T) {
	cb := NewConnectionBackoff()

	host := "8.8.8.8"

	cb.RecordFailure(host)
	cb.RecordFailure(host)

	if cb.ShouldConnect(host) {
		t.Fatal("should be in backoff")
	}

	cb.RecordSuccess(host)

	if !cb.ShouldConnect(host) {
		t.Fatal("should allow connection after success")
	}

	failures, _ := cb.GetBackoffInfo(host)
	if failures != 0 {
		t.Fatalf("expected 0 failures after success, got %d", failures)
	}
}

func TestConnectionBackoff_MaxFailures(t *testing.T) {
	cb := NewConnectionBackoff()
	cb.maxFailures = 3

	host := "172.16.0.1"

	for i := 0; i < 5; i++ {
		cb.RecordFailure(host)
	}

	if cb.ShouldConnect(host) {
		t.Fatal("should not attempt connection after max failures")
	}
}

func TestConnectionBackoff_Cleanup(t *testing.T) {
	cb := NewConnectionBackoff()
	cb.cleanupAge = 100 * time.Millisecond

	host := "192.168.5.5"
	cb.RecordFailure(host)

	time.Sleep(150 * time.Millisecond)
	cb.Cleanup()

	if !cb.ShouldConnect(host) {
		t.Fatal("should allow connection after cleanup")
	}
}
