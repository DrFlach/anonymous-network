package transport

import (
	"sync"
	"time"
)

// backoffEntry tracks failed connection attempts to a host.
type backoffEntry struct {
	failures   int       // number of consecutive failures
	lastFail   time.Time // when the last failure occurred
	backoffEnd time.Time // don't retry before this time
}

// ConnectionBackoff implements exponential backoff for failed connection attempts.
// This prevents the node from spamming unreachable peers (e.g. private IPs
// from other subnets, or hosts behind impenetrable NAT).
type ConnectionBackoff struct {
	mu      sync.Mutex
	entries map[string]*backoffEntry

	// Configurable parameters
	initialBackoff time.Duration // first backoff duration (e.g. 30s)
	maxBackoff     time.Duration // maximum backoff cap (e.g. 10m)
	maxFailures    int           // after this many failures, stop trying entirely
	cleanupAge     time.Duration // remove entries older than this
}

// NewConnectionBackoff creates a new backoff tracker.
func NewConnectionBackoff() *ConnectionBackoff {
	cb := &ConnectionBackoff{
		entries:        make(map[string]*backoffEntry),
		initialBackoff: 30 * time.Second,
		maxBackoff:     10 * time.Minute,
		maxFailures:    10,
		cleanupAge:     1 * time.Hour,
	}
	return cb
}

// ShouldConnect returns true if we should attempt connecting to this host.
// Returns false if the host is currently in a backoff period.
func (cb *ConnectionBackoff) ShouldConnect(host string) bool {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	entry, exists := cb.entries[host]
	if !exists {
		return true
	}

	// If max failures exceeded, don't try at all
	if entry.failures >= cb.maxFailures {
		// But reset after cleanupAge so we eventually retry
		if time.Since(entry.lastFail) > cb.cleanupAge {
			delete(cb.entries, host)
			return true
		}
		return false
	}

	// Check if backoff period has expired
	return time.Now().After(entry.backoffEnd)
}

// RecordFailure records a failed connection attempt to a host.
// The next backoff duration doubles each time up to maxBackoff.
func (cb *ConnectionBackoff) RecordFailure(host string) {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	entry, exists := cb.entries[host]
	if !exists {
		entry = &backoffEntry{}
		cb.entries[host] = entry
	}

	entry.failures++
	entry.lastFail = time.Now()

	// Exponential backoff: initialBackoff * 2^(failures-1)
	backoff := cb.initialBackoff
	for i := 1; i < entry.failures; i++ {
		backoff *= 2
		if backoff > cb.maxBackoff {
			backoff = cb.maxBackoff
			break
		}
	}
	entry.backoffEnd = time.Now().Add(backoff)
}

// RecordSuccess clears the backoff state for a host (successful connection).
func (cb *ConnectionBackoff) RecordSuccess(host string) {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	delete(cb.entries, host)
}

// GetBackoffInfo returns the number of failures and time until next retry for a host.
// Returns (0, 0) if no backoff is active.
func (cb *ConnectionBackoff) GetBackoffInfo(host string) (failures int, retryIn time.Duration) {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	entry, exists := cb.entries[host]
	if !exists {
		return 0, 0
	}

	remaining := time.Until(entry.backoffEnd)
	if remaining < 0 {
		remaining = 0
	}
	return entry.failures, remaining
}

// Cleanup removes stale entries from the backoff map.
func (cb *ConnectionBackoff) Cleanup() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	cutoff := time.Now().Add(-cb.cleanupAge)
	for host, entry := range cb.entries {
		if entry.lastFail.Before(cutoff) {
			delete(cb.entries, host)
		}
	}
}

// Reset clears all backoff state.
func (cb *ConnectionBackoff) Reset() {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	cb.entries = make(map[string]*backoffEntry)
}
