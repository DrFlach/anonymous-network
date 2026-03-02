package netdb

import (
    "fmt"
    "sync"
    "time"
)

// Store manages the network database (RouterInfos)
type Store struct {
    routers map[[32]byte]*RouterInfo
    mu      sync.RWMutex
}

// NewStore creates a new NetDB store
func NewStore() *Store {
    return &Store{
        routers: make(map[[32]byte]*RouterInfo),
    }
}

// Add adds or updates a RouterInfo in the store
func (s *Store) Add(ri *RouterInfo) error {
    if !ri.Verify() {
        return fmt.Errorf("invalid signature on RouterInfo")
    }
    
    if ri.IsExpired() {
        return fmt.Errorf("RouterInfo is expired")
    }
    
    s.mu.Lock()
    defer s.mu.Unlock()
    
    s.routers[ri.RouterHash] = ri
    return nil
}

// Get retrieves a RouterInfo by hash
func (s *Store) Get(hash [32]byte) (*RouterInfo, error) {
    s.mu.RLock()
    defer s.mu.RUnlock()
    
    ri, exists := s.routers[hash]
    if !exists {
        return nil, fmt.Errorf("RouterInfo not found")
    }
    
    if ri.IsExpired() {
        return nil, fmt.Errorf("RouterInfo expired")
    }
    
    return ri, nil
}

// GetAll returns all RouterInfos
func (s *Store) GetAll() []*RouterInfo {
    s.mu.RLock()
    defer s.mu.RUnlock()
    
    result := make([]*RouterInfo, 0, len(s.routers))
    for _, ri := range s.routers {
        if !ri.IsExpired() {
            result = append(result, ri)
        }
    }
    
    return result
}

// GetRandom returns n random non-expired RouterInfos
func (s *Store) GetRandom(n int) []*RouterInfo {
    all := s.GetAll()
    
    if len(all) <= n {
        return all
    }
    
    // Simple random selection (not cryptographically secure, good enough for MVP)
    result := make([]*RouterInfo, n)
    perm := make([]int, len(all))
    for i := range perm {
        perm[i] = i
    }
    
    // Fisher-Yates shuffle first n elements
    for i := 0; i < n; i++ {
        j := i + int(time.Now().UnixNano()%(int64(len(all)-i)))
        perm[i], perm[j] = perm[j], perm[i]
        result[i] = all[perm[i]]
    }
    
    return result
}

// Remove removes a RouterInfo from the store
func (s *Store) Remove(hash [32]byte) {
    s.mu.Lock()
    defer s.mu.Unlock()
    
    delete(s.routers, hash)
}

// CleanExpired removes expired RouterInfos
func (s *Store) CleanExpired() int {
    s.mu.Lock()
    defer s.mu.Unlock()
    
    count := 0
    for hash, ri := range s.routers {
        if ri.IsExpired() {
            delete(s.routers, hash)
            count++
        }
    }
    
    return count
}

// Count returns the number of RouterInfos in the store
func (s *Store) Count() int {
    s.mu.RLock()
    defer s.mu.RUnlock()
    
    return len(s.routers)
}

// GetRandomFiltered returns up to n random non-expired RouterInfos
// that are NOT present in the given bloom filter.
// If bloom is nil, behaves like GetRandom.
func (s *Store) GetRandomFiltered(n int, bloom *BloomFilter) []*RouterInfo {
    all := s.GetAll()

    // Filter out entries the remote already has
    var candidates []*RouterInfo
    for _, ri := range all {
        if bloom != nil && bloom.Contains(ri.RouterHash) {
            continue
        }
        candidates = append(candidates, ri)
    }

    if len(candidates) <= n {
        return candidates
    }

    // Fisher-Yates shuffle first n
    for i := 0; i < n; i++ {
        j := i + int(time.Now().UnixNano()%(int64(len(candidates)-i)))
        candidates[i], candidates[j] = candidates[j], candidates[i]
    }

    return candidates[:n]
}

// BuildBloomFilter creates a bloom filter containing all current RouterHashes.
// This is sent with PeerExchangeReq so the remote knows what we already have.
func (s *Store) BuildBloomFilter() *BloomFilter {
    s.mu.RLock()
    defer s.mu.RUnlock()

    bf := NewBloomFilterForCount(len(s.routers))
    for hash := range s.routers {
        bf.Add(hash)
    }
    return bf
}

// GetAllHashes returns all stored router hashes
func (s *Store) GetAllHashes() [][32]byte {
    s.mu.RLock()
    defer s.mu.RUnlock()

    hashes := make([][32]byte, 0, len(s.routers))
    for h := range s.routers {
        hashes = append(hashes, h)
    }
    return hashes
}

// MergeRouterInfos adds multiple RouterInfos from a peer exchange.
// Returns the number of new entries added.
func (s *Store) MergeRouterInfos(infos []*RouterInfo) int {
    added := 0
    for _, ri := range infos {
        if ri == nil {
            continue
        }
        if !ri.Verify() {
            continue
        }
        if ri.IsExpired() {
            continue
        }
        s.mu.Lock()
        if _, exists := s.routers[ri.RouterHash]; !exists {
            s.routers[ri.RouterHash] = ri
            added++
        } else {
            // Update if newer
            existing := s.routers[ri.RouterHash]
            if ri.Timestamp.After(existing.Timestamp) {
                s.routers[ri.RouterHash] = ri
            }
        }
        s.mu.Unlock()
    }
    return added
}