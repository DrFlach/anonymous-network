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