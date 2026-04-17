package tunnel

import (
	"fmt"
	"math/rand"
	"sync"
	"time"

	"network/pkg/crypto"
	"network/pkg/netdb"
	"network/pkg/util"
)

// Pool manages a pool of inbound and outbound tunnels
type Pool struct {
	identity       *crypto.RouterIdentity
	netDB          *netdb.Store
	builder        *TunnelBuilder
	inbound        []*Tunnel
	outbound       []*Tunnel
	mu             sync.RWMutex
	targetInbound  int
	targetOutbound int
	tunnelLength   int
	tunnelLifetime time.Duration
	logger         *util.Logger
	stopChan       chan struct{}
	wg             sync.WaitGroup
	onBuildTunnel  func(tunnel *Tunnel, requests [][]byte) error // Callback to send build requests
	participants   *TunnelParticipantStore
}

// PoolConfig configures the tunnel pool
type PoolConfig struct {
	TargetInbound  int
	TargetOutbound int
	TunnelLength   int
	TunnelLifetime time.Duration
}

// DefaultPoolConfig returns sensible defaults
func DefaultPoolConfig() *PoolConfig {
	return &PoolConfig{
		TargetInbound:  3,
		TargetOutbound: 3,
		TunnelLength:   3,
		TunnelLifetime: 10 * time.Minute,
	}
}

// NewPool creates a new tunnel pool
func NewPool(identity *crypto.RouterIdentity, netDB *netdb.Store, config *PoolConfig) *Pool {
	return &Pool{
		identity:       identity,
		netDB:          netDB,
		builder:        NewTunnelBuilder(identity, config.TunnelLifetime),
		inbound:        make([]*Tunnel, 0),
		outbound:       make([]*Tunnel, 0),
		targetInbound:  config.TargetInbound,
		targetOutbound: config.TargetOutbound,
		tunnelLength:   config.TunnelLength,
		tunnelLifetime: config.TunnelLifetime,
		logger:         util.GetLogger(),
		stopChan:       make(chan struct{}),
		participants:   NewTunnelParticipantStore(),
	}
}

// SetBuildCallback sets the callback for sending tunnel build requests
func (p *Pool) SetBuildCallback(cb func(tunnel *Tunnel, requests [][]byte) error) {
	p.onBuildTunnel = cb
}

// GetParticipantStore returns the participant store
func (p *Pool) GetParticipantStore() *TunnelParticipantStore {
	return p.participants
}

// Start begins the tunnel pool maintenance loop
func (p *Pool) Start() {
	p.wg.Add(1)
	go p.maintenanceLoop()
	p.logger.Info("Tunnel pool started (target: %d inbound, %d outbound, length: %d)",
		p.targetInbound, p.targetOutbound, p.tunnelLength)
}

// Stop stops the tunnel pool
func (p *Pool) Stop() {
	close(p.stopChan)
	p.wg.Wait()
	p.logger.Info("Tunnel pool stopped")
}

// maintenanceLoop periodically checks and builds tunnels
func (p *Pool) maintenanceLoop() {
	defer p.wg.Done()

	// Initial build attempt after short delay
	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()

	for {
		select {
		case <-p.stopChan:
			return
		case <-timer.C:
			p.maintain()
			// Clean expired participations
			if cleaned := p.participants.CleanExpired(); cleaned > 0 {
				p.logger.Debug("Cleaned %d expired tunnel participations", cleaned)
			}
			timer.Reset(30 * time.Second)
		}
	}
}

// maintain checks tunnel counts and builds new tunnels as needed
func (p *Pool) maintain() {
	p.cleanExpired()

	p.mu.RLock()
	inCount := len(p.inbound)
	outCount := len(p.outbound)
	p.mu.RUnlock()

	p.logger.Debug("Tunnel pool status: %d/%d inbound, %d/%d outbound",
		inCount, p.targetInbound, outCount, p.targetOutbound)

	// Build inbound tunnels
	for i := inCount; i < p.targetInbound; i++ {
		if err := p.buildNewTunnel(Inbound); err != nil {
			p.logger.Error("Failed to build inbound tunnel: %v", err)
			break
		}
	}

	// Build outbound tunnels
	for i := outCount; i < p.targetOutbound; i++ {
		if err := p.buildNewTunnel(Outbound); err != nil {
			p.logger.Error("Failed to build outbound tunnel: %v", err)
			break
		}
	}
}

// cleanExpired removes expired tunnels from the pool
func (p *Pool) cleanExpired() {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.inbound = filterExpired(p.inbound)
	p.outbound = filterExpired(p.outbound)
}

func filterExpired(tunnels []*Tunnel) []*Tunnel {
	result := make([]*Tunnel, 0, len(tunnels))
	for _, t := range tunnels {
		if !t.IsExpired() {
			result = append(result, t)
		}
	}
	return result
}

// buildNewTunnel selects hops and builds a new tunnel
func (p *Pool) buildNewTunnel(direction Direction) error {
	// Select random routers from NetDB for hops
	routers := p.netDB.GetRandom(p.tunnelLength)
	if len(routers) < p.tunnelLength {
		// If not enough routers, use what we have (minimum 1 for zero-hop)
		if len(routers) == 0 {
			p.logger.Warn("No routers in NetDB, creating zero-hop tunnel")
			return p.createZeroHopTunnel(direction)
		}
	}

	// Extract router hashes and keys
	hopRouters := make([][32]byte, len(routers))
	peerKeys := make(map[[32]byte][32]byte)

	for i, ri := range routers {
		hopRouters[i] = ri.RouterHash
		peerKeys[ri.RouterHash] = ri.EncryptionKey
	}

	// Build the tunnel
	tunnel, buildRequests, err := p.builder.BuildTunnel(direction, hopRouters, peerKeys)
	if err != nil {
		return fmt.Errorf("failed to build tunnel: %w", err)
	}

	// Send build requests through the network
	if p.onBuildTunnel != nil {
		if err := p.onBuildTunnel(tunnel, buildRequests); err != nil {
			return fmt.Errorf("failed to send build requests: %w", err)
		}
	}

	// Mark tunnel as ready (in production, would wait for responses)
	tunnel.IsReady = true

	// Add to pool
	p.mu.Lock()
	if direction == Inbound {
		p.inbound = append(p.inbound, tunnel)
	} else {
		p.outbound = append(p.outbound, tunnel)
	}
	p.mu.Unlock()

	p.logger.Info("Built %s tunnel with %d hops (ID=%d)",
		directionString(direction), len(tunnel.Hops), tunnel.ID)

	return nil
}

// createZeroHopTunnel creates a local tunnel (no hops, for testing/bootstrap)
func (p *Pool) createZeroHopTunnel(direction Direction) error {
	tunnel := &Tunnel{
		ID:        GenerateTunnelID(),
		Direction: direction,
		Hops:      nil,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(p.tunnelLifetime),
		LayerKeys: nil,
		Gateway:   p.identity.RouterHash,
		Endpoint:  p.identity.RouterHash,
		IsReady:   true,
	}

	p.mu.Lock()
	if direction == Inbound {
		p.inbound = append(p.inbound, tunnel)
	} else {
		p.outbound = append(p.outbound, tunnel)
	}
	p.mu.Unlock()

	p.logger.Info("Created zero-hop %s tunnel (ID=%d)", directionString(direction), tunnel.ID)
	return nil
}

// GetOutboundTunnel returns a random ready outbound tunnel
func (p *Pool) GetOutboundTunnel() (*Tunnel, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	ready := make([]*Tunnel, 0)
	for _, t := range p.outbound {
		if t.IsReady && !t.IsExpired() {
			ready = append(ready, t)
		}
	}

	if len(ready) == 0 {
		return nil, fmt.Errorf("no outbound tunnels available")
	}

	return ready[rand.Intn(len(ready))], nil
}

// GetInboundTunnel returns a random ready inbound tunnel
func (p *Pool) GetInboundTunnel() (*Tunnel, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	ready := make([]*Tunnel, 0)
	for _, t := range p.inbound {
		if t.IsReady && !t.IsExpired() {
			ready = append(ready, t)
		}
	}

	if len(ready) == 0 {
		return nil, fmt.Errorf("no inbound tunnels available")
	}

	return ready[rand.Intn(len(ready))], nil
}

// GetAllOutbound returns all outbound tunnels
func (p *Pool) GetAllOutbound() []*Tunnel {
	p.mu.RLock()
	defer p.mu.RUnlock()

	result := make([]*Tunnel, len(p.outbound))
	copy(result, p.outbound)
	return result
}

// GetAllInbound returns all inbound tunnels
func (p *Pool) GetAllInbound() []*Tunnel {
	p.mu.RLock()
	defer p.mu.RUnlock()

	result := make([]*Tunnel, len(p.inbound))
	copy(result, p.inbound)
	return result
}

// Stats returns tunnel pool statistics
func (p *Pool) Stats() (inbound, outbound, participations int) {
	p.mu.RLock()
	inbound = len(p.inbound)
	outbound = len(p.outbound)
	p.mu.RUnlock()

	p.participants.mu.RLock()
	participations = len(p.participants.participants)
	p.participants.mu.RUnlock()

	return
}
