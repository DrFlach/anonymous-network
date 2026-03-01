package proxy

import (
	"crypto/tls"
	"fmt"
	"net"
	"sync"
	"time"

	"network/pkg/tunnel"
	"network/pkg/util"
)

// Outproxy handles connections to the clearnet (regular internet)
// It acts as the exit point of the anonymous tunnel
type Outproxy struct {
	enabled      bool
	logger       *util.Logger
	dialer       *net.Dialer
	tlsConfig    *tls.Config
	mu           sync.RWMutex
	activeConns  int64
	blockedHosts map[string]bool // Simple blocklist
	dnsResolver  *SecureDNSResolver
}

// OutproxyConfig configures the outproxy
type OutproxyConfig struct {
	Enabled       bool
	ConnTimeout   time.Duration
	BlockedHosts  []string
	DNSServers    []string // DNS-over-HTTPS servers
}

// DefaultOutproxyConfig returns sensible defaults
func DefaultOutproxyConfig() *OutproxyConfig {
	return &OutproxyConfig{
		Enabled:     true,
		ConnTimeout: 30 * time.Second,
		BlockedHosts: []string{},
		DNSServers: []string{
			"https://1.1.1.1/dns-query",       // Cloudflare
			"https://dns.google/dns-query",     // Google
			"https://dns.quad9.net/dns-query",  // Quad9
		},
	}
}

// NewOutproxy creates a new outproxy
func NewOutproxy(config *OutproxyConfig) *Outproxy {
	blocked := make(map[string]bool)
	for _, h := range config.BlockedHosts {
		blocked[h] = true
	}

	resolver := NewSecureDNSResolver(config.DNSServers)

	return &Outproxy{
		enabled: config.Enabled,
		logger:  util.GetLogger(),
		dialer: &net.Dialer{
			Timeout:   config.ConnTimeout,
			KeepAlive: 30 * time.Second,
		},
		tlsConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
		blockedHosts: blocked,
		dnsResolver:  resolver,
	}
}

// Connect creates a connection to the target address through the anonymous network
func (o *Outproxy) Connect(targetAddr string, outTunnel *tunnel.Tunnel) (net.Conn, error) {
	if !o.enabled {
		return nil, fmt.Errorf("outproxy is disabled")
	}

	// Parse host and port
	host, port, err := net.SplitHostPort(targetAddr)
	if err != nil {
		return nil, fmt.Errorf("invalid target address: %w", err)
	}

	// Check blocklist
	if o.isBlocked(host) {
		return nil, fmt.Errorf("host is blocked: %s", host)
	}

	// Resolve DNS securely (through DoH)
	resolvedAddr, err := o.resolveSecure(host, port)
	if err != nil {
		return nil, fmt.Errorf("DNS resolution failed: %w", err)
	}

	if resolvedAddr != targetAddr {
		o.logger.Info("[DNS] %s → %s (resolved via DoH — no DNS leak)", host, resolvedAddr)
	}
	o.logger.Debug("Outproxy connecting to %s (resolved: %s)", targetAddr, resolvedAddr)

	// If we have a tunnel, the data was already encrypted through the tunnel
	// The outproxy is the exit node that makes the actual connection
	conn, err := o.dialer.Dial("tcp", resolvedAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to %s: %w", resolvedAddr, err)
	}

	o.mu.Lock()
	o.activeConns++
	o.mu.Unlock()

	// Wrap connection to track when it's closed
	return &trackedConn{
		Conn:     conn,
		outproxy: o,
	}, nil
}

// resolveSecure resolves a hostname securely using DNS-over-HTTPS
func (o *Outproxy) resolveSecure(host, port string) (string, error) {
	// If it's already an IP, no need to resolve
	if ip := net.ParseIP(host); ip != nil {
		return net.JoinHostPort(host, port), nil
	}

	// Use secure DNS resolver
	ip, err := o.dnsResolver.Resolve(host)
	if err != nil {
		return "", fmt.Errorf("secure DNS resolution failed for %s: %w", host, err)
	}

	return net.JoinHostPort(ip, port), nil
}

// isBlocked checks if a host is in the blocklist
func (o *Outproxy) isBlocked(host string) bool {
	o.mu.RLock()
	defer o.mu.RUnlock()
	return o.blockedHosts[host]
}

// AddBlockedHost adds a host to the blocklist
func (o *Outproxy) AddBlockedHost(host string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.blockedHosts[host] = true
}

// ActiveConnections returns the number of active outproxy connections
func (o *Outproxy) ActiveConnections() int64 {
	o.mu.RLock()
	defer o.mu.RUnlock()
	return o.activeConns
}

// trackedConn wraps a net.Conn to track active connection count
type trackedConn struct {
	net.Conn
	outproxy *Outproxy
	closed   bool
	mu       sync.Mutex
}

func (tc *trackedConn) Close() error {
	tc.mu.Lock()
	defer tc.mu.Unlock()

	if tc.closed {
		return nil
	}

	tc.closed = true
	tc.outproxy.mu.Lock()
	tc.outproxy.activeConns--
	tc.outproxy.mu.Unlock()

	return tc.Conn.Close()
}
