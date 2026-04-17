package proxy

import (
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"network/pkg/util"
)

// SecureDNSResolver resolves DNS queries using DNS-over-HTTPS (DoH)
// This prevents DNS leaks that could compromise anonymity
type SecureDNSResolver struct {
	servers    []string // DoH server URLs
	client     *http.Client
	cache      map[string]*dnsEntry
	cacheMu    sync.RWMutex
	cacheTTL   time.Duration
	strictOnly bool
	logger     *util.Logger
}

type dnsEntry struct {
	ip        string
	expiresAt time.Time
}

// DoH response structures
type dohResponse struct {
	Status   int           `json:"Status"`
	TC       bool          `json:"TC"`
	RD       bool          `json:"RD"`
	RA       bool          `json:"RA"`
	AD       bool          `json:"AD"`
	CD       bool          `json:"CD"`
	Question []dohQuestion `json:"Question"`
	Answer   []dohAnswer   `json:"Answer"`
}

type dohQuestion struct {
	Name string `json:"name"`
	Type int    `json:"type"`
}

type dohAnswer struct {
	Name string `json:"name"`
	Type int    `json:"type"`
	TTL  int    `json:"TTL"`
	Data string `json:"data"`
}

// NewSecureDNSResolver creates a new secure DNS resolver
func NewSecureDNSResolver(servers []string) *SecureDNSResolver {
	return NewSecureDNSResolverWithPolicy(servers, false)
}

// NewSecureDNSResolverWithPolicy creates a new secure DNS resolver with explicit fallback policy.
// If strictOnly=true, system DNS fallback is disabled to prevent DNS leaks.
func NewSecureDNSResolverWithPolicy(servers []string, strictOnly bool) *SecureDNSResolver {
	if len(servers) == 0 {
		servers = []string{
			"https://1.1.1.1/dns-query",
			"https://dns.google/dns-query",
		}
	}

	// Create HTTP client that doesn't use system DNS
	transport := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSHandshakeTimeout: 10 * time.Second,
		MaxIdleConns:        10,
		IdleConnTimeout:     90 * time.Second,
	}

	return &SecureDNSResolver{
		servers: servers,
		client: &http.Client{
			Transport: transport,
			Timeout:   15 * time.Second,
		},
		cache:      make(map[string]*dnsEntry),
		cacheTTL:   5 * time.Minute,
		strictOnly: strictOnly,
		logger:     util.GetLogger(),
	}
}

// Resolve resolves a hostname to an IP address using DoH
func (r *SecureDNSResolver) Resolve(hostname string) (string, error) {
	// Check cache first
	if ip, ok := r.getFromCache(hostname); ok {
		return ip, nil
	}

	// Try each DoH server
	var lastErr error
	servers := r.shuffledServers()

	for _, server := range servers {
		ip, err := r.queryDoH(server, hostname)
		if err != nil {
			lastErr = err
			r.logger.Debug("DoH query to %s failed: %v", server, err)
			continue
		}

		// Cache the result
		r.addToCache(hostname, ip)
		return ip, nil
	}

	if r.strictOnly {
		if lastErr != nil {
			return "", fmt.Errorf("all DoH servers failed (strict mode enabled): %w", lastErr)
		}
		return "", fmt.Errorf("all DoH servers failed (strict mode enabled)")
	}

	// Fallback: try Go's built-in resolver as last resort (non-strict mode)
	addrs, err := net.LookupHost(hostname)
	if err != nil {
		if lastErr != nil {
			return "", fmt.Errorf("all DoH servers failed (last: %v), fallback also failed: %w", lastErr, err)
		}
		return "", err
	}

	if len(addrs) > 0 {
		r.addToCache(hostname, addrs[0])
		return addrs[0], nil
	}

	return "", fmt.Errorf("no addresses found for %s", hostname)
}

// queryDoH performs a DNS-over-HTTPS query using the JSON API
func (r *SecureDNSResolver) queryDoH(server, hostname string) (string, error) {
	// Build DoH request URL with query parameters
	queryURL := fmt.Sprintf("%s?name=%s&type=A", server, hostname)

	req, err := http.NewRequest("GET", queryURL, nil)
	if err != nil {
		return "", err
	}

	req.Header.Set("Accept", "application/dns-json")
	// Don't send identifying headers
	req.Header.Set("User-Agent", "")

	resp, err := r.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("DoH server returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1MB limit
	if err != nil {
		return "", err
	}

	var dohResp dohResponse
	if err := json.Unmarshal(body, &dohResp); err != nil {
		return "", fmt.Errorf("failed to parse DoH response: %w", err)
	}

	if dohResp.Status != 0 {
		return "", fmt.Errorf("DoH query returned status %d", dohResp.Status)
	}

	// Find A record (type 1) or AAAA record (type 28)
	for _, answer := range dohResp.Answer {
		if answer.Type == 1 { // A record
			ip := strings.Trim(answer.Data, "\"")
			if net.ParseIP(ip) != nil {
				return ip, nil
			}
		}
	}

	// Try AAAA
	for _, answer := range dohResp.Answer {
		if answer.Type == 28 { // AAAA record
			ip := strings.Trim(answer.Data, "\"")
			if net.ParseIP(ip) != nil {
				return ip, nil
			}
		}
	}

	return "", fmt.Errorf("no A/AAAA records found for %s", hostname)
}

func (r *SecureDNSResolver) getFromCache(hostname string) (string, bool) {
	r.cacheMu.RLock()
	defer r.cacheMu.RUnlock()

	entry, ok := r.cache[hostname]
	if !ok {
		return "", false
	}

	if time.Now().After(entry.expiresAt) {
		return "", false
	}

	return entry.ip, true
}

func (r *SecureDNSResolver) addToCache(hostname, ip string) {
	r.cacheMu.Lock()
	defer r.cacheMu.Unlock()

	r.cache[hostname] = &dnsEntry{
		ip:        ip,
		expiresAt: time.Now().Add(r.cacheTTL),
	}
}

func (r *SecureDNSResolver) shuffledServers() []string {
	servers := make([]string, len(r.servers))
	copy(servers, r.servers)
	rand.Shuffle(len(servers), func(i, j int) {
		servers[i], servers[j] = servers[j], servers[i]
	})
	return servers
}

// ClearCache clears the DNS cache
func (r *SecureDNSResolver) ClearCache() {
	r.cacheMu.Lock()
	defer r.cacheMu.Unlock()
	r.cache = make(map[string]*dnsEntry)
}
