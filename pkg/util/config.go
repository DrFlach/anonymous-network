package util

import (
    "encoding/json"
    "fmt"
    "os"
)

type Config struct {
    // Network settings
    ListenAddress     string   `json:"listen_address"`
    ListenPort        int      `json:"listen_port"`
    SeedRouters       []string `json:"seed_routers"`
    
    // Router settings
    RouterInfoFile    string `json:"router_info_file"`
    IdentityFile      string `json:"identity_file"`
    MaxConnections    int    `json:"max_connections"`
    IsFloodfill       bool   `json:"is_floodfill"`
    
    // Tunnel settings
    TunnelLength      int `json:"tunnel_length"`
    TunnelLifetime    int `json:"tunnel_lifetime_seconds"`
    InboundTunnels    int `json:"inbound_tunnels"`
    OutboundTunnels   int `json:"outbound_tunnels"`
    
    // SOCKS5 Proxy settings
    SOCKS5Enabled     bool   `json:"socks5_enabled"`
    SOCKS5Address     string `json:"socks5_address"`
    SOCKS5Username    string `json:"socks5_username,omitempty"`
    SOCKS5Password    string `json:"socks5_password,omitempty"`
    
    // Outproxy settings
    OutproxyEnabled   bool     `json:"outproxy_enabled"`
    DNSServers        []string `json:"dns_servers"`
    BlockedHosts      []string `json:"blocked_hosts,omitempty"`
    
    // Performance
    MessageQueueSize  int `json:"message_queue_size"`
    
    // UPnP auto port forwarding
    DisableUPnP       bool `json:"disable_upnp,omitempty"`
    
    // Logging
    LogLevel          string `json:"log_level"`
}

func LoadConfig(path string) (*Config, error) {
    data, err := os.ReadFile(path)
    if err != nil {
        return nil, fmt.Errorf("failed to read config file: %w", err)
    }
    
    var config Config
    if err := json.Unmarshal(data, &config); err != nil {
        return nil, fmt.Errorf("failed to parse config: %w", err)
    }
    
    return &config, nil
}

func DefaultConfig() *Config {
    return &Config{
        ListenAddress:    "0.0.0.0",
        ListenPort:       7656,
        SeedRouters:      []string{},
        RouterInfoFile:   "router.dat",
        IdentityFile:     "identity.json",
        MaxConnections:   200,
        IsFloodfill:      false,
        TunnelLength:     3,
        TunnelLifetime:   600, // 10 minutes
        InboundTunnels:   3,
        OutboundTunnels:  3,
        SOCKS5Enabled:    true,
        SOCKS5Address:    "127.0.0.1:4447",
        SOCKS5Username:   "",
        SOCKS5Password:   "",
        OutproxyEnabled:  true,
        DNSServers: []string{
            "https://1.1.1.1/dns-query",
            "https://dns.google/resolve",
            "https://mozilla.cloudflare-dns.com/dns-query",
        },
        BlockedHosts:     []string{},
        MessageQueueSize: 1000,
        LogLevel:         "INFO",
    }
}

func (c *Config) Save(path string) error {
    data, err := json.MarshalIndent(c, "", "  ")
    if err != nil {
        return fmt.Errorf("failed to marshal config: %w", err)
    }
    
    if err := os.WriteFile(path, data, 0644); err != nil {
        return fmt.Errorf("failed to write config file: %w", err)
    }
    
    return nil
}