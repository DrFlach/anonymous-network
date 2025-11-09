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
    MaxConnections    int    `json:"max_connections"`
    
    // Tunnel settings
    TunnelLength      int `json:"tunnel_length"`
    TunnelLifetime    int `json:"tunnel_lifetime_seconds"`
    InboundTunnels    int `json:"inbound_tunnels"`
    OutboundTunnels   int `json:"outbound_tunnels"`
    
    // Performance
    MessageQueueSize  int `json:"message_queue_size"`
    
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
        MaxConnections:   200,
        TunnelLength:     3,
        TunnelLifetime:   600, // 10 minutes
        InboundTunnels:   2,
        OutboundTunnels:  2,
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