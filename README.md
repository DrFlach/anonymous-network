# Anonymous P2P Network

An anonymous peer-to-peer network featuring onion routing, garlic encryption, and a SOCKS5 proxy for secure and private internet access.

## Architecture

```
+--------------+     +----------------------------------------------+
|   Browser    |---->|  SOCKS5 Proxy (127.0.0.1:4447)              |
|  (Firefox)   |     |                                              |
+--------------+     |  +--------------------------------------+    |
                     |  |  Tunnel Pool                         |    |
                     |  |  +--------+ +--------+ +--------+   |    |
                     |  |  |Outbound| |Outbound| |Outbound|   |    |
                     |  |  |Tunnel 1| |Tunnel 2| |Tunnel 3|   |    |
                     |  |  +---+----+ +---+----+ +---+----+   |    |
                     |  |      |          |          |         |    |
                     |  |  [Onion Encryption - 3 layers]       |    |
                     |  +------+----------+----------+---------+    |
                     |         |          |          |               |
                     |  +------v----------v----------v---------+    |
                     |  |  Transport (NTCP2 Encrypted P2P)     |    |
                     |  +--------------------------------------+    |
                     |                                              |
                     |  +--------------------------------------+    |
                     |  |  NetDB + Floodfill DHT               |    |
                     |  +--------------------------------------+    |
                     |                                              |
                     |  +--------------------------------------+    |
                     |  |  Outproxy (Exit Node -> Internet)    |    |
                     |  |  + DNS-over-HTTPS (DoH)              |    |
                     |  +--------------------------------------+    |
                     +----------------------------------------------+
```

## Components

### Cryptography (`pkg/crypto/`)
- **Ed25519** -- digital signatures (RouterInfo, messages)
- **X25519** -- Diffie-Hellman key exchange
- **ChaCha20-Poly1305** -- authenticated encryption (AEAD)
- **HKDF** -- session key derivation
- **Onion encryption** -- layered encryption for tunnels
- **Key persistence** -- save/load identity to disk

### Transport (`pkg/transport/`)
- **NTCP2-like protocol** -- encrypted P2P connections
- **Noise handshake** -- ephemeral DH keys for perfect forward secrecy
- **Peer management** -- heartbeats, automatic disconnection of inactive peers

### Tunnels (`pkg/tunnel/`)
- **Onion routing** -- data is encrypted in layers (each node peels one layer)
- **Tunnel building** -- build protocol through a chain of routers
- **Tunnel pool** -- automatic maintenance of inbound/outbound tunnels
- **Transit participation** -- routing data on behalf of other users

### Garlic Routing (`pkg/garlic/`)
- **Garlic messages** -- bundling multiple cloves into a single message
- **Lease Sets** -- publishing tunnel entry points for destinations

### Proxy (`pkg/proxy/`)
- **SOCKS5 server** -- browser connection through the anonymous network
- **Outproxy** -- exit node for accessing the regular internet
- **DNS-over-HTTPS** -- secure DNS resolution (Cloudflare, Google, Mozilla)

### NetDB (`pkg/netdb/`)
- **RouterInfo** -- router metadata (addresses, keys, capabilities)
- **Floodfill DHT** -- distributed storage and propagation of RouterInfo
- **Peer discovery** -- finding new nodes in the network

## Quick Start

### Build

```bash
go build -o anon-router ./cmd/router/
```

### Generate Identity

```bash
./anon-router -keygen
```

### Verify Encryption Subsystems

```bash
./anon-router -verify
```

### Run the Router

```bash
# Basic start (SOCKS5 on 127.0.0.1:4447)
./anon-router

# With debug logging
./anon-router -debug

# Connect to seed nodes
./anon-router -seeds "192.168.1.10:7656,192.168.1.11:7656"

# As a floodfill node
./anon-router -floodfill

# With a custom SOCKS5 address
./anon-router -socks 127.0.0.1:9050

# Without an exit node (internal network traffic only)
./anon-router -no-outproxy
```

### Browser Configuration

#### Firefox
1. **Settings** > **Network Settings** > **Settings...**
2. Select **Manual proxy configuration**
3. **SOCKS Host:** `127.0.0.1`
4. **Port:** `4447`
5. Select **SOCKS v5**
6. Check **Proxy DNS when using SOCKS v5** (important)

#### Chrome / Chromium
```bash
chromium --proxy-server="socks5://127.0.0.1:4447"
```

## Configuration (config.json)

```json
{
  "listen_address": "0.0.0.0",
  "listen_port": 7656,
  "seed_routers": [],
  "identity_file": "identity.json",
  "max_connections": 200,
  "is_floodfill": false,
  "tunnel_length": 3,
  "tunnel_lifetime_seconds": 600,
  "inbound_tunnels": 3,
  "outbound_tunnels": 3,
  "socks5_enabled": true,
  "socks5_address": "127.0.0.1:4447",
  "outproxy_enabled": true,
  "dns_servers": [
    "https://1.1.1.1/dns-query",
    "https://dns.google/resolve",
    "https://mozilla.cloudflare-dns.com/dns-query"
  ],
  "log_level": "INFO"
}
```

## Security Layers

| Layer | Protects Against | Method |
|-------|-----------------|--------|
| **Transport** | Eavesdropping between routers | ChaCha20-Poly1305 + X25519 ECDH |
| **Tunnels** | Traffic analysis | Onion encryption (3+ layers) |
| **DNS** | DNS leaks | DNS-over-HTTPS (DoH) |
| **Garlic** | Message correlation | Bundling + re-encryption |
| **Perfect Forward Secrecy** | Compromise of past sessions | Ephemeral keys per connection |

## Project Structure

```
cmd/
  router/
    main.go              # Entry point, component integration
pkg/
  crypto/
    encrypt.go           # AEAD encryption, onion encryption
    identity.go          # RouterIdentity generation (Ed25519 + X25519)
    persist.go           # Key save/load
  garlic/
    garlic.go            # Garlic messages and cloves
    leaseset.go          # Lease sets for destinations
  netdb/
    floodfill.go         # DHT, RouterInfo propagation
    routerinfo.go        # RouterInfo: addresses, keys, signatures
    store.go             # In-memory RouterInfo store
  proxy/
    outproxy.go          # Exit node (outproxy)
    resolver.go          # DNS-over-HTTPS resolver
    socks5.go            # SOCKS5 proxy server
  router/
    message.go           # Protocol messages
  transport/
    manager.go           # P2P connection management
    ntcp2/
      conn.go            # Encrypted connections
      handshake.go       # Noise-like handshake
  tunnel/
    build.go             # Tunnel build protocol
    pool.go              # Tunnel pool (auto-management)
    tunnel.go            # Tunnel structures, transit participation
  util/
    config.go            # Configuration
    logger.go            # Logging
```

## How Anonymization Works

1. The **browser** connects to the local SOCKS5 proxy (`127.0.0.1:4447`).
2. The request is encrypted with **3 layers** (one per hop in the tunnel).
3. Each intermediate node peels **only its own layer** of encryption.
4. No single node knows both the **sender** and the **destination**.
5. The **exit node** (outproxy) connects to the target server.
6. **DNS** is resolved via **DNS-over-HTTPS**, preventing leaks.

## License

MIT