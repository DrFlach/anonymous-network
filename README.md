# Anonymous P2P Network

A fully functional anonymous peer-to-peer network with onion routing, garlic encryption, automatic peer discovery, and a SOCKS5 proxy for private internet browsing. Written in Go with zero external dependencies.

## Features

- **Onion-routed tunnels** — multi-hop encrypted tunnels (like Tor/I2P)
- **Garlic encryption** — bundle multiple messages into one encrypted packet
- **SOCKS5 proxy** — plug into any browser for anonymous browsing
- **DNS-over-HTTPS** — no DNS leaks (Cloudflare, Google, Mozilla)
- **Automatic peer discovery** — connect to a seed node, find the rest automatically
- **UPnP auto port forwarding** — opens your router port automatically so others can connect to you
- **Relay forwarding** — peers behind NAT can still participate via relay through public nodes
- **Floodfill DHT** — distributed router database, no central server required
- **Zero config** — just build and run, everything works out of the box

## Quick Start — Join the Network

### 1. Clone and build

```bash
git clone https://github.com/DrFlach/anonymous-network.git
cd anonymous-network
```

#### Linux / macOS
```bash
go build -o anon-router ./cmd/router/
```

#### Windows (cmd / PowerShell / Git Bash)
```bash
go build -o anon-router.exe ./cmd/router/
```

### 2. Run

#### Linux / macOS
```bash
./anon-router
```

#### Windows (cmd / PowerShell)
```powershell
.\anon-router.exe
```

#### Windows (Git Bash / MINGW64)
```bash
./anon-router.exe
```

## Alternative: run in Docker

If you prefer to keep everything isolated, run the router in a container.
The repository already includes [Dockerfile](Dockerfile) and [docker-compose.yml](docker-compose.yml).

### Option A — plain Docker

Build the image:

```bash
docker build -t anonymous-network:latest .
```

Start the router:

```bash
docker run -d \
  --name anon-router \
  --restart unless-stopped \
  -p 7656:7656/tcp \
  -p 4447:4447/tcp \
  -v $(pwd)/data:/data \
  anonymous-network:latest
```

Useful commands:

```bash
docker logs -f anon-router
docker stop anon-router
docker rm anon-router
```

### Option B — Docker Compose (recommended)

```bash
docker compose up -d --build
docker compose logs -f
docker compose down
```

The `./data` folder is mounted into the container as `/data`, so your `identity.json`
and `config.json` stay persistent between restarts.

> Linux note: if you get `permission denied` for `/var/run/docker.sock`, run commands with `sudo`
> or add your user to the `docker` group and re-login.

That's it. The router will:
- Generate a unique identity (saved to `identity.json`)
- Connect to the seed node (`34.118.110.89:7656`)
- Discover other peers automatically
- Try to open your router port via UPnP
- Start a SOCKS5 proxy on `127.0.0.1:4447`
- Build encrypted tunnels through the network

### 3. Configure your browser

#### Firefox (recommended)
1. **Settings** → **Network Settings** → **Settings...**
2. Select **Manual proxy configuration**
3. **SOCKS Host:** `127.0.0.1`, **Port:** `4447`
4. Select **SOCKS v5**
5. ✅ Check **Proxy DNS when using SOCKS v5** *(important — prevents DNS leaks)*

#### Chrome / Chromium
```bash
chromium --proxy-server="socks5://127.0.0.1:4447"
```

### 4. Verify it works

You should see output like:
```
Transport manager listening on 0.0.0.0:7656
Peer connected: 34.118.110.89:7656 (total: 1)
UPnP: Port 7656 forwarded successfully
Built inbound tunnel with 1 hops
Built outbound tunnel with 1 hops
SOCKS5 proxy ready on 127.0.0.1:4447
── Status: Peers=2 | Known nodes=5 | Tunnels: in=3 out=3 ──
```

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
                     |  |  Peer Discovery + UPnP + Relay       |    |
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
- **Ed25519** — digital signatures (RouterInfo, messages)
- **X25519** — Diffie-Hellman key exchange
- **ChaCha20-Poly1305** — authenticated encryption (AEAD)
- **HKDF** — session key derivation
- **Onion encryption** — layered encryption for tunnels
- **Key persistence** — save/load identity to `identity.json`

### Transport (`pkg/transport/`)
- **NTCP2-like protocol** — encrypted P2P connections over TCP
- **Noise handshake** — ephemeral DH keys for perfect forward secrecy
- **Peer management** — heartbeats, automatic reconnection, peer exchange
- **UPnP** — automatic port forwarding via IGD protocol (SSDP + SOAP)
- **Relay forwarding** — NAT-traversal by relaying through public nodes
- **STUN-like IP discovery** — peers report your external IP

### Tunnels (`pkg/tunnel/`)
- **Onion routing** — data is encrypted in layers (each node peels one layer)
- **Tunnel building** — build protocol through a chain of routers
- **Tunnel pool** — automatic maintenance of inbound/outbound tunnels
- **Transit participation** — routing data on behalf of other users

### Garlic Routing (`pkg/garlic/`)
- **Garlic messages** — bundling multiple cloves into a single message
- **Lease Sets** — publishing tunnel entry points for destinations

### Proxy (`pkg/proxy/`)
- **SOCKS5 server** — browser connection through the anonymous network
- **Outproxy** — exit node for accessing the regular internet
- **DNS-over-HTTPS** — secure DNS resolution (Cloudflare, Google, Mozilla)

### NetDB (`pkg/netdb/`)
- **RouterInfo** — router metadata (addresses, keys, capabilities)
- **Floodfill DHT** — distributed storage and propagation of RouterInfo
- **Peer discovery** — automatic discovery of new nodes via peer exchange

## Command-Line Flags

| Flag | Description |
|------|-------------|
| `-config <path>` | Path to configuration file (default: `config.json`) |
| `-keygen` | Generate a new router identity and exit |
| `-verify` | Run encryption self-test and exit |
| `-listen <addr>` | Override listen address (e.g. `0.0.0.0:7656`) |
| `-seeds <addrs>` | Comma-separated seed router addresses |
| `-join <addr>` | Connect to a specific peer to join the network |
| `-socks <addr>` | Override SOCKS5 proxy address (e.g. `127.0.0.1:9050`) |
| `-floodfill` | Enable floodfill mode (store and propagate NetDB) |
| `-debug` | Enable verbose debug logging |
| `-no-outproxy` | Disable outproxy (no exit to regular internet) |
| `-no-upnp` | Disable UPnP automatic port forwarding |

### Examples

> On Windows, replace `./anon-router` with `.\anon-router.exe` (PowerShell) or `./anon-router.exe` (Git Bash).

```bash
# Just run (connects to seed, auto-discovers peers)
./anon-router

# Run with debug logging
./anon-router -debug

# Connect to a specific peer
./anon-router -join 203.0.113.50:7656

# Run as a floodfill relay (for VPS / public servers)
./anon-router -floodfill -no-upnp

# Custom SOCKS5 port
./anon-router -socks 127.0.0.1:9050

# Disable exit traffic (relay only)
./anon-router -no-outproxy
```

## Configuration (config.json)

A `config.json` file is created automatically on first run. You can customize it:

```json
{
  "listen_address": "0.0.0.0",
  "listen_port": 7656,
  "seed_routers": [
    "34.118.110.89:7656"
  ],
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
  "disable_upnp": false,
  "dns_servers": [
    "https://1.1.1.1/dns-query",
    "https://dns.google/resolve",
    "https://mozilla.cloudflare-dns.com/dns-query"
  ],
  "log_level": "INFO"
}
```

## Network Topology

```
                    Internet
                       │
              ┌────────┴────────┐
              │   Seed / Relay  │   Public VPS (floodfill)
              │ 34.118.110.89   │   Knows all peers, relays for NAT users
              └──┬──────┬───┬───┘
                 │      │   │
        ┌────────┘      │   └────────┐
        ▼               ▼            ▼
   ┌─────────┐   ┌──────────┐  ┌─────────┐
   │ Peer A  │   │ Peer B   │  │ Peer C  │
   │(UPnP OK)│◄─►│(public IP│  │ (NAT)   │
   │ direct  │   │ direct)  │  │ relay   │
   └─────────┘   └──────────┘  └─────────┘
```

- **Peers with public IP or UPnP**: fully reachable, accept incoming connections
- **Peers behind NAT**: connect outward to seed, use relay forwarding for inbound traffic
- **Peer exchange**: every 60 seconds, nodes share known peer addresses with each other

## Security Layers

| Layer | Protects Against | Method |
|-------|-----------------|--------|
| **Transport** | Eavesdropping between routers | ChaCha20-Poly1305 + X25519 ECDH |
| **Tunnels** | Traffic analysis | Onion encryption (3+ layers) |
| **DNS** | DNS leaks | DNS-over-HTTPS (DoH) |
| **Garlic** | Message correlation | Bundling + re-encryption |
| **Perfect Forward Secrecy** | Compromise of past sessions | Ephemeral keys per connection |

## How Anonymization Works

1. The **browser** connects to the local SOCKS5 proxy (`127.0.0.1:4447`).
2. The request is encrypted with **3 layers** (one per hop in the tunnel).
3. Each intermediate node peels **only its own layer** of encryption.
4. No single node knows both the **sender** and the **destination**.
5. The **exit node** (outproxy) connects to the target server.
6. **DNS** is resolved via **DNS-over-HTTPS**, preventing leaks.

## Project Structure

```
cmd/
  router/
    main.go              # Entry point, CLI flags, component wiring
pkg/
  crypto/
    encrypt.go           # AEAD encryption, onion encryption
    identity.go          # RouterIdentity generation (Ed25519 + X25519)
    persist.go           # Key save/load to disk
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
    message.go           # Protocol message types (13 types)
  transport/
    manager.go           # P2P connections, peer exchange, relay, NAT traversal
    upnp.go              # UPnP IGD auto port forwarding
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
    sockopt_unix.go      # SO_REUSEADDR for Linux/macOS
    sockopt_windows.go   # SO_REUSEADDR for Windows
```

## Supported Platforms

| OS | Architecture | Status |
|----|-------------|--------|
| Linux | amd64, arm64 | ✅ Fully supported |
| macOS | amd64 (Intel), arm64 (Apple Silicon) | ✅ Fully supported |
| Windows | amd64 | ✅ Fully supported |

## Requirements

- **Go 1.21+**
- No external dependencies (stdlib only)

## License

MIT