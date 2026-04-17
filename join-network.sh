#!/bin/bash
# ═══════════════════════════════════════════════════════════════
#  Join Anonymous P2P Network
#  Run this script on any Linux machine to join the network.
#  Works from any city, country, or network.
# ═══════════════════════════════════════════════════════════════

set -e

# ── Configuration ──────────────────────────────────────────────
VPS_SEED="34.118.110.89:7656"
LISTEN_PORT=7656
SOCKS_PORT=4447
INSTALL_DIR="$HOME/anon-network"
# ───────────────────────────────────────────────────────────────

echo "╔═══════════════════════════════════════════════╗"
echo "║  Anonymous P2P Network — Join Script          ║"
echo "╚═══════════════════════════════════════════════╝"
echo ""

# Check for Go
if ! command -v go &>/dev/null; then
    echo "❌ Go is not installed. Install Go 1.21+ first:"
    echo "   https://go.dev/dl/"
    exit 1
fi

GO_VER=$(go version | grep -oP 'go\K[0-9]+\.[0-9]+')
echo "✓ Go $GO_VER found"

# Create install directory
mkdir -p "$INSTALL_DIR"
cd "$INSTALL_DIR"

# Clone or update the repo
if [ -d ".git" ]; then
    echo "→ Updating existing installation..."
    git pull origin main 2>/dev/null || true
else
    echo "→ Cloning repository..."
    git clone https://github.com/DrFlach/anonymous-network.git .
fi

# Build
echo "→ Building binary..."
CGO_ENABLED=0 go build -o anon-router ./cmd/router/
echo "✓ Binary built: $INSTALL_DIR/anon-router"

# Generate config if needed
if [ ! -f config.json ]; then
    cat > config.json <<CONF
{
  "listen_address": "0.0.0.0",
  "listen_port": $LISTEN_PORT,
  "seed_routers": ["$VPS_SEED"],
    "bootstrap_seed_urls": [
        "https://raw.githubusercontent.com/DrFlach/anonymous-network/main/seeds.txt"
    ],
    "min_seed_routers": 3,
  "router_info_file": "router.dat",
  "identity_file": "identity.json",
  "max_connections": 200,
  "is_floodfill": false,
  "tunnel_length": 3,
  "tunnel_lifetime_seconds": 600,
  "inbound_tunnels": 3,
  "outbound_tunnels": 3,
  "socks5_enabled": true,
  "socks5_address": "127.0.0.1:$SOCKS_PORT",
  "outproxy_enabled": true,
    "strict_dns_only": true,
  "dns_servers": [
    "https://1.1.1.1/dns-query",
    "https://dns.google/resolve",
    "https://mozilla.cloudflare-dns.com/dns-query"
  ],
  "message_queue_size": 1000,
  "log_level": "INFO"
}
CONF
    echo "✓ Config created with seed: $VPS_SEED"
else
    echo "✓ Config already exists"
fi

# Delete old identity if it's a duplicate from git
if [ -f identity.json ]; then
    echo "✓ Using existing identity"
else
    echo "→ New identity will be generated on first run"
fi

echo ""
echo "═══════════════════════════════════════════════"
echo "  ✅ Installation complete!"
echo ""
echo "  To start the node:"
echo "    cd $INSTALL_DIR"
echo "    ./anon-router"
echo ""
echo "  To browse anonymously:"
echo "    1. Start the node (above)"
echo "    2. Set browser SOCKS5 proxy to 127.0.0.1:$SOCKS_PORT"
echo ""
echo "  To accept incoming connections (increases network):"
echo "    - Open port $LISTEN_PORT/tcp on your firewall/router"
echo "    - Other nodes will discover you through the VPS"
echo ""
echo "  Tip: Use --debug flag for verbose logging"
echo "═══════════════════════════════════════════════"
