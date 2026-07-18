#!/bin/bash

echo "╔════════════════════════════════════════════════╗"
echo "║  Anonymous Network — SOCKS5 Proxy Diagnostics  ║"
echo "╚════════════════════════════════════════════════╝"
echo ""

# 1. Check if router is running
echo "1. Router Process:"
if pgrep -f "anon-router" > /dev/null; then
    echo "   ✓ Router is running"
    PID=$(pgrep -f "anon-router" | head -1)
    echo "   PID: $PID"
else
    echo "   ✗ Router is NOT running!"
    exit 1
fi

# 2. Check SOCKS5 listening
echo ""
echo "2. SOCKS5 Proxy Status:"
if netstat -tlnp 2>/dev/null | grep -q 4447; then
    echo "   ✓ SOCKS5 listening on 127.0.0.1:4447"
else
    echo "   ✗ SOCKS5 NOT listening on 4447"
fi

# 3. Check config
echo ""
echo "3. Config File:"
if [ -f config.json ]; then
    echo "   ✓ config.json found"
    echo "   SOCKS5: $(grep 'socks5_enabled' config.json)"
    echo "   SOCKS5 address: $(grep 'socks5_address' config.json)"
    echo "   Outproxy: $(grep 'outproxy_enabled' config.json)"
    echo "   Seed routers: $(grep -A2 'seed_routers' config.json | head -3)"
else
    echo "   ✗ config.json NOT found"
fi

# 4. Test SOCKS5 connection
echo ""
echo "4. SOCKS5 Connection Test:"
if timeout 3 bash -c 'echo "" | nc -x 127.0.0.1:4447 google.com 443' 2>/dev/null; then
    echo "   ✓ SOCKS5 proxy responding"
else
    echo "   ? SOCKS5 proxy may not be fully initialized"
fi

# 5. Check tunnels (if router supports debug output)
echo ""
echo "5. Router Connectivity:"
echo "   - For peer/tunnel status, check router console output"
echo "   - Running: cat <(tail -f /proc/$PID/fd/1) 2>/dev/null | grep -E 'Peers|Tunnels|Status|Failed'"
echo ""

# 6. Test with curl via SOCKS5
echo ""
echo "6. Test HTTP via SOCKS5:"
echo "   Running: curl -x socks5://127.0.0.1:4447 -v https://github.com 2>&1 | head -20"
curl -x socks5://127.0.0.1:4447 -v https://github.com 2>&1 | head -20

echo ""
echo "════════════════════════════════════════════════"
echo "If SOCKS5 is running but curl fails:"
echo "• Check that router is connected to seed (20.123.204.201:7656)"
echo "• Verify router has outbound tunnels built (check console)"
echo "• Make sure allow_direct_outproxy is false in config"
echo "════════════════════════════════════════════════"
