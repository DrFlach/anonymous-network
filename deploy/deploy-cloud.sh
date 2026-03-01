#!/bin/bash
#
# deploy-cloud.sh — Deploy anon-router to a cloud VPS
#
# Works with: Google Cloud (gcloud), DigitalOcean, Hetzner, AWS, Vultr, etc.
# The VPS becomes a public relay node that anyone can --join.
#
# Usage:
#   For Google Cloud (from Cloud Shell or local with gcloud):
#     ./deploy/deploy-cloud.sh --gcloud <vm-name> [zone]  [deploy|stop|status|logs]
#     ./deploy/deploy-cloud.sh --gcloud anon-relay                    # deploy
#     ./deploy/deploy-cloud.sh --gcloud anon-relay us-central1-a stop # stop
#
#   For any VPS via SSH:
#     ./deploy/deploy-cloud.sh <user@ip> [ssh-key] [deploy|stop|status|logs]
#     ./deploy/deploy-cloud.sh root@203.0.113.10
#     ./deploy/deploy-cloud.sh root@203.0.113.10 ~/.ssh/id_ed25519 stop

set +e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BINARY_NAME="anon-router"
REMOTE_DIR="/opt/anon-router"
PORT=7656

info()  { echo -e "\033[1;32m[INFO]\033[0m  $*"; }
warn()  { echo -e "\033[1;33m[WARN]\033[0m  $*"; }
error() { echo -e "\033[1;31m[ERROR]\033[0m $*"; }

# ---- Parse args ----
if [ -z "$1" ]; then
    echo "Usage:"
    echo "  Google Cloud:"
    echo "    $0 --gcloud <vm-name> [zone] [deploy|stop|status|logs]"
    echo "    $0 --gcloud anon-relay"
    echo ""
    echo "  Any VPS (SSH):"
    echo "    $0 <user@ip> [ssh-key] [deploy|stop|status|logs]"
    echo "    $0 root@203.0.113.10"
    exit 1
fi

# ---- Detect mode: --gcloud or SSH ----
USE_GCLOUD=false
GCE_VM=""
GCE_ZONE=""
TARGET=""
SSH_KEY=""
ACTION="deploy"
VPS_IP=""

if [ "$1" = "--gcloud" ]; then
    USE_GCLOUD=true
    GCE_VM="$2"
    if [ -z "$GCE_VM" ]; then
        error "VM name required: $0 --gcloud <vm-name>"
        exit 1
    fi
    # $3 could be a zone or an action
    if [ -n "$3" ]; then
        case "$3" in
            deploy|stop|status|logs) ACTION="$3" ;;
            *)
                GCE_ZONE="$3"
                ACTION="${4:-deploy}"
                ;;
        esac
    fi
    # Build zone flag
    GCE_ZONE_FLAG=""
    if [ -n "$GCE_ZONE" ]; then
        GCE_ZONE_FLAG="--zone=$GCE_ZONE"
    fi
else
    TARGET="$1"
    if [ -n "$2" ]; then
        if [ -f "$2" ] || [[ "$2" == ~/.ssh/* ]]; then
            SSH_KEY="$2"
            ACTION="${3:-deploy}"
        else
            ACTION="$2"
        fi
    fi
fi

# ---- SSH / SCP wrappers ----
SSH_OPTS="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o ConnectTimeout=10"
if [ -n "$SSH_KEY" ]; then
    SSH_OPTS="$SSH_OPTS -i $SSH_KEY"
fi

# Extract just the IP from user@ip
if [ -n "$TARGET" ]; then
    VPS_IP="${TARGET#*@}"
fi

rssh() {
    if $USE_GCLOUD; then
        gcloud compute ssh "$GCE_VM" $GCE_ZONE_FLAG --command="$*" 2>/dev/null
    else
        ssh $SSH_OPTS "$TARGET" "$@"
    fi
}

rscpp() {
    local src="$1" dest="$2"
    if $USE_GCLOUD; then
        gcloud compute scp "$src" "$GCE_VM:$dest" $GCE_ZONE_FLAG 2>/dev/null
    else
        scp $SSH_OPTS "$src" "$TARGET:$dest"
    fi
}

# Get the display name for messages
get_display_name() {
    if $USE_GCLOUD; then
        echo "gcloud:$GCE_VM"
    else
        echo "$TARGET"
    fi
}

# ---- Actions ----

do_build() {
    info "Building static binary for linux/amd64..."
    cd "$PROJECT_DIR"
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o "$BINARY_NAME" ./cmd/router/ || {
        error "Build failed"; exit 1
    }
    info "Build OK ($(du -h "$BINARY_NAME" | cut -f1))"
}

do_deploy() {
    local DISPLAY_NAME
    DISPLAY_NAME=$(get_display_name)

    echo ""
    echo "========================================"
    echo "  Cloud VPS Deploy → $DISPLAY_NAME"
    echo "========================================"
    echo ""

    # Test SSH
    info "Testing SSH connection..."
    rssh "echo 'SSH OK'" || {
        error "Cannot SSH to $DISPLAY_NAME"
        echo ""
        if $USE_GCLOUD; then
            echo "Make sure:"
            echo "  1. VM '$GCE_VM' exists and is running"
            echo "  2. You have the right project set: gcloud config set project <PROJECT_ID>"
            echo "  3. Try: gcloud compute ssh $GCE_VM"
        else
            echo "Make sure:"
            echo "  1. The IP is correct"
            echo "  2. SSH key is added: ssh-copy-id $TARGET"
            echo "  3. Port 22 is open on the VPS"
        fi
        exit 1
    }
    info "SSH connection OK"

    # Build
    do_build

    # Stop old instance
    info "Stopping old instance (if any)..."
    rssh "sudo pkill -f '$BINARY_NAME' 2>/dev/null; true"
    sleep 1

    # Create dir & upload
    info "Uploading binary..."
    rssh "sudo mkdir -p $REMOTE_DIR && sudo chmod 777 $REMOTE_DIR"
    rscpp "$PROJECT_DIR/$BINARY_NAME" "$REMOTE_DIR/$BINARY_NAME"
    rssh "chmod +x $REMOTE_DIR/$BINARY_NAME"

    # Get the external IP for display
    if $USE_GCLOUD; then
        VPS_IP=$(gcloud compute instances describe "$GCE_VM" $GCE_ZONE_FLAG \
            --format='get(networkInterfaces[0].accessConfigs[0].natIP)' 2>/dev/null)
        if [ -z "$VPS_IP" ]; then
            VPS_IP=$(rssh "curl -s http://metadata.google.internal/computeMetadata/v1/instance/network-interfaces/0/access-configs/0/external-ip -H 'Metadata-Flavor: Google'" 2>/dev/null)
        fi
        info "External IP: $VPS_IP"
    fi

    # Generate config on the VPS
    info "Generating config..."
    rssh "cat > $REMOTE_DIR/config.json << CFGEOF
{
    \"listen_address\": \"0.0.0.0\",
    \"listen_port\": $PORT,
    \"max_connections\": 50,
    \"is_floodfill\": true,
    \"outproxy_enabled\": true,
    \"socks5_enabled\": false,
    \"seed_routers\": [],
    \"identity_file\": \"$REMOTE_DIR/identity.json\",
    \"inbound_tunnels\": 3,
    \"outbound_tunnels\": 3,
    \"tunnel_length\": 3,
    \"tunnel_lifetime\": 600
}
CFGEOF"

    # Open firewall
    info "Opening port $PORT in firewall..."
    rssh "
        # Try ufw (Ubuntu/Debian)
        if command -v ufw &>/dev/null; then
            sudo ufw allow $PORT/tcp 2>/dev/null
        fi
        # Try firewall-cmd (CentOS/Fedora)
        if command -v firewall-cmd &>/dev/null; then
            sudo firewall-cmd --add-port=$PORT/tcp --permanent 2>/dev/null
            sudo firewall-cmd --reload 2>/dev/null
        fi
        # iptables fallback
        if command -v iptables &>/dev/null; then
            sudo iptables -C INPUT -p tcp --dport $PORT -j ACCEPT 2>/dev/null || \
            sudo iptables -I INPUT -p tcp --dport $PORT -j ACCEPT 2>/dev/null
        fi
        true
    "

    # Create systemd service
    info "Installing systemd service..."
    rssh "sudo tee /etc/systemd/system/anon-router.service > /dev/null << SVCEOF
[Unit]
Description=Anonymous P2P Network Router
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=$REMOTE_DIR
ExecStart=$REMOTE_DIR/$BINARY_NAME -config $REMOTE_DIR/config.json
Restart=always
RestartSec=5
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
SVCEOF
sudo systemctl daemon-reload
sudo systemctl enable anon-router 2>/dev/null"

    # Start
    info "Starting router..."
    rssh "sudo systemctl restart anon-router"
    sleep 3

    # Check
    local svc_status
    svc_status=$(rssh "sudo systemctl is-active anon-router" 2>/dev/null)
    if echo "$svc_status" | grep -q "active"; then
        info "Router is running on $VPS_IP:$PORT"
    else
        error "Router failed to start. Logs:"
        rssh "sudo journalctl -u anon-router --no-pager -n 20"
        exit 1
    fi

    echo ""
    echo "========================================"
    info "VPS node deployed!"
    echo ""
    echo "  Public address: $VPS_IP:$PORT"
    echo ""
    echo "  To connect from your computer:"
    echo "    ./anon-router --join $VPS_IP:$PORT --socks 127.0.0.1:4447"
    echo ""
    echo "  To connect from any device:"
    echo "    ./anon-router --join $VPS_IP:$PORT"
    echo ""
    echo "  Commands:"
    SELF_ARGS="$1"
    if $USE_GCLOUD; then SELF_ARGS="--gcloud $GCE_VM"; fi
    echo "    $0 $SELF_ARGS status  - check node"
    echo "    $0 $SELF_ARGS logs    - view logs"
    echo "    $0 $SELF_ARGS stop    - stop node"
    echo "========================================"
    echo ""
}

do_stop() {
    local DISPLAY_NAME
    DISPLAY_NAME=$(get_display_name)
    info "Stopping router on $DISPLAY_NAME..."
    rssh "sudo systemctl stop anon-router 2>/dev/null; sudo pkill -f '$BINARY_NAME' 2>/dev/null; true"
    info "Stopped"
}

do_status() {
    local DISPLAY_NAME
    DISPLAY_NAME=$(get_display_name)
    echo ""
    echo "Node: $DISPLAY_NAME"
    echo "---"
    local svc_status
    svc_status=$(rssh "sudo systemctl is-active anon-router" 2>/dev/null)
    if echo "$svc_status" | grep -q "active"; then
        echo "  Status: RUNNING"
        rssh "sudo journalctl -u anon-router --no-pager -n 10 2>/dev/null" | grep -E "Peers=|Peer connected|started|Router Hash" | tail -5 | sed 's/^/  /'
    else
        echo "  Status: STOPPED"
    fi
    echo ""
}

do_logs() {
    rssh "sudo journalctl -u anon-router --no-pager -n 50 -f"
}

# ---- Main ----
case "$ACTION" in
    deploy) do_deploy ;;
    stop)   do_stop ;;
    status) do_status ;;
    logs)   do_logs ;;
    *)
        echo "Usage: $0 <user@ip> [ssh-key] [deploy|stop|status|logs]"
        ;;
esac
