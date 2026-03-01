#!/bin/bash
#
# deploy.sh - Deploy anonymous network to 3 nodes (host + 2 Ubuntu VMs)
#
# Network topology:
#   Host   (192.168.56.1)   - floodfill + SOCKS5 proxy (your browser connects here)
#   ubuntu1 (192.168.56.101) - floodfill relay node
#   ubuntu2 (192.168.56.102) - floodfill relay node
#
# Prerequisites:
#   - VMs running: cd ~/Desktop/all-courses && vagrant up
#   - SSH access to VMs (default vagrant/vagrant)
#
# Usage:
#   ./deploy/deploy.sh          # full deploy (build + upload + start all)
#   ./deploy/deploy.sh stop     # stop all nodes
#   ./deploy/deploy.sh status   # check status of all nodes

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BINARY_NAME="anon-router"
REMOTE_DIR="/opt/anon-router"

HOST_IP="192.168.56.1"
VM1_IP="192.168.56.101"
VM2_IP="192.168.56.102"
VM_USER="vagrant"
VM_PASS="vagrant"

# SSH options to skip host key checking
SSH_OPTS="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR"

info()  { echo -e "\033[1;32m[INFO]\033[0m  $*"; }
warn()  { echo -e "\033[1;33m[WARN]\033[0m  $*"; }
error() { echo -e "\033[1;31m[ERROR]\033[0m $*"; }

# Run command on remote VM via sshpass
remote() {
    local ip="$1"; shift
    sshpass -p "$VM_PASS" ssh $SSH_OPTS "$VM_USER@$ip" "$@"
}

# Copy file to remote VM
remote_cp() {
    local file="$1" ip="$2" dest="$3"
    sshpass -p "$VM_PASS" scp $SSH_OPTS "$file" "$VM_USER@$ip:$dest"
}

check_deps() {
    if ! command -v sshpass &>/dev/null; then
        error "sshpass is required. Install it:"
        echo "  sudo dnf install sshpass    # Fedora/RHEL"
        echo "  sudo apt install sshpass    # Debian/Ubuntu"
        exit 1
    fi
}

build() {
    info "Building binary for linux/amd64..."
    cd "$PROJECT_DIR"
    GOOS=linux GOARCH=amd64 go build -o "$BINARY_NAME" ./cmd/router/
    info "Binary built: $PROJECT_DIR/$BINARY_NAME"
}

deploy_vm() {
    local ip="$1" config_file="$2" node_name="$3"

    info "Deploying to $node_name ($ip)..."

    # Create remote directory
    remote "$ip" "sudo mkdir -p $REMOTE_DIR && sudo chown $VM_USER:$VM_USER $REMOTE_DIR"

    # Stop existing instance if running
    remote "$ip" "sudo pkill -f '$REMOTE_DIR/$BINARY_NAME' 2>/dev/null || true"
    sleep 1

    # Upload binary and config
    remote_cp "$PROJECT_DIR/$BINARY_NAME" "$ip" "$REMOTE_DIR/$BINARY_NAME"
    remote_cp "$config_file" "$ip" "$REMOTE_DIR/config.json"

    # Make binary executable
    remote "$ip" "chmod +x $REMOTE_DIR/$BINARY_NAME"

    info "Deployed to $node_name"
}

start_vm() {
    local ip="$1" node_name="$2"

    info "Starting router on $node_name ($ip)..."

    # Stop existing instance
    remote "$ip" "sudo pkill -f '$REMOTE_DIR/$BINARY_NAME' 2>/dev/null || true"
    sleep 1

    # Start in background with nohup
    remote "$ip" "cd $REMOTE_DIR && nohup ./$BINARY_NAME -config config.json > router.log 2>&1 &"

    sleep 2

    # Verify it started
    if remote "$ip" "pgrep -f '$REMOTE_DIR/$BINARY_NAME'" &>/dev/null; then
        info "$node_name is running"
    else
        error "$node_name failed to start. Check logs:"
        echo "  ssh $VM_USER@$ip 'cat $REMOTE_DIR/router.log'"
    fi
}

stop_vm() {
    local ip="$1" node_name="$2"
    info "Stopping $node_name ($ip)..."
    remote "$ip" "sudo pkill -f '$REMOTE_DIR/$BINARY_NAME' 2>/dev/null || true"
}

status_vm() {
    local ip="$1" node_name="$2"
    if remote "$ip" "pgrep -f '$REMOTE_DIR/$BINARY_NAME'" &>/dev/null 2>&1; then
        echo "  $node_name ($ip): RUNNING"
        remote "$ip" "tail -3 $REMOTE_DIR/router.log 2>/dev/null" | sed 's/^/    /'
    else
        echo "  $node_name ($ip): STOPPED"
    fi
}

start_host() {
    info "Starting router on host ($HOST_IP)..."

    # Stop existing
    pkill -f "$PROJECT_DIR/$BINARY_NAME" 2>/dev/null || true
    sleep 1

    # Copy host config
    cp "$SCRIPT_DIR/config-host.json" "$PROJECT_DIR/config.json"

    # Start
    cd "$PROJECT_DIR"
    nohup ./"$BINARY_NAME" -config config.json > router.log 2>&1 &

    sleep 2
    if pgrep -f "$PROJECT_DIR/$BINARY_NAME" &>/dev/null; then
        info "Host router is running (SOCKS5 on 127.0.0.1:4447)"
    else
        error "Host router failed to start. Check: $PROJECT_DIR/router.log"
    fi
}

stop_host() {
    info "Stopping host router..."
    pkill -f "$PROJECT_DIR/$BINARY_NAME" 2>/dev/null || true
}

status_host() {
    if pgrep -f "$PROJECT_DIR/$BINARY_NAME" &>/dev/null; then
        echo "  host ($HOST_IP): RUNNING"
        tail -3 "$PROJECT_DIR/router.log" 2>/dev/null | sed 's/^/    /'
    else
        echo "  host ($HOST_IP): STOPPED"
    fi
}

# ---- Main ----

case "${1:-deploy}" in
    deploy)
        check_deps
        echo ""
        echo "====================================="
        echo "  Anonymous Network - 3 Node Deploy"
        echo "====================================="
        echo ""
        echo "  Host:    $HOST_IP (floodfill + SOCKS5)"
        echo "  ubuntu1: $VM1_IP (floodfill relay)"
        echo "  ubuntu2: $VM2_IP (floodfill relay)"
        echo ""

        build

        info "Deploying to VMs..."
        deploy_vm "$VM1_IP" "$SCRIPT_DIR/config-ubuntu1.json" "ubuntu1"
        deploy_vm "$VM2_IP" "$SCRIPT_DIR/config-ubuntu2.json" "ubuntu2"

        info "Starting all nodes..."
        # Start VMs first so they're ready when host connects
        start_vm "$VM1_IP" "ubuntu1"
        start_vm "$VM2_IP" "ubuntu2"
        sleep 2
        start_host

        echo ""
        info "All 3 nodes deployed and started!"
        echo ""
        echo "  Your browser SOCKS5 proxy: 127.0.0.1:4447"
        echo ""
        echo "  Check status:  $0 status"
        echo "  Stop all:      $0 stop"
        echo "  View VM logs:  ssh vagrant@$VM1_IP 'tail -f $REMOTE_DIR/router.log'"
        echo "  View host log: tail -f $PROJECT_DIR/router.log"
        echo ""
        ;;

    stop)
        echo "Stopping all nodes..."
        stop_host
        check_deps
        stop_vm "$VM1_IP" "ubuntu1"
        stop_vm "$VM2_IP" "ubuntu2"
        info "All nodes stopped"
        ;;

    status)
        echo ""
        echo "Node Status:"
        echo "-------------"
        status_host
        check_deps
        status_vm "$VM1_IP" "ubuntu1"
        status_vm "$VM2_IP" "ubuntu2"
        echo ""
        ;;

    logs)
        node="${2:-host}"
        case "$node" in
            host)    tail -f "$PROJECT_DIR/router.log" ;;
            ubuntu1) check_deps; remote "$VM1_IP" "tail -f $REMOTE_DIR/router.log" ;;
            ubuntu2) check_deps; remote "$VM2_IP" "tail -f $REMOTE_DIR/router.log" ;;
            *)       echo "Usage: $0 logs [host|ubuntu1|ubuntu2]" ;;
        esac
        ;;

    *)
        echo "Usage: $0 [deploy|stop|status|logs]"
        echo ""
        echo "  deploy  - Build, upload, and start all 3 nodes (default)"
        echo "  stop    - Stop all nodes"
        echo "  status  - Check if nodes are running"
        echo "  logs    - Tail logs: $0 logs [host|ubuntu1|ubuntu2]"
        ;;
esac
