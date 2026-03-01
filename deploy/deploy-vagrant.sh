#!/bin/bash
#
# deploy-vagrant.sh - Deploy anonymous network using vagrant ssh (no sshpass needed)
#
# Network topology (3 peers):
#   Host    (192.168.56.1)   - floodfill + SOCKS5 proxy (your browser)
#   ubuntu1 (192.168.56.101) - floodfill relay
#   ubuntu2 (192.168.56.102) - floodfill relay
#
# Usage:
#   ./deploy/deploy-vagrant.sh              # full deploy
#   ./deploy/deploy-vagrant.sh stop         # stop all
#   ./deploy/deploy-vagrant.sh status       # check all
#   ./deploy/deploy-vagrant.sh logs ubuntu1 # tail logs

set +e  # Don't exit on error — vagrant ssh returns 255 on connection close

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BINARY_NAME="anon-router"
REMOTE_DIR="/opt/anon-router"

# Path to Vagrantfile directory
VAGRANT_DIR="/home/DrFlachAdmin/Desktop/lfcs/lfcs/all-courses"

HOST_IP="192.168.56.1"

info()  { echo -e "\033[1;32m[INFO]\033[0m  $*"; }
warn()  { echo -e "\033[1;33m[WARN]\033[0m  $*"; }
error() { echo -e "\033[1;31m[ERROR]\033[0m $*"; }

vssh() {
    local vm="$1"; shift
    local rc
    (cd "$VAGRANT_DIR" && vagrant ssh "$vm" -c "$*") 2>/dev/null
    rc=$?
    # vagrant ssh returns 255 on clean connection close — treat as success
    if [ $rc -eq 255 ]; then return 0; fi
    return $rc
}

# Get SSH port for a VM from vagrant ssh-config
_vm_port() {
    case "$1" in
        ubuntu1) echo 2222 ;;
        ubuntu2) echo 2200 ;;
    esac
}

# Get SSH private key path for a VM
_vm_key() {
    echo "$VAGRANT_DIR/.vagrant/machines/$1/virtualbox/private_key"
}

vscp() {
    local file="$1" vm="$2" dest="$3"
    local port key
    port=$(_vm_port "$vm")
    key=$(_vm_key "$vm")

    # If cached port/key don't work, fall back to parsing ssh-config
    if [ -z "$port" ] || [ ! -f "$key" ]; then
        local cfg
        cfg=$(cd "$VAGRANT_DIR" && vagrant ssh-config "$vm" 2>/dev/null)
        port=$(echo "$cfg" | awk '/Port/{print $2; exit}')
        key=$(echo "$cfg" | awk '/IdentityFile/{print $2; exit}')
    fi

    scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR \
        -P "$port" -i "$key" "$file" "vagrant@127.0.0.1:$dest"
}

check_vms() {
    cd "$VAGRANT_DIR"
    local status
    status=$(vagrant status --machine-readable 2>/dev/null | grep ',state,' | grep -v ',state_human,')
    
    local all_running=true
    for vm in ubuntu1 ubuntu2; do
        local state
        state=$(echo "$status" | grep "^.*,$vm,state," | cut -d',' -f4)
        if [ "$state" != "running" ]; then
            warn "$vm is $state"
            all_running=false
        fi
    done

    if [ "$all_running" = false ]; then
        echo ""
        error "VMs are not running. Start them first:"
        echo "  cd $VAGRANT_DIR && vagrant up"
        echo ""
        exit 1
    fi
    info "Both VMs are running"
}

build() {
    info "Building binary for linux/amd64..."
    cd "$PROJECT_DIR"
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o "$BINARY_NAME" ./cmd/router/ || { error "Build failed"; exit 1; }
    info "Build complete"
}

deploy_vm() {
    local vm="$1" config_file="$2"

    info "Deploying to $vm..."

    # Create directory
    vssh "$vm" "sudo mkdir -p $REMOTE_DIR && sudo chown vagrant:vagrant $REMOTE_DIR"

    # Stop if running
    vssh "$vm" "sudo pkill -f '$BINARY_NAME' 2>/dev/null; true"
    sleep 1

    # Upload binary + config
    vscp "$PROJECT_DIR/$BINARY_NAME" "$vm" "$REMOTE_DIR/$BINARY_NAME" || { error "Failed to upload binary to $vm"; return 1; }
    vscp "$config_file" "$vm" "$REMOTE_DIR/config.json" || { error "Failed to upload config to $vm"; return 1; }

    # Make executable
    vssh "$vm" "chmod +x $REMOTE_DIR/$BINARY_NAME"

    info "Deployed to $vm"
}

start_vm() {
    local vm="$1"

    info "Starting $vm..."
    vssh "$vm" "sudo pkill -f '$BINARY_NAME' 2>/dev/null; true"
    sleep 1
    # Start with nohup in the same SSH session, sleep to let it init
    vssh "$vm" "cd $REMOTE_DIR && nohup ./$BINARY_NAME -config config.json > router.log 2>&1 & sleep 2 && pgrep -f '$BINARY_NAME' > /dev/null"
    sleep 1

    # Verify independently
    vssh "$vm" "pgrep -f '$BINARY_NAME' > /dev/null"
    if [ $? -eq 0 ]; then
        info "$vm is running"
    else
        error "$vm failed to start. View logs:"
        echo "  cd $VAGRANT_DIR && vagrant ssh $vm -c 'cat $REMOTE_DIR/router.log'"
    fi
}

stop_vm() {
    local vm="$1"
    info "Stopping $vm..."
    vssh "$vm" "sudo pkill -f '$BINARY_NAME' 2>/dev/null; true"
}

status_vm() {
    local vm="$1"
    vssh "$vm" "pgrep -f '$BINARY_NAME' > /dev/null"
    if [ $? -eq 0 ]; then
        echo "  $vm: RUNNING"
        vssh "$vm" "tail -3 $REMOTE_DIR/router.log 2>/dev/null" | sed 's/^/    /'
    else
        echo "  $vm: STOPPED"
    fi
}

start_host() {
    info "Starting host router..."
    pkill -f "anon-router" 2>/dev/null || true
    sleep 1

    cp "$SCRIPT_DIR/config-host.json" "$PROJECT_DIR/config.json"

    cd "$PROJECT_DIR"
    nohup ./"$BINARY_NAME" -config config.json > router.log 2>&1 &
    sleep 3

    if pgrep -f "anon-router" &>/dev/null; then
        info "Host router running (SOCKS5 on 127.0.0.1:4447)"
    else
        error "Host failed to start. Check: $PROJECT_DIR/router.log"
    fi
}

stop_host() {
    info "Stopping host router..."
    pkill -f "anon-router" 2>/dev/null || true
}

status_host() {
    if pgrep -f "anon-router" &>/dev/null; then
        echo "  host ($HOST_IP): RUNNING"
        tail -3 "$PROJECT_DIR/router.log" 2>/dev/null | sed 's/^/    /'
    else
        echo "  host ($HOST_IP): STOPPED"
    fi
}

# ---- Main ----

case "${1:-deploy}" in
    deploy)
        echo ""
        echo "========================================"
        echo "  Anonymous Network - 3 Node Deploy"
        echo "========================================"
        echo ""

        check_vms
        build

        deploy_vm "ubuntu1" "$SCRIPT_DIR/config-ubuntu1.json"
        deploy_vm "ubuntu2" "$SCRIPT_DIR/config-ubuntu2.json"

        info "Starting all nodes (VMs first, then host)..."
        start_vm "ubuntu1"
        start_vm "ubuntu2"
        sleep 2
        start_host

        echo ""
        echo "========================================"
        info "All 3 nodes are up!"
        echo ""
        echo "  Browser proxy: SOCKS5 127.0.0.1:4447"
        echo ""
        echo "  Commands:"
        echo "    $0 status        - check all nodes"
        echo "    $0 stop          - stop all nodes"
        echo "    $0 logs ubuntu1  - tail VM logs"
        echo "    $0 logs host     - tail host logs"
        echo "========================================"
        echo ""
        ;;

    stop)
        echo "Stopping all nodes..."
        stop_host
        check_vms 2>/dev/null || true
        stop_vm "ubuntu1" 2>/dev/null || true
        stop_vm "ubuntu2" 2>/dev/null || true
        info "All nodes stopped"
        ;;

    status)
        echo ""
        echo "Node Status:"
        echo "-------------"
        status_host
        status_vm "ubuntu1"
        status_vm "ubuntu2"
        echo ""
        ;;

    logs)
        node="${2:-host}"
        case "$node" in
            host)    tail -f "$PROJECT_DIR/router.log" ;;
            ubuntu1) cd "$VAGRANT_DIR" && vagrant ssh ubuntu1 -c "tail -f $REMOTE_DIR/router.log" ;;
            ubuntu2) cd "$VAGRANT_DIR" && vagrant ssh ubuntu2 -c "tail -f $REMOTE_DIR/router.log" ;;
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
