#!/usr/bin/env bash
# setup_frr_namespaces.sh — Start FRR daemons inside lab network namespaces
#
# Requires: frr package (apt install frr)
# Run AFTER setup_lab.sh has created the namespaces and veth pairs.
#
# FRR 8.x+ uses per-VRF/namespace support via -N flag for vtysh.
# Each namespace gets: zebra (FIB manager) + bgpd (BGP daemon)
#
# Daemon sockets land in /var/run/frr/<namespace>/ so vtysh can target them:
#   vtysh -N ns-ce -c "show bgp summary"

set -euo pipefail

FRR_CONFIG_DIR="$(dirname "$0")/../frr"
FRR_RUN_BASE="/var/run/frr"
FRR_LOG_BASE="/var/log/frr"
FRR_BIN_DIR="/usr/lib/frr"   # Debian/Ubuntu default
FRR_ETC_DIR="/etc/frr"

# Namespaces that run BGP
BGP_NAMESPACES=("ns-ce" "ns-pop" "ns-cloud")

if [ "$(uname)" != "Linux" ]; then
    echo "ERROR: FRR namespace setup requires Linux."
    exit 1
fi

if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: Must run as root."
    exit 1
fi

if ! command -v zebra &>/dev/null && ! [ -f "$FRR_BIN_DIR/zebra" ]; then
    echo "ERROR: FRR not found. Install with: sudo apt install frr frr-pythontools"
    exit 1
fi

ZEBRA="${FRR_BIN_DIR}/zebra"
BGPD="${FRR_BIN_DIR}/bgpd"
[ ! -f "$ZEBRA" ] && ZEBRA="zebra"
[ ! -f "$BGPD"  ] && BGPD="bgpd"

stop_frr_in_ns() {
    local ns="$1"
    echo "[frr] Stopping FRR in $ns..."
    # Kill any existing zebra/bgpd running with this namespace marker
    pkill -f "zebra.*$ns" 2>/dev/null || true
    pkill -f "bgpd.*$ns"  2>/dev/null || true
    sleep 0.5
}

start_frr_in_ns() {
    local ns="$1"
    local config_dir="$FRR_CONFIG_DIR"

    # Map namespace name to frr config subdirectory
    case "$ns" in
        ns-ce)     config_dir="$FRR_CONFIG_DIR/ce-router"     ;;
        ns-pop)    config_dir="$FRR_CONFIG_DIR/pop-router"    ;;
        ns-cloud)  config_dir="$FRR_CONFIG_DIR/cloud-router"  ;;
        *)
            echo "[frr] No FRR config for $ns — skipping."
            return 0
            ;;
    esac

    if [ ! -d "$config_dir" ]; then
        echo "[frr] Config dir $config_dir not found — skipping $ns."
        return 0
    fi

    local run_dir="$FRR_RUN_BASE/$ns"
    local log_dir="$FRR_LOG_BASE/$ns"
    mkdir -p "$run_dir" "$log_dir"
    chown frr:frr "$run_dir" "$log_dir" 2>/dev/null || true

    echo "[frr] Starting zebra in $ns..."
    ip netns exec "$ns" "$ZEBRA" \
        -d \
        -f "$config_dir/frr.conf" \
        --pid_file "$run_dir/zebra.pid" \
        --vty_socket "$run_dir" \
        -A 127.0.0.1 \
        -z "$run_dir/zserv.api" \
        -l "$log_dir/zebra.log" \
        2>>"$log_dir/zebra.log" || {
            echo "[frr] WARNING: zebra failed to start in $ns"
            return 1
        }

    sleep 0.3

    echo "[frr] Starting bgpd in $ns..."
    ip netns exec "$ns" "$BGPD" \
        -d \
        -f "$config_dir/frr.conf" \
        --pid_file "$run_dir/bgpd.pid" \
        --vty_socket "$run_dir" \
        -A 127.0.0.1 \
        -z "$run_dir/zserv.api" \
        -l "$log_dir/bgpd.log" \
        2>>"$log_dir/bgpd.log" || {
            echo "[frr] WARNING: bgpd failed to start in $ns"
            return 1
        }

    echo "[frr] FRR running in $ns (run_dir=$run_dir)"
}

wait_for_bgp_established() {
    local ns="$1"
    local max_wait=30
    local elapsed=0
    echo "[frr] Waiting for BGP ESTABLISHED in $ns..."
    while [ "$elapsed" -lt "$max_wait" ]; do
        output=$(ip netns exec "$ns" vtysh -N "$ns" -c "show bgp summary" 2>/dev/null || true)
        if echo "$output" | grep -q "Established"; then
            echo "[frr] BGP ESTABLISHED in $ns (${elapsed}s)"
            return 0
        fi
        sleep 2
        elapsed=$((elapsed + 2))
    done
    echo "[frr] WARNING: BGP did not reach Established in $ns within ${max_wait}s"
    return 1
}

echo "=== FRR Namespace Setup ==="
echo "Config dir: $FRR_CONFIG_DIR"
echo "Run dir:    $FRR_RUN_BASE"
echo ""

for ns in "${BGP_NAMESPACES[@]}"; do
    # Verify namespace exists
    if ! ip netns list | grep -q "^$ns"; then
        echo "[frr] Namespace $ns not found — run setup_lab.sh first."
        continue
    fi
    stop_frr_in_ns "$ns"
    start_frr_in_ns "$ns"
done

echo ""
echo "Waiting 5s for BGP sessions to initialize..."
sleep 5

for ns in "${BGP_NAMESPACES[@]}"; do
    if ip netns list | grep -q "^$ns"; then
        wait_for_bgp_established "$ns" || true
    fi
done

echo ""
echo "=== FRR Status ==="
echo "Check BGP:   sudo vtysh -N ns-ce -c 'show bgp summary'"
echo "Check routes: sudo ip netns exec ns-ce ip route show proto bgp"
echo "Logs:        tail -f $FRR_LOG_BASE/ns-ce/bgpd.log"
