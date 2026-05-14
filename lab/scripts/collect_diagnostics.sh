#!/usr/bin/env bash
# Collects full diagnostic snapshot across all namespaces.
# Output: experiments/<latest>/diagnostics.json
set -euo pipefail

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
OUT_DIR="experiments/snapshot_${TIMESTAMP}"
mkdir -p "$OUT_DIR"

log() { echo "[collect] $*"; }

log "Collecting diagnostics at $TIMESTAMP..."

collect_ns() {
    local ns=$1
    local out="$OUT_DIR/${ns}"
    mkdir -p "$out"
    ip netns exec "$ns" ip route show > "$out/routes.txt" 2>/dev/null || echo "unavailable" > "$out/routes.txt"
    ip netns exec "$ns" ip link show > "$out/links.txt" 2>/dev/null || echo "unavailable" > "$out/links.txt"
    ip netns exec "$ns" ip addr show > "$out/addrs.txt" 2>/dev/null || echo "unavailable" > "$out/addrs.txt"
    ip netns exec "$ns" iptables -L -n -v 2>/dev/null > "$out/iptables.txt" || echo "unavailable" > "$out/iptables.txt"
    ip netns exec "$ns" iptables -t nat -L -n -v 2>/dev/null > "$out/iptables_nat.txt" || echo "unavailable" > "$out/iptables_nat.txt"
}

for ns in ns-enterprise ns-ce ns-satcom ns-pop ns-cloud ns-app; do
    collect_ns "$ns" && log "Collected: $ns"
done

# Capture 5s of traffic on SATCOM WAN
PCAP_DIR="captures/snapshot_${TIMESTAMP}"
mkdir -p "$PCAP_DIR"
log "Short packet capture on SATCOM WAN..."
ip netns exec ns-satcom tcpdump -q -i eth0 -w "$PCAP_DIR/satcom_wan.pcap" -G 5 -W 1 &>/dev/null &
ip netns exec ns-enterprise ping -c 20 -i 0.1 192.168.100.10 > /dev/null 2>&1 || true
wait

# Build diagnostics.json
python3 -c "
import json, os, datetime, glob

def read(path):
    try:
        with open(path) as f: return f.read().strip()
    except: return 'unavailable'

namespaces = ['ns-enterprise','ns-ce','ns-satcom','ns-pop','ns-cloud','ns-app']
out_dir = '$OUT_DIR'

routes = {ns: read(f'{out_dir}/{ns}/routes.txt') for ns in namespaces}
links  = {ns: read(f'{out_dir}/{ns}/links.txt')  for ns in namespaces}
nat    = read(f'{out_dir}/ns-ce/iptables_nat.txt')

diag = {
    'experiment': 'snapshot_$TIMESTAMP',
    'timestamp': datetime.datetime.utcnow().isoformat(),
    'telemetry': {
        'latency_ms': None,
        'packet_loss_percent': None,
        'signal_quality': None,
        'link_state': 'unknown',
        'vpn_state': 'unknown',
        'bgp_state': 'unknown',
        'route_count': sum(1 for l in routes.get('ns-ce','').splitlines() if l.strip())
    },
    'routes': routes,
    'interface_status': links,
    'nat_table': nat,
    'vpn_status': {'wireguard': 'unknown', 'ipsec': 'unknown'},
    'bgp_status': {},
    'pcap_summary': {'captures': 'captures/snapshot_$TIMESTAMP/'},
    'failure_mode': 'unknown'
}

out_path = f'{out_dir}/diagnostics.json'
with open(out_path, 'w') as f:
    json.dump(diag, f, indent=2)
print(f'[collect] diagnostics.json -> {out_path}')
"

log "Done. Diagnostics: $OUT_DIR/diagnostics.json"
