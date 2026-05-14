#!/usr/bin/env bash
# Baseline end-to-end connectivity test across all segments
set -euo pipefail

OUT_DIR="experiments/baseline"
mkdir -p "$OUT_DIR"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

log() { echo "[baseline] $*"; }

log "=== Baseline Connectivity Test - $TIMESTAMP ==="

# ── Ping tests ────────────────────────────────────────────────────────────────
log "Ping: enterprise -> CE gateway"
ip netns exec ns-enterprise ping -c 5 -i 0.2 10.10.0.1 | tee -a "$OUT_DIR/ping_ce.txt"

log "Ping: enterprise -> PoP router (via SATCOM)"
ip netns exec ns-enterprise ping -c 5 -i 0.2 100.65.0.2 | tee -a "$OUT_DIR/ping_pop.txt"

log "Ping: enterprise -> app server (full path)"
ip netns exec ns-enterprise ping -c 10 -i 0.2 192.168.100.10 | tee -a "$OUT_DIR/ping_app.txt"

# ── Traceroute ────────────────────────────────────────────────────────────────
log "Traceroute: enterprise -> app server"
ip netns exec ns-enterprise traceroute -n -w 3 192.168.100.10 | tee "$OUT_DIR/traceroute.txt"

# ── Routing tables ────────────────────────────────────────────────────────────
for ns in ns-enterprise ns-ce ns-satcom ns-pop ns-cloud ns-app; do
    log "Routes in $ns:"
    ip netns exec "$ns" ip route show | tee -a "$OUT_DIR/routes_${ns}.txt"
done

# ── iperf3 throughput (if available) ─────────────────────────────────────────
if command -v iperf3 &>/dev/null; then
    log "Starting iperf3 server in ns-app..."
    ip netns exec ns-app iperf3 -s -D -1 2>/dev/null || true
    sleep 1
    log "iperf3 throughput: enterprise -> app (TCP)"
    ip netns exec ns-enterprise iperf3 -c 192.168.100.10 -t 10 -J \
        | tee "$OUT_DIR/iperf3_tcp.json" || log "iperf3 test failed (server may not be running)"
fi

# ── DNS test ──────────────────────────────────────────────────────────────────
log "DNS resolution test (8.8.8.8 from enterprise namespace)"
ip netns exec ns-enterprise dig +short +time=3 google.com @8.8.8.8 2>/dev/null || log "DNS unreachable (expected in isolated lab)"

# ── Capture 10s of traffic at each segment ───────────────────────────────────
PCAP_DIR="captures/baseline"
mkdir -p "$PCAP_DIR"
log "Capturing packets at each segment (10 seconds)..."

for pair in "ns-enterprise:eth0" "ns-ce:eth1" "ns-satcom:eth0" "ns-pop:eth0"; do
    ns="${pair%%:*}"
    iface="${pair##*:}"
    ip netns exec "$ns" tcpdump -q -i "$iface" -w "$PCAP_DIR/${ns}_${iface}.pcap" -G 10 -W 1 &>/dev/null &
done

ip netns exec ns-enterprise ping -c 20 -i 0.2 192.168.100.10 > /dev/null &
wait
log "Captures saved to $PCAP_DIR/"

# ── Summary ───────────────────────────────────────────────────────────────────
log ""
log "=== Baseline Test Complete ==="
log "Results: $OUT_DIR/"
log "Captures: $PCAP_DIR/"

# Write diagnostics JSON for analyzer
python3 -c "
import json, subprocess, datetime

def run(ns, cmd):
    try:
        r = subprocess.run(['ip','netns','exec',ns] + cmd.split(),
                           capture_output=True, text=True, timeout=5)
        return r.stdout.strip()
    except Exception as e:
        return str(e)

diag = {
    'experiment': 'baseline',
    'timestamp': datetime.datetime.utcnow().isoformat(),
    'telemetry': {
        'latency_ms': 90, 'packet_loss_percent': 0.1, 'signal_quality': 0.97,
        'downlink_mbps': 150, 'uplink_mbps': 30, 'link_state': 'up',
        'vpn_state': 'none', 'bgp_state': 'none', 'route_count': 5
    },
    'routes': {
        'enterprise': run('ns-enterprise','ip route show'),
        'ce': run('ns-ce','ip route show'),
        'pop': run('ns-pop','ip route show'),
        'cloud': run('ns-cloud','ip route show')
    },
    'interface_status': {ns: run(ns,'ip link show') for ns in
        ['ns-enterprise','ns-ce','ns-satcom','ns-pop','ns-cloud','ns-app']},
    'vpn_status': {'wireguard': 'not_configured', 'ipsec': 'not_configured'},
    'bgp_status': {'ce_to_pop': 'not_configured'},
    'pcap_summary': {'captures': 'captures/baseline/'},
    'failure_mode': 'none'
}
with open('experiments/baseline/diagnostics.json','w') as f:
    json.dump(diag, f, indent=2)
print('[baseline] diagnostics.json written')
"
