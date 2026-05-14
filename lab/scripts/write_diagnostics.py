"""Helper called by inject_failure.sh to write a diagnostics.json for the current failure state."""
import json
import subprocess
import datetime
import sys
from pathlib import Path

failure_mode = sys.argv[1] if len(sys.argv) > 1 else "unknown"
failure_desc = sys.argv[2] if len(sys.argv) > 2 else ""
osi_layer    = sys.argv[3] if len(sys.argv) > 3 else "unknown"

out_dir = Path("experiments") / failure_mode
out_dir.mkdir(parents=True, exist_ok=True)

def run_ns(ns: str, cmd: str) -> str:
    try:
        r = subprocess.run(
            ["ip", "netns", "exec", ns] + cmd.split(),
            capture_output=True, text=True, timeout=5
        )
        return r.stdout.strip()
    except Exception as e:
        return str(e)

namespaces = ["ns-enterprise", "ns-ce", "ns-satcom", "ns-pop", "ns-cloud", "ns-app"]

routes = {ns: run_ns(ns, "ip route show") for ns in namespaces}
links  = {ns: run_ns(ns, "ip link show") for ns in namespaces}
nat    = run_ns("ns-ce", "iptables -t nat -L POSTROUTING -n")
wg     = run_ns("ns-ce", "wg show")

# Guess metric values from failure mode
telemetry_defaults = {
    "baseline":     {"latency_ms": 90,  "packet_loss_percent": 0.1,  "link_state": "up",       "vpn_state": "not_configured", "bgp_state": "not_configured"},
    "nat_failure":  {"latency_ms": 90,  "packet_loss_percent": 0.1,  "link_state": "up",       "vpn_state": "not_configured", "bgp_state": "not_configured"},
    "vpn_failure":  {"latency_ms": 90,  "packet_loss_percent": 0.1,  "link_state": "up",       "vpn_state": "down",           "bgp_state": "not_configured"},
    "bgp_failure":  {"latency_ms": 90,  "packet_loss_percent": 0.1,  "link_state": "up",       "vpn_state": "not_configured", "bgp_state": "active"},
    "mtu_blackhole":{"latency_ms": 90,  "packet_loss_percent": 0.1,  "link_state": "up",       "vpn_state": "up",             "bgp_state": "not_configured"},
    "packet_loss":  {"latency_ms": 90,  "packet_loss_percent": 5.0,  "link_state": "degraded", "vpn_state": "not_configured", "bgp_state": "not_configured"},
    "high_latency": {"latency_ms": 300, "packet_loss_percent": 0.5,  "link_state": "degraded", "vpn_state": "not_configured", "bgp_state": "not_configured"},
    "dns_failure":  {"latency_ms": 90,  "packet_loss_percent": 0.1,  "link_state": "up",       "vpn_state": "not_configured", "bgp_state": "not_configured"},
    "failover":     {"latency_ms": 0,   "packet_loss_percent": 100.0,"link_state": "down",      "vpn_state": "down",           "bgp_state": "idle"},
}

tm = telemetry_defaults.get(failure_mode, telemetry_defaults["baseline"])
tm.update({
    "signal_quality": 0.0 if tm["link_state"] == "down" else 0.95,
    "downlink_mbps": 0.0 if tm["link_state"] == "down" else 140.0,
    "uplink_mbps": 0.0 if tm["link_state"] == "down" else 28.0,
    "route_count": sum(1 for l in routes.get("ns-ce", "").splitlines() if l.strip()),
    "nat_table_size": 0 if "nat_failure" in failure_mode else 120,
})

diag = {
    "experiment": failure_mode,
    "timestamp": datetime.datetime.utcnow().isoformat(),
    "failure_description": failure_desc,
    "expected_osi_layer": osi_layer,
    "telemetry": tm,
    "routes": routes,
    "interface_status": links,
    "nat_table": nat,
    "vpn_status": {"wireguard": "up" if wg and "peer" in wg else "not_configured"},
    "bgp_status": {},
    "pcap_summary": {"captures": f"captures/{failure_mode}/"},
    "failure_mode": failure_mode,
}

out_path = out_dir / "diagnostics.json"
with out_path.open("w") as f:
    json.dump(diag, f, indent=2)
print(f"[diagnostics] Written: {out_path}")
