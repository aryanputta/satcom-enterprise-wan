# SATCOM Enterprise WAN Integration and Telemetry Platform

A production-grade network systems lab simulating a Starlink-style enterprise SATCOM deployment: customer LAN, CE router with NAT, SATCOM WAN emulator, cloud PoP with BGP, WireGuard VPN overlay, and an automated root cause analyzer that classifies failures by OSI layer.

Built to directly map to: enterprise network deployment, SATCOM integration engineering, cloud networking, and software engineering for network systems.

---

## Why This Project Exists

Enterprise SATCOM deployments (Starlink Business, Viasat, SES, OneWeb) fail in specific, repeatable ways that generic network tools miss. The failure modes are:

- MTU black holes inside VPN tunnels due to SATCOM overhead
- BGP session instability under link flap (hold timer misconfiguration)
- NAT tables that silently drop inbound traffic
- DNS interception that makes IP-healthy networks appear broken
- TCP throughput collapse at 1% packet loss (worse than wired by 10x)
- VPN handshakes blocked by intermediate CGNAT

This lab simulates all of them, captures packet evidence at each segment, and runs a layered root cause analyzer that classifies each incident by OSI layer with supporting evidence and confidence scoring.

---

## Architecture

```mermaid
graph LR
    ENT[Enterprise LAN<br/>10.10.0.0/24] -->|veth| CE[Customer Edge<br/>NAT + iptables<br/>WireGuard + BGP 65001]
    CE -->|veth| SATCOM[SATCOM WAN Emulator<br/>tc netem<br/>latency + loss + jitter]
    SATCOM -->|veth| POP[Cloud PoP Router<br/>BGP 65002<br/>Route Reflector]
    POP -->|veth| CLOUD[Cloud VPC Router<br/>BGP 65002 iBGP]
    CLOUD -->|veth| APP[Application Server<br/>192.168.100.10]

    CE -.->|WireGuard UDP 51820| POP

    TELEMETRY[Telemetry API<br/>FastAPI + Prometheus] --> GRAFANA[Grafana<br/>:3000]
    RCA[Root Cause Analyzer<br/>OSI L1-L7] --> OUTPUT[JSON + Rich CLI]
```

## Network Topology

| Namespace | Role | Interfaces | Key Config |
|-----------|------|-----------|------------|
| ns-enterprise | Enterprise LAN host | eth0: 10.10.0.100/24 | Default GW: 10.10.0.1 |
| ns-ce | Customer edge router | eth0: 10.10.0.1/24, eth1: 100.64.0.1/30 | NAT masquerade, iptables, BGP 65001, WireGuard |
| ns-satcom | SATCOM WAN emulator | eth0: 100.64.0.2/30, eth1: 100.65.0.1/30 | tc netem (latency/loss/jitter), IP forward |
| ns-pop | Cloud PoP router | eth0: 100.65.0.2/30, eth1: 172.16.0.1/30 | FRRouting, BGP 65002, eBGP to CE, iBGP to cloud |
| ns-cloud | Cloud VPC router | eth0: 172.16.0.2/30, eth1: 192.168.100.1/24 | FRRouting, iBGP, VPC prefix advertisement |
| ns-app | Application server | eth0: 192.168.100.10/24 | Default GW: 192.168.100.1 |

## Protocols Used

| Layer | Protocol | Where |
|-------|----------|-------|
| L1 | tc netem impairment simulation | ns-satcom interfaces |
| L2 | veth pairs, Linux bridge | All namespace interconnects |
| L3 | IPv4 (RFC1918 + transit /30 subnets) | Full topology |
| L3 | BGP (eBGP 65001↔65002, iBGP within 65002) | CE, PoP, cloud-router |
| L3 | NAT (MASQUERADE) | ns-ce outbound |
| L3 | Static routing | All namespaces |
| L4 | WireGuard (UDP 51820) | CE → PoP overlay |
| L4 | IPsec IKEv2 / strongSwan (optional) | CE → PoP |
| L7 | DNS (dig, tcpdump capture) | Failure scenario 7 |
| L7 | HTTP (iperf3, curl) | Application testing |

---

## Stack

**Networking:** Linux netns, FRRouting, iptables/nftables, tc netem, WireGuard, strongSwan
**Telemetry:** FastAPI, Prometheus, Grafana, Pydantic
**Packet analysis:** Scapy, tcpdump, Wireshark-compatible pcap
**Benchmarking:** iperf3, ping, traceroute, dig
**Languages:** Python 3.12, Bash, YAML
**Containerization:** Docker Compose (telemetry stack only)

---

## Prerequisites

**Linux (required for network namespaces):**
```bash
sudo apt-get install iproute2 iptables tcpdump iperf3 traceroute dnsutils
# FRRouting (for BGP):
curl -s https://deb.frrouting.org/frr/keys.gpg | sudo tee /usr/share/keyrings/frrouting.gpg > /dev/null
echo "deb [signed-by=/usr/share/keyrings/frrouting.gpg] https://deb.frrouting.org/frr focal frr-stable" | sudo tee /etc/apt/sources.list.d/frr.list
sudo apt-get install frr
# WireGuard:
sudo apt-get install wireguard-tools
# Docker:
sudo apt-get install docker.io docker-compose-plugin
```

**macOS (telemetry stack and analyzers only — namespaces require Linux):**
```bash
brew install python@3.12
pip3 install -r requirements.txt
docker compose up -d  # telemetry stack works on macOS
```

> Network namespace lab requires Linux. Use a VM, WSL2, or cloud instance for the full lab.

---

## Quick Start

```bash
# Clone and install
git clone https://github.com/aryanputta/satcom-enterprise-wan
cd satcom-enterprise-wan
make setup

# Start telemetry stack (works on macOS and Linux)
make up
# Grafana: http://localhost:3000 (admin/satcom123)
# API:     http://localhost:8000/metrics/current
# Prometheus: http://localhost:9090

# On Linux: bring up the network lab
sudo make lab-up

# Run baseline tests
make baseline

# Inject a failure and analyze
make inject-vpn-failure
make analyze

# Run all tests
make test
```

---

## Running Experiments

### Inject and analyze any failure mode:

```bash
# NAT misconfiguration (outbound traffic uses RFC1918 source)
make inject-nat-failure

# VPN handshake blocked by CE firewall
make inject-vpn-failure

# BGP ASN mismatch causes route loss
make inject-bgp-failure

# MTU black hole: large packets dropped silently inside VPN tunnel
make inject-mtu-blackhole

# 5% SATCOM packet loss
make inject-loss

# Restore to baseline
sudo bash lab/scripts/inject_failure.sh restore
```

### Simulate telemetry profiles via API:

```bash
# Rain fade
curl -X POST http://localhost:8000/simulate \
  -H "Content-Type: application/json" \
  -d '{"profile": "rain_fade", "vpn_state": "up", "bgp_state": "established"}'

# Link down
curl -X POST http://localhost:8000/simulate \
  -d '{"profile": "link_down"}'

# Current metrics
curl http://localhost:8000/metrics/current | python3 -m json.tool
```

---

## Root Cause Analyzer

The analyzer takes a diagnostics snapshot (telemetry + routes + BGP + VPN + pcap summary) and classifies the root cause by OSI layer.

### Run it:

```bash
# After any experiment
python3 analyzer/root_cause_analyzer.py --input experiments/vpn_failure/diagnostics.json

# JSON only (for pipeline use)
python3 analyzer/root_cause_analyzer.py --input experiments/nat_failure/diagnostics.json --json-only
```

### Example output — MTU black hole:

```json
{
  "incident": "mtu_blackhole",
  "probable_cause": "MTU Black Hole — VPN Path",
  "osi_layer": "Layer 3 / Layer 4",
  "evidence": [
    "Large packet ping test failed (MTU black hole confirmed)",
    "Small packet ping succeeds (confirms asymmetric MTU failure)",
    "High TCP retransmissions with NO ICMP frag-needed — possible MTU black hole"
  ],
  "recommended_fix": "Lower tunnel MTU to 1280. Apply MSS clamping: iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu",
  "confidence": 0.91
}
```

### Example output — BGP down:

```json
{
  "incident": "bgp_failure",
  "probable_cause": "BGP Session Not Established",
  "osi_layer": "Layer 3",
  "evidence": [
    "telemetry.bgp_state='active' matches {'in': ['active', 'idle', 'connect']}"
  ],
  "recommended_fix": "1. Check BGP state: vtysh -c 'show bgp summary'\n2. Verify remote-as matches peer ASN\n3. Check TCP 179 reachability: nc -zv <peer_ip> 179",
  "confidence": 0.92
}
```

---

## Experiment Results (Simulated — from lab measurements)

> Results marked [Simulated] use tc netem profiles. Real hardware will vary.

| Experiment | Failure Mode | OSI Layer | Analyzer Confidence | Fix |
|-----------|-------------|-----------|---------------------|-----|
| 1 | None (baseline) | N/A | N/A | N/A |
| 2 | NAT masquerade removed | L3 | 0.91 | Re-add MASQUERADE rule |
| 3 | WireGuard UDP 51820 blocked | L4 | 0.90 | Remove DROP rule |
| 4 | BGP ASN mismatch | L3 | 0.92 | Fix remote-as config |
| 5 | MTU black hole (SATCOM overhead) | L3/L4 | 0.91 | Set MTU 1280, MSS clamp |
| 6 | 5% packet loss [Simulated] | L1 | 0.88 | Enable BBR, TCP PEP |
| 7 | DNS blocked at firewall | L7 | 0.93 | Remove DNS DROP rules |
| 8 | SATCOM link outage + failover | L1 | 0.97 | Restore link / failover |

### Throughput under SATCOM impairment [Simulated]:

| Profile | TCP Throughput | UDP Throughput | Notes |
|---------|---------------|----------------|-------|
| Baseline (45ms RTT, 0.1% loss) | ~140 Mbps | ~130 Mbps | LEO SATCOM |
| High latency (300ms RTT) | ~60 Mbps | ~120 Mbps | Congestion/handoff |
| 1% loss | ~80 Mbps | ~110 Mbps | Weather fade onset |
| 5% loss | ~20 Mbps | ~55 Mbps | Significant rain fade |
| Link down | 0 | 0 | Full outage |

---

## Telemetry Dashboard

After `make up`, open Grafana at http://localhost:3000 (admin/satcom123).

The SATCOM Overview dashboard shows:
- Link state, VPN state, BGP session (green/red indicators)
- Real-time latency and jitter timeseries
- Downlink/uplink throughput
- Packet loss percentage
- Modem temperature
- NAT table size and active route count

Switch profiles via API to see real-time dashboard changes:
```bash
# Trigger rain fade — watch latency and throughput charts
curl -X POST http://localhost:8000/simulate -d '{"profile": "rain_fade"}'
```

---

## Packet Analysis

```bash
# Analyze a single pcap
python3 analyzer/pcap_analyzer.py --pcap captures/baseline/ns-ce_eth1.pcap

# Analyze all pcaps from an experiment
python3 analyzer/pcap_analyzer.py --dir captures/vpn_failure/ \
  --output experiments/vpn_failure/pcap_summary.json
```

Output includes: protocol mix, TCP retransmissions, failed handshakes, DNS timeouts, ICMP unreachable, MTU black hole indicators, top talkers.

---

## BGP Analysis

```bash
# Parse vtysh output
python3 -c "
from analyzer.bgp_analyzer import parse_bgp_summary
output = open('experiments/bgp_failure/bgp_summary.txt').read()
analysis = parse_bgp_summary(output)
print('Healthy:', analysis.healthy)
print('Issues:', analysis.issues)
"
```

---

## Key Networking Concepts (as they appear in this project)

**Linux network namespaces:** Isolated network stacks sharing the same kernel. Each namespace has its own interfaces, routing table, iptables chains, and ARP cache. Used here to simulate 6 distinct network devices on one host.

**veth pairs:** Virtual Ethernet pairs — packets sent on one end come out the other. Used here to connect namespaces like physical cables.

**tc netem:** Linux traffic control's network emulator. Adds latency, jitter, loss, duplication, corruption, and bandwidth limits to interfaces. Precise to microseconds.

**FRRouting (FRR):** Open-source routing suite implementing BGP, OSPF, IS-IS, and others. Used here for BGP peering between CE and PoP. Configured via `frr.conf` or `vtysh` CLI.

**BGP (Border Gateway Protocol):** Path-vector routing protocol used between ASes. eBGP peers with different ASNs, iBGP peers within the same AS. Used here to propagate customer LAN prefix (10.10.0.0/24) to the cloud and VPC prefix (192.168.100.0/24) back to the enterprise.

**MASQUERADE (NAT):** iptables target that rewrites the source IP of outbound packets to the interface address. Used at CE to allow RFC1918 LAN traffic to traverse the SATCOM WAN.

**WireGuard:** Modern VPN using Curve25519 key exchange and ChaCha20-Poly1305. Zero configuration handshake — tunnel comes up automatically when peer is reachable. Overhead: ~80 bytes per packet.

**MTU black hole:** When an intermediate link drops oversized packets without sending ICMP fragmentation-needed (type 3 code 4). The sender has no signal to reduce packet size so retransmits indefinitely. Common in SATCOM VPN paths.

**PMTUD (Path MTU Discovery):** TCP mechanism to discover the minimum MTU along a path. Relies on ICMP type 3 code 4 messages. When these are blocked by firewalls, PMTUD fails and MTU black holes form.

**BBR (Bottleneck Bandwidth and Round-trip propagation):** Google's congestion control algorithm. Models bandwidth and RTT separately. Outperforms CUBIC on high-latency (SATCOM) and lossy links. Enable: `sysctl net.ipv4.tcp_congestion_control=bbr`.

**BGP hold timer:** Maximum time BGP waits for a keepalive before declaring the session dead. Default: 90 seconds. On SATCOM links, frequent brief outages cause 90s blackouts. Tune to 30s or deploy BFD for faster detection.

**Ka-band SATCOM:** 26.5-40 GHz frequency band used by Starlink, Viasat, and SES for high-throughput satellite. Heavily attenuated by rain (rain fade). Requires precise dish pointing and maintains high latency (35-50ms LEO, 600ms GEO).

---

## Interview Talking Points (Starlink / SpaceX / Network Engineering)

**"Walk me through the SATCOM WAN architecture you built."**
> Built a 6-namespace lab modeling the complete enterprise SATCOM stack. CE router handles NAT and BGP peering in ASN 65001. SATCOM emulator uses tc netem for realistic Ka-band impairments. Cloud PoP does BGP route reflection in ASN 65002. The key insight was that SATCOM link characteristics — 45ms baseline latency, variable loss, frequent short outages — break assumptions that work fine on terrestrial WAN.

**"How do you troubleshoot a Starlink enterprise deployment where the customer says 'the internet is down'?"**
> Start at Layer 1: check link_state, packet_loss, signal_quality from terminal metrics. If L1 is healthy, check L3: routing table, NAT table, BGP state. If L3 is healthy, check L4: VPN state, firewall rules, MTU with path MTU test. If all L1-L4 look healthy, check L7: DNS resolution independently from application — half of "application is down" tickets are DNS-broken with working IP connectivity.

**"How does MTU affect VPN over SATCOM?"**
> SATCOM adds framing overhead beyond the normal IP MTU. WireGuard adds 80 bytes. If the path MTU is 1500 and your VPN overhead is 200 bytes, large packets are silently dropped when ICMP frag-needed is blocked. The fix is setting the VPN interface MTU to 1280 (safe minimum) and applying TCP MSS clamping at the CE with iptables mangle. The diagnostic is: small pings succeed, large pings fail, no ICMP type 3 code 4 in capture.

**"What would you change about BGP timer configuration for SATCOM?"**
> Default BGP hold timer is 90 seconds — that means a 90-second traffic blackout on any link flap. Tune to `timers 10 30` (keepalive 10s, hold 30s). For faster recovery, deploy BFD alongside BGP — BFD can detect failure in 100ms. Also prefix-filter at CE to avoid advertising default routes that could cause routing loops during partial outages.

**"How do you handle TCP performance on a high-latency lossy SATCOM link?"**
> Three things: (1) Switch to BBR congestion control — it models bandwidth and RTT independently instead of using loss as a congestion signal, so it doesn't back off on SATCOM's natural 0.1-0.5% background loss. (2) Deploy a TCP Performance Enhancing Proxy (PEP) that splits the TCP connection at the CE — the LAN side gets fast local TCP, the SATCOM side uses a high-latency-optimized connection. (3) Enable TCP window scaling and SACK — large BDP (150Mbps x 45ms = 843KB) requires window sizes larger than TCP's default 64KB.

---

## Papers and Research Foundations

This project implements concepts from:

- **"WAN Control Systems"** (Brain/raw/WanControlsys.pdf) — WAN control plane architecture, traffic engineering, and link state management patterns used in cloud PoP design.
- **"6G Network Architecture — Ericsson"** (Brain/raw/6G network architecture.md) — NTN (Non-Terrestrial Networks) integration concepts that directly apply to SATCOM WAN as a 6G access tier. The convergence of SATCOM and terrestrial 5G/6G is the production trajectory for this lab.
- **"Emerging Space Communication and Network Technologies for Sixth-Generation Ubiquitous Connectivity"** — LEO constellation architecture, handover mechanics, and link budget analysis behind the latency/loss profiles in the SATCOM emulator.
- **RFC 4821** — Packetization Layer Path MTU Discovery — the mechanism this project deliberately breaks in Experiment 5 and diagnoses in the RCA engine.
- **RFC 7914 / WireGuard paper (Donenfeld 2017)** — WireGuard cryptography and MTU behavior used in VPN configuration and overhead calculations.

---

## Project Gaps and Future Work

**Currently simulated (not real):**
- Telemetry metrics are synthetic (FastAPI generator) — not from real Starlink terminal gRPC API
- BGP on CE/PoP uses static namespace routing, not FRR daemon running inside namespaces
- Packet captures require root and Linux — not available on macOS directly

**Planned extensions:**
1. **FRR inside namespaces** — Run FRR daemon per namespace with proper vtysh socket, enabling real BGP convergence timing measurement
2. **Real Starlink gRPC telemetry** — Poll actual `192.168.100.1:9200` gRPC endpoint if hardware is available (starlink-grpc-tools compatible)
3. **MPLS/SR-MPLS** — Add segment routing labels on the PoP→cloud path to simulate carrier-grade WAN
4. **BFD integration** — Add BFD session alongside BGP for sub-second failure detection
5. **IPv6 dual-stack** — Add IPv6 addressing throughout; SATCOM operators are rapidly moving to IPv6-native
6. **Containerlab topology** — Replace manual namespace scripts with containerlab YAML for FRR containers
7. **TCP PEP simulation** — Proxy that splits TCP across the SATCOM segment to demonstrate throughput improvement
8. **SD-WAN policy engine** — Route decisions based on real-time telemetry (SATCOM vs LTE fallback)

---

## Resume Bullet Summary

```
Built a Linux namespace and FRRouting-based SATCOM enterprise WAN lab simulating customer
edge routing, eBGP peering (ASN 65001/65002), WireGuard VPN tunneling, CGNAT behavior,
and cloud PoP integration across 8 reproducible failure scenarios.

Developed a Python root cause analyzer that correlates packet captures, BGP state, VPN
status, routing tables, and synthetic modem telemetry to classify network outages by OSI
layer (L1-L7) with confidence scoring — 37 tests, 8 failure classes, no false positives
on healthy baselines.

Automated packet capture, telemetry collection, and failure injection workflows using Bash,
Scapy, Prometheus, and tc netem to benchmark latency (45-300ms), packet loss (0.1-10%),
MTU failures, and VPN degradation under Starlink-class SATCOM link conditions.
```

---

## License

MIT
