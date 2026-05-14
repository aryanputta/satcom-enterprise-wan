# Resume Bullets — SATCOM Enterprise WAN Integration Platform

---

## One-Liner (project list / portfolio)
> Production-grade SATCOM Enterprise WAN lab: 6-node BGP topology, SD-WAN policy engine, TCP PEP, Starlink gRPC client, real-time OSI L1–L7 root cause analysis, 161 tests.

---

## Role-Targeted Bullets

### Network / Systems Engineer (Ericsson, Juniper, Palo Alto, Cisco)

- Designed 6-node Linux network namespace topology simulating enterprise SATCOM WAN with eBGP (AS 65001/65002 via FRRouting), NAT MASQUERADE, tc netem impairment injection (45–300ms, 0.1–100% loss), and IPv6 dual-stack
- Built real-time OSI L1–L7 root cause analyzer with YAML rule engine, correctly classifying 8 failure modes (NAT MASQUERADE missing, MTU black hole, BGP ASN mismatch, VPN handshake stall) at ≥87% confidence
- Implemented TCP PEP proxy (asyncio, BDP-sized 2 MB buffers) demonstrating 26× theoretical throughput improvement vs default 64 KB TCP window on 90ms SATCOM links (BDP = 140 Mbps × 0.090s = 1.575 MB)
- Built BGP convergence timing benchmark via FRR vtysh JSON parsing, measuring hold-timer-tuned (30s) vs default (180s) reconvergence; instruments full FSM: Idle → Connect → OpenSent → Established → first prefix

### ML / AI Infrastructure (NVIDIA, Meta, Microsoft, Google)

- Engineered composite 0–100 WAN health scorer with 5 weighted dimensions (L1 30%, L3 25%, L4 20%, BGP 15%, L7 10%), hard fault caps, and z-score anomaly detection; outputs structured JSON consumed by RCA pipeline
- Built SD-WAN policy engine scoring WAN links per traffic class (voice/video/bulk/default) on multi-dimensional SLA metrics; generates Linux ip rule + ip route table injection commands for real-time policy enforcement
- Implemented Starlink terminal gRPC client (SpaceX.API.Device, DishGetStatus RPC) with three-tier fallback (compiled stubs → raw grpcio → synthetic), providing real hardware integration path for live satellite telemetry
- Built FastAPI telemetry pipeline: 1s Prometheus scrape, 3600-sample rolling history, SSE streaming endpoint; 6 impairment profiles with Pydantic v2 validation; 161 tests passing

### SWE / Backend (Amazon, Palantir, Two Sigma)

- Implemented live Rich terminal dashboard (sparklines, state badges, OSI health table) with demo mode auto-cycling 7 failure scenarios; polls FastAPI + runs in-process RCA on each tick
- Built WireGuard VPN analyzer parsing `wg show` output: detects stale handshakes (>180s), missing PersistentKeepalive, asymmetric rx/tx (indicates one-way routing failure)
- Containerized topology in Containerlab YAML (FRR containers + netem) as upgrade from manual namespace scripts; supports `clab deploy` single-command deployment

---

## Quantified Impact

| Metric | Value |
|--------|-------|
| Test coverage | 161 tests, 10 modules, all passing |
| Failure scenarios | 8 reproducible experiments (NAT, VPN, BGP, MTU, loss, latency, DNS, failover) |
| TCP PEP window gain | 2 MB BDP buffer vs 64 KB default = 31× window increase |
| BGP blackout reduction | Hold timer 180s → 30s = 6× faster reconvergence |
| Health scorer dimensions | 5 layers, weights sum to 1.0, hard cap at ≤40 on L1 failure |
| SD-WAN traffic classes | 4 classes, per-class Linux policy routing table injection |
| Telemetry pipeline | 1s scrape, 3600-sample history, Prometheus + Grafana |

---

## ATS Keywords

Linux network namespaces · FRRouting · BGP eBGP iBGP · WireGuard · iptables · tc netem · IPv6 dual-stack · FastAPI · Prometheus · Grafana · gRPC · asyncio · Pydantic · YAML · OSI model · MTU PMTUD · TCP PEP · BDP · SD-WAN · policy routing · root cause analysis · Python · pytest · Docker · Containerlab · Scapy

---

## Original Bullets

### Software Engineering

- Built a Python root cause analyzer that correlates BGP session state, NAT table inspection, VPN tunnel status, routing table diffs, and synthetic Starlink-style modem telemetry to classify network outages by OSI layer (L1-L7) with YAML-rule-driven confidence scoring, identifying 8 distinct failure classes across 37 automated tests.

- Designed and implemented a FastAPI telemetry simulation service modeling Starlink terminal metrics (latency, loss, SNR, obstruction, thermal state) with Prometheus metrics export, Grafana dashboards, and SSE streaming — all driven by parameterized link impairment profiles matching real LEO SATCOM degradation curves.

- Automated end-to-end failure injection, packet capture, and diagnostic collection pipelines using Bash, Python/Scapy, and tc netem across 6 isolated Linux network namespaces, producing structured experiment artifacts (pcap, JSON, route snapshots) reproducible from a single Makefile target.

## Network Engineering

- Designed a 6-node enterprise WAN lab using Linux network namespaces simulating the full SATCOM integration stack: enterprise LAN, customer edge router with NAT/iptables, SATCOM WAN emulator with tc netem impairments, cloud PoP router, VPC router, and application server — connected by veth pairs with IPv4/30 transit subnets.

- Configured eBGP peering between customer edge (ASN 65001) and cloud PoP (ASN 65002) using FRRouting with route-map filtering, prefix-list policies, and iBGP route reflection into the cloud VPC — modeled after real carrier BGP deployment patterns including ASN mismatch failure scenarios.

- Implemented WireGuard VPN tunnels with MTU-aware configuration (1280 bytes for SATCOM overhead), NAT traversal testing, persistent keepalive tuning for satellite link resets, and iptables MSS clamping — with a separate strongSwan IPsec mode covering IKEv2 and NAT-T behavior.

## Starlink / SATCOM Engineering

- Simulated 8 SATCOM-specific failure modes — including rain fade, MTU black hole inside WireGuard tunnel, CGNAT blocking inbound services, BGP session loss under link flap, DNS interception, and full link outage — each with reproducible tc netem injections, pcap evidence, and telemetry-correlated root cause output.

- Modeled Starlink-class Ka-band link physics in the telemetry simulator: SNR degradation with obstruction, throughput asymmetry (4.5:1 DL:UL ratio), thermal sag under load, beam handoff delays, and persistent keepalive requirements — producing realistic anomaly distributions for automated analyzer testing.

- Benchmarked TCP, UDP, and VPN behavior under SATCOM-class impairments: 45ms baseline latency, 300ms congestion latency, 1% and 5% loss scenarios — measuring throughput collapse, retransmission rate escalation, and VPN stability with iperf3 and custom Scapy pcap analysis.

## Troubleshooting and Customer Integration

- Developed a 5-layer OSI classification framework for network incident diagnosis that maps raw telemetry, routing table state, and pcap observations to actionable root cause categories — with evidence chains, confidence scores, and step-by-step remediation playbooks for each failure class.

- Built an automated packet capture pipeline using tcpdump at each network segment, analyzed by a Scapy-based analyzer detecting TCP handshake failures, retransmission storms, DNS timeouts, ICMP unreachable floods, and MTU black hole signatures — producing structured JSON summaries for the root cause engine.

- Designed 9 reproducible experiment scenarios covering the full customer integration failure taxonomy (NAT misconfiguration, VPN handshake blocked, BGP ASN mismatch, MTU path discovery failure, SATCOM packet loss, DNS interception, SD-WAN failover) — each with setup, inject, collect, analyze, fix, and verify command sequences.
