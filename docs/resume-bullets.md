# Resume Bullets — SATCOM Enterprise WAN Integration Platform

## Software Engineering

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
