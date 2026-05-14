# Interview Prep — SATCOM Enterprise WAN

Questions you will get asked about this project at Ericsson, Juniper, NVIDIA, Palantir, Google, or Amazon. Each answer is grounded in actual code from this repo.

---

## BGP

**Q: Walk me through the BGP session state machine.**

FSM has 6 states: Idle → Connect → Active → OpenSent → OpenConfirm → Established.
- **Idle**: BGP waiting to start. Triggered by admin enable or timer expiry.
- **Connect**: TCP SYN sent to peer on port 179. If TCP times out, goes to Active.
- **Active**: Retrying TCP connection. Key symptom of misconfiguration — check remote-as, TCP 179 reachability.
- **OpenSent**: TCP connected, OPEN message sent. Contains AS number, hold timer, router-id.
- **OpenConfirm**: Waiting for KEEPALIVE in response to OPEN. Hold timer countdown active.
- **Established**: Session up. UPDATE messages flowing. Hold timer resets on each KEEPALIVE.

In this lab: CE (AS65001) ↔ PoP (AS65002) eBGP. Hold timer tuned to 30s (default 180s) for SATCOM. See `lab/frr/ce-router/frr.conf`.

**Q: What's the difference between eBGP and iBGP?**

- eBGP: peers in different ASes. TTL=1 by default (must be directly connected). Routes have AS_PATH updated. Administrative distance 20.
- iBGP: peers in same AS. Full mesh or route reflector required — iBGP learned routes are not re-advertised to other iBGP peers (split horizon). AD 200.
- In this lab: PoP acts as route reflector for cloud-router (both AS65002). `route-reflector-client` set on cloud-router neighbor.

**Q: Why did you tune BGP timers?**

Default keepalive 60s / hold timer 180s. On SATCOM, beam handoff causes link outages of 5–30s. With default timers, hold timer expires after 180s of no keepalive → session torn down → 180s routing blackout. Tuned to 10/30 (`neighbor timers 10 30`). Hold timer expires at 30s → max 30s blackout. For sub-second: add BFD (`bfd profile satcom`).

**Q: What is BGP route reflector and why is it needed?**

iBGP split horizon: routes learned from iBGP peer are not advertised to other iBGP peers. In a full mesh (n peers → n*(n-1)/2 sessions), n=100 routers = 4950 sessions. Route reflector (RR) breaks this: RR advertises iBGP routes to all clients. Clients only peer with RR, not each other. In this lab: PoP is RR, cloud-router is RR client.

---

## Routing / NAT

**Q: Explain MASQUERADE vs SNAT.**

Both do source NAT. SNAT requires a static `--to-source` IP — breaks if WAN IP changes (e.g., SATCOM beam handoff changes CGNAT address). MASQUERADE dynamically uses the current WAN interface IP. More expensive per-packet (kernel reads interface IP each time) but correct for dynamic IP environments. Used in `setup_lab.sh`:
```bash
iptables -t nat -A POSTROUTING -o eth1 -j MASQUERADE
```

**Q: What is CGNAT and how does it affect SATCOM VPN?**

CGNAT (RFC 6598, 100.64.0.0/10): ISP shares one public IP across multiple customers by NAT-ing at carrier level. CE router sees a CGNAT address, not a true public IP. Implications:
1. Inbound port forwarding at CE doesn't work (carrier NAT blocks it)
2. VPN must connect outbound to cloud PoP (not inbound to CE)
3. WireGuard handles this via PersistentKeepalive=25, which maintains the NAT binding
In this lab: transit uses 100.64.0.0/30 (CGNAT range) intentionally.

**Q: What is an MTU black hole?**

When SATCOM WAN MTU < default TCP MSS (1460). Large packets get fragmented or, more commonly, silently dropped when ICMP type 3 code 4 ("fragmentation needed, don't fragment bit set") is blocked by upstream firewall. TCP sender never learns about the MTU constraint. Connection works for small packets (e.g., HTTP GET) but stalls for large ones (e.g., file download). Fix: MSS clamping:
```bash
iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
```
This modifies the TCP SYN to advertise a smaller MSS matching the path MTU.

**Q: What is policy routing and when do you use it?**

Linux policy routing uses multiple routing tables selected by `ip rule` based on source IP, DSCP mark, or iptables fwmark. Allows different traffic classes to use different WAN links. In this lab's SD-WAN engine (`sdwan/policy_engine.py`):
- Voice traffic (DSCP EF, fwmark 10) → table 110 → LTE link (low latency)
- Bulk traffic (DSCP CS1, fwmark 30) → table 130 → SATCOM (high bandwidth)
```bash
ip rule add fwmark 10 lookup 110 prio 10010
ip route add default via 10.99.0.1 dev eth2 table 110
```

---

## TCP / Transport

**Q: Why does TCP perform badly over SATCOM without tuning?**

TCP throughput = cwnd / RTT. Default cwnd starts at ~10 MSS (~14 KB). RTT on LEO SATCOM = 90ms. Throughput = 14 KB / 0.090s = 1.24 Mbps on a 140 Mbps link. Even with window scaling, OS default `tcp_rmem` max is 6 MB but actual buffer grows slowly. BDP = 140 Mbps × 0.090s = 1.575 MB (12.6 Mbit). Need at least 1.575 MB receive window to saturate the link.

Fix:
```bash
sysctl -w net.core.rmem_max=4194304
sysctl -w net.ipv4.tcp_rmem="4096 131072 4194304"
sysctl -w net.ipv4.tcp_wmem="4096 131072 4194304"
sysctl -w net.ipv4.tcp_congestion_control=bbr
```

**Q: Why BBR over CUBIC on SATCOM?**

CUBIC interprets packet loss as congestion signal — halves cwnd on every drop. SATCOM has RF-induced loss (rain fade, interference) that has nothing to do with congestion. CUBIC on 7% rain fade loss: throughput collapses. BBR uses bandwidth and RTT measurements, not loss, to estimate available bandwidth. Maintains high throughput under background loss. Designed by Google for high-BDP paths. See `docs/troubleshooting-playbook.md`.

**Q: What is TCP PEP and when is it used?**

TCP PEP (RFC 3135) splits an end-to-end TCP connection at the satellite boundary. CE PEP accepts the client TCP connection and immediately opens a separate connection to the cloud. Each half is independently tuned:
- LAN side: standard TCP, matches client expectations
- SATCOM side: BDP-sized buffers, BBR, aggressive keepalives

Without PEP: sender's cwnd grows slowly across the full RTT (90ms). With PEP: LAN side has 1ms RTT → cwnd grows 90× faster. Satellite side pre-fetches data into buffer. In `tcp_pep/pep_proxy.py`: 2 MB buffers (31× larger than default 64 KB window), per-socket TCP_KEEPIDLE/TCP_KEEPINTVL tuning.

---

## VPN / Security

**Q: Why WireGuard over OpenVPN/IPsec for SATCOM?**

- WireGuard overhead: ~80 bytes (vs ~100 for IPsec, ~150 for OpenVPN). On 140 Mbps link, 80B overhead per 1280B MTU packet = 6% overhead. Acceptable.
- Cryptography: Curve25519 (ECDH), ChaCha20-Poly1305 AEAD. Hardware-accelerated on modern CPUs.
- MTU: WireGuard MTU = path MTU - 80. Set to 1280 for compatibility with CGNAT path.
- NAT traversal: PersistentKeepalive=25 maintains UDP 51820 NAT binding across beam handoffs. IPsec IKE/ESP can fail CGNAT traversal.
- Handshake: 1-RTT if initiating, stateless otherwise. Critical on high-latency SATCOM.

**Q: What is a WireGuard "stale handshake" and how do you detect it?**

WireGuard sessions expire after 180s without traffic. After expiry, next packet triggers re-handshake. On SATCOM, re-handshake adds ~90ms (one RTT). Stale detection in `analyzer/vpn_analyzer.py`: parse `wg show` output, check `latest handshake: X seconds ago`. If >180s, flag as stale. Also check `transfer: 0 B received` — indicates peer is unreachable or sending but CE isn't receiving.

---

## Observability

**Q: How does your health scorer work?**

5-dimension weighted score (see `analyzer/health_scorer.py`):
- Physical Link (L1): 30% — link state, packet loss, signal quality, temperature, obstruction
- Routing/NAT (L3): 25% — route count, default route presence, NAT masquerade, latency
- VPN (L4): 20% — WireGuard tunnel state
- BGP (L3 control): 15% — session state
- Application (L7): 10% — DNS failures, latency impact on app timeouts

Hard cap: if L1 score = 0 (link down), total score ≤ 40. Prevents VPN/BGP "not configured" (both score 100) from masking a dead physical link.

**Q: Walk me through your RCA engine.**

Input: `diagnostics.json` — telemetry fields, route tables, NAT table, BGP state, VPN state, pcap keywords.
Process: Load YAML rules from `analyzer/rules/` (layer1–4_rules.yaml). For each rule, evaluate `match` conditions against diagnostics dict. Conditions: numeric comparisons (gte/lte), keyword presence, boolean fields. Score top findings by confidence. Output structured JSON: `probable_cause`, `osi_layer`, `evidence`, `recommended_fix`, `confidence`.

Real example from `test_integration.py`: NAT MASQUERADE missing → rule L3_NAT_BROKEN fires at 0.91 confidence with evidence `["NAT MASQUERADE rule missing"]` and fix `iptables -t nat -A POSTROUTING -o <wan_if> -j MASQUERADE`.

---

## Networking Fundamentals

**Q: What is BDP and why does it matter?**

Bandwidth-Delay Product = bandwidth × RTT. Maximum amount of data "in flight" in the network at any time. A TCP connection can only sustain throughput = cwnd / RTT. If cwnd < BDP, the pipe is underutilized. On SATCOM (140 Mbps, 90ms): BDP = 140e6 × 0.090 / 8 = 1.575 MB. Default 64 KB buffer = 4% utilization. With 2 MB buffer = 127% utilization (slight overhead = good, fills pipe).

**Q: What is the difference between latency, jitter, and delay budget?**

- Latency: one-way or RTT. On LEO SATCOM: 35–50ms one-way (vs 600ms GEO).
- Jitter: variance in latency. tc netem: `delay 45ms 3ms distribution normal` = 45ms ± 3ms normally distributed. High jitter causes TCP retransmit storms and VoIP quality degradation.
- Delay budget: maximum latency a traffic class can tolerate end-to-end. Voice: 150ms one-way (ITU G.114). Video: 400ms. BGP: N/A (but affects convergence). Used in SD-WAN scoring.

**Q: What is PMTUD and why does it fail on SATCOM?**

Path MTU Discovery (RFC 1191): sender sets DF (Don't Fragment) bit. If intermediate router must fragment (packet > link MTU), it drops and sends ICMP type 3 code 4 (fragmentation needed, MTU=X). Sender reduces packet size. Failure mode: if ICMP is blocked (firewall, CGNAT), sender never learns. Large packets silently dropped. TCP connection stalls for large transfers, works for small ones. Fix: MSS clamping or explicitly set MTU.

---

## System Design

**Q: How would you scale this to a real multi-site enterprise deployment?**

1. Replace namespace scripts with Containerlab + FRR containers (already done in `containerlab/satcom-wan.yml`)
2. BGP route reflector hierarchy: regional RRs with clients at each site
3. SD-WAN controller: centralized policy server pushing decisions to site agents via gRPC
4. Telemetry aggregation: Prometheus federation, Thanos for long-term storage
5. Real Starlink gRPC polling at each CE: `telemetry/collector/starlink_grpc.py` already handles this
6. LTE/5G fallback: wwan0 interface + dual-SIM modem, SD-WAN engine handles failover
7. BFD for sub-second failure detection: `bfd profile satcom` in FRR config

**Q: How would you add MPLS to this topology?**

MPLS with Segment Routing (SR-MPLS): PoP assigns SID (Segment Identifier) to each prefix. CE encapsulates packets with MPLS label stack. Benefits: traffic engineering (explicit paths), fast reroute (50ms via ECMP/LFA), reduced BGP signaling.
FRR supports IS-IS SR and OSPF SR. Implementation path:
```
PoP: router isis / segment-routing mpls
CE: segment-routing prefix-sid <prefix> index <N>
```
SR-TE (Traffic Engineering): explicit path list specifying PoP segment, bypass segment, and egress.

---

## Behavioral / Depth Questions

**Q: What was the hardest bug you fixed in this project?**

The L3_NAT_BROKEN rule never fired. Root cause: rule matched on BOTH `nat_masquerade_missing: true` AND `nat_table_size: {lte: 0}`. Test environment had nat_table_size=120 (healthy), so the AND condition blocked detection even when MASQUERADE was missing. Fix: removed the `nat_table_size` condition — the definitive indicator is MASQUERADE missing, not table size. Lesson: over-specified rule conditions create false negatives; diagnostic rules should match on the minimum necessary indicators.

**Q: What would you add next?**

Priority in order of production value:
1. **FRR inside namespaces with real BGP** — enables actual convergence timing measurements
2. **BFD integration** — sub-second failure detection alongside BGP hold timer
3. **TCP throughput benchmark comparing PEP vs direct** — quantify the 26× claim with iperf3
4. **Real Starlink gRPC** — need actual hardware but client code is ready
5. **SR-MPLS** — carrier-grade traffic engineering on PoP→cloud path
