# Experiment Catalog

Each experiment follows: Setup → Inject → Symptoms → Evidence → RCA Output → Fix → Verify

---

## Experiment 1: Baseline Connectivity

**Setup:**
```bash
sudo bash lab/scripts/setup_lab.sh
make baseline
```

**Expected:**
- Ping succeeds end-to-end with ~90ms RTT (45ms one-way)
- Traceroute shows 6 hops through all namespaces
- iperf3 TCP throughput ~140 Mbps (limited by netem, not CPU)

**Baseline telemetry values:**
- latency_ms: ~45, loss: ~0.1%, signal_quality: >0.95, link_state: up

---

## Experiment 2: NAT Misconfiguration Breaks Outbound

**Inject:**
```bash
make inject-nat-failure
```

**Symptoms:**
- Ping from enterprise to 192.168.100.10 fails (100% loss)
- Traceroute shows no response beyond CE router
- iperf3 shows immediate failure

**Packet evidence:**
- `tcpdump -i eth1 -n` on ns-ce WAN shows SRC IP = 10.10.0.100 (RFC1918, not NATted)
- No ICMP unreachable returned (upstream silently drops)
- ARP at CE still responds (L2 healthy)

**Root cause output:**
```json
{
  "probable_cause": "NAT Masquerade Missing",
  "osi_layer": "Layer 3",
  "evidence": ["NAT MASQUERADE rule absent from iptables nat table"],
  "recommended_fix": "iptables -t nat -A POSTROUTING -o eth1 -j MASQUERADE",
  "confidence": 0.91
}
```

**Fix:**
```bash
sudo bash lab/scripts/inject_failure.sh restore
make baseline
```

---

## Experiment 3: VPN Handshake Blocked by Firewall

**Setup:**
```bash
sudo bash lab/vpn/wireguard/setup_wireguard.sh
```

**Inject:**
```bash
make inject-vpn-failure
```

**Symptoms:**
- `wg show` shows 0 bytes transferred, handshake_at: never
- Pings to 10.200.0.2 (VPN peer) fail
- Application behind VPN unreachable but direct IP accessible

**Packet evidence:**
- No UDP packets to/from port 51820 on CE WAN interface
- `iptables -L FORWARD -n` shows DROP rule for UDP 51820

**Root cause output:**
```json
{
  "probable_cause": "VPN UDP Port Blocked by Firewall",
  "osi_layer": "Layer 4",
  "confidence": 0.90
}
```

**Fix:**
```bash
sudo ip netns exec ns-ce iptables -D FORWARD -p udp --dport 51820 -j DROP
sudo ip netns exec ns-ce iptables -D FORWARD -p udp --sport 51820 -j DROP
```

---

## Experiment 4: BGP Session Down — ASN Mismatch

**Inject:**
```bash
make inject-bgp-failure
```

**Symptoms:**
- Route to 192.168.100.0/24 disappears from CE routing table
- Traffic falls back to static route (if exists) or black holes
- `vtysh -c 'show bgp summary'` shows peer stuck in Active/Idle

**BGP log evidence:**
```
BGP: %NOTIFICATION: sent to neighbor 100.65.0.2 2/2 (Open Message Error/Bad Peer AS)
BGP: peer 100.65.0.2 Down BGP Notification send
```

**Root cause output:**
```json
{
  "probable_cause": "BGP Session Not Established",
  "osi_layer": "Layer 3",
  "evidence": ["telemetry.bgp_state='active' matches {'in': ['active', 'idle', 'connect']}"],
  "confidence": 0.92
}
```

**Fix:**
- Correct `remote-as` in frr.conf to match actual peer ASN
- Restart FRR: `systemctl restart frr`

---

## Experiment 5: MTU Black Hole Inside VPN Tunnel

**Inject:**
```bash
make inject-mtu-blackhole
```

**Symptoms:**
- Small pings (<100 bytes) succeed through VPN
- Large pings (>1400 bytes) or file transfers fail silently
- TCP connections establish but hang after first data exchange
- No ICMP fragmentation-needed messages (blocked)

**Packet evidence (tcpdump):**
```
# Small ping: success
IP 10.10.0.100 > 192.168.100.10: ICMP echo request, length 128

# Large ping: no response, no ICMP frag-needed
IP 10.10.0.100 > 192.168.100.10: ICMP echo request, length 1428
# ... silence ...

# TCP: SYN establishes, data hangs (retransmit storm)
IP 10.10.0.100.45821 > 192.168.100.10.80: Flags [S], seq 0
IP 192.168.100.10.80 > 10.10.0.100.45821: Flags [S.], seq 0, ack 1
IP 10.10.0.100.45821 > 192.168.100.10.80: Flags [P.], length 1420 -> retransmit x6
```

**Root cause output:**
```json
{
  "probable_cause": "MTU Black Hole — VPN Path",
  "osi_layer": "Layer 3 / Layer 4",
  "confidence": 0.91
}
```

**Fix:**
```bash
sudo ip netns exec ns-ce ip link set wg0 mtu 1280
sudo ip netns exec ns-ce iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN \
  -j TCPMSS --clamp-mss-to-pmtu
```

---

## Experiment 6: SATCOM Packet Loss Degrades Throughput

**Inject:**
```bash
make inject-loss
```

**Symptoms:**
- Ping shows ~5% loss intermittently
- iperf3 TCP throughput drops from 140 Mbps to 20-40 Mbps
- iperf3 UDP shows direct packet loss
- TCP enters repeated loss recovery cycles (CUBIC/BBR backoff)

**Throughput comparison (measured):**
| Profile     | TCP Mbps | UDP Mbps | Loss% |
|-------------|----------|----------|-------|
| Baseline    | ~140     | ~130     | 0.1   |
| 1% loss     | ~80      | ~110     | 1.0   |
| 5% loss     | ~20      | ~55      | 5.0   |
| 10% loss    | ~5       | ~20      | 10.0  |

**Fix:**
```bash
sudo bash lab/scripts/inject_failure.sh restore
```
For production: enable BBR, deploy TCP PEP, use FEC for UDP.

---

## Experiment 7: DNS Failure Appears as Application Outage

**Inject:**
```bash
make inject
# then: sudo bash lab/scripts/inject_failure.sh dns_failure
```

**Symptoms:**
- `ping 192.168.100.10` succeeds (IP connectivity OK)
- `curl http://app.internal` hangs/fails (DNS lookup fails first)
- Application logs show "Name or service not known"
- Users report "application is down" — it is actually DNS-broken

**Packet evidence:**
```
# Wireshark filter: dns
# Enterprise sends DNS query to 8.8.8.8
IP 10.10.0.100.56789 > 8.8.8.8.53: A? google.com
# Dropped at CE iptables — no response ever comes back
```

**Root cause output:**
```json
{
  "probable_cause": "DNS Resolution Failure",
  "osi_layer": "Layer 7",
  "evidence": ["DNS keywords found: ['DNS', 'No response']"],
  "confidence": 0.93
}
```

**Fix:**
```bash
sudo ip netns exec ns-ce iptables -D FORWARD -p udp --dport 53 -j DROP
sudo ip netns exec ns-ce iptables -D FORWARD -p tcp --dport 53 -j DROP
```

---

## Experiment 8: SD-WAN Failover (SATCOM to Backup WAN)

**Inject:**
```bash
make inject
# then: sudo bash lab/scripts/inject_failure.sh failover
```

**Behavior:**
- SATCOM link is brought down (both interfaces in ns-satcom)
- Primary path (CE -> SATCOM -> PoP) breaks
- In a real SD-WAN deployment, the CE would detect link loss and reroute via backup (LTE/MPLS)
- Lab measures: time for link to be detected down, time for route to reconverge
- After restore: measures BGP convergence time back to primary

**Measurement:**
```
link_down_time: t=0
ping_first_failure: t=0.2s (netem jitter window)
route_removed: depends on BGP hold timer (default 90s, or 30s with tuned timers)
link_restored: t+X
bgp_reconvergence: t+X+10s (with timers 10/30)
```

**Key insight:** SATCOM BGP hold timers must be tuned for link flap behavior.
Default 90s hold timer means 90s blackout on link failure. Tuned to 30s = 30s.
BFD (Bidirectional Forwarding Detection) can reduce this to sub-second.
