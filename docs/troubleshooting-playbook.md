# Troubleshooting Playbook

Structured decision tree for SATCOM enterprise WAN incidents. Follow the OSI layer order — always rule out L1 before chasing L3 problems.

---

## Step 0: Start the Monitor

```bash
make up          # start telemetry stack
make monitor     # open live terminal dashboard
```

The dashboard shows real-time link state, OSI health, and the last RCA result.

---

## L1 — Is the physical SATCOM link up?

**Check:**
```bash
# From API
curl http://localhost:8000/metrics/current | python3 -m json.tool | grep -E "link_state|packet_loss|signal_quality|obstruction"

# From namespace (if lab running)
sudo ip netns exec ns-satcom tc qdisc show
sudo ip netns exec ns-satcom ip link show
```

**Symptom → Cause table:**

| Symptom | Probable Cause | Fix |
|---------|---------------|-----|
| `link_state: down` | Physical outage, dish power | Check hardware, dish pointing, power |
| `packet_loss > 5%` | Rain fade, obstruction | Check sky view, weather, obstruction% |
| `signal_quality < 0.7` | Misalignment, interference | Realign dish, check nearby RF |
| `modem_temperature > 75C` | Thermal throttle | Improve ventilation |

**Lab injection:**
```bash
# Simulate link down
sudo bash lab/scripts/inject_failure.sh failover
# Simulate 5% loss
make inject-loss
```

---

## L2 — Are interfaces operational?

**Check:**
```bash
sudo ip netns exec ns-ce ip link show
sudo ip netns exec ns-satcom ip link show
```

**Symptom → Cause:**

| Symptom | Probable Cause | Fix |
|---------|---------------|-----|
| Interface shows `DOWN` or `NO-CARRIER` | Admin down or cable issue | `ip link set <if> up` |
| MTU mismatch | Misconfiguration | `ip link set <if> mtu 1500` |

---

## L3 — Can packets be routed?

**Check routing:**
```bash
sudo ip netns exec ns-enterprise ip route show
sudo ip netns exec ns-ce ip route show
# If BGP configured:
sudo ip netns exec ns-ce vtysh -c "show bgp summary"
```

**Check NAT:**
```bash
sudo ip netns exec ns-ce iptables -t nat -L -n -v
# Must see MASQUERADE rule in POSTROUTING
```

**Symptom → Cause:**

| Symptom | Probable Cause | Fix |
|---------|---------------|-----|
| No route to destination | Missing default route, BGP down | Add static route or fix BGP |
| Traffic reaches WAN with 10.x.x.x source | NAT masquerade missing | Add POSTROUTING MASQUERADE rule |
| BGP stuck in Active/Idle | ASN mismatch, TCP 179 blocked | Fix remote-as config, check firewall |
| Route flaps continuously | BGP hold timer too aggressive | Tune: `timers 10 30` in FRR config |

**Lab injection:**
```bash
make inject-nat-failure     # removes MASQUERADE rule
make inject-bgp-failure     # simulates ASN mismatch
```

**MTU black hole — the SATCOM-specific L3 trap:**
```bash
# Test: small ping succeeds, large fails = black hole
sudo ip netns exec ns-enterprise ping -c 3 -s 100 192.168.100.10   # should succeed
sudo ip netns exec ns-enterprise ping -c 3 -s 1400 -M do 192.168.100.10  # -M do = DF bit
# If second fails silently (no "Frag needed"), PMTUD is broken
```

Fix:
```bash
sudo ip netns exec ns-ce ip link set wg0 mtu 1280
sudo ip netns exec ns-ce iptables -t mangle -A FORWARD \
  -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
```

---

## L4 — Is the VPN tunnel working?

**Check WireGuard:**
```bash
sudo ip netns exec ns-ce wg show
# Healthy output:
#   latest handshake: 30 seconds ago
#   transfer: X MiB received, Y MiB sent
#
# Problem signs:
#   latest handshake: never            → tunnel never established
#   latest handshake: 5 minutes ago    → stale (SATCOM NAT binding expired)
#   transfer: X sent, 0 received       → asymmetric routing
```

**Check firewall:**
```bash
sudo ip netns exec ns-ce iptables -L FORWARD -n | grep 51820
# Should show NO DROP rules for UDP 51820
```

**SATCOM-specific VPN issues:**

| Symptom | Cause | Fix |
|---------|-------|-----|
| Handshake: never | UDP 51820 blocked | Remove iptables DROP rule for 51820 |
| Handshake: stale after link reset | No PersistentKeepalive | Add `PersistentKeepalive = 25` to WG peer config |
| Tunnel up but traffic drops | MTU black hole | Lower tunnel MTU to 1280 |
| Tunnel up, large transfers fail | PMTUD broken | Add MSS clamping via iptables mangle |

**Lab injection:**
```bash
make inject-vpn-failure     # blocks UDP 51820
make inject-mtu-blackhole   # creates MTU black hole
```

---

## L7 — Is the application working?

**Classic SATCOM L7 trap:** IP connectivity is fine, but DNS fails. Application looks completely broken.

```bash
# Test IP directly (should work)
sudo ip netns exec ns-enterprise ping 192.168.100.10

# Test hostname resolution (may fail)
sudo ip netns exec ns-enterprise dig +short +time=3 app.internal @8.8.8.8

# Test DNS bypass (forces direct DNS query)
sudo ip netns exec ns-enterprise dig +short google.com @8.8.8.8
```

**If ping works but DNS fails:**
```bash
# Check firewall for DNS block
sudo ip netns exec ns-ce iptables -L FORWARD -n | grep -E "53|domain"
# Fix
sudo ip netns exec ns-ce iptables -D FORWARD -p udp --dport 53 -j DROP
sudo ip netns exec ns-ce iptables -D FORWARD -p tcp --dport 53 -j DROP
```

**Application timeouts on SATCOM (not a failure, but needs tuning):**
```bash
# Increase TCP initial congestion window (reduces slow start penalty)
sysctl -w net.ipv4.tcp_init_cwnd=30
# Switch to BBR (handles loss better than CUBIC)
sysctl -w net.ipv4.tcp_congestion_control=bbr
# Enable SACK and large window scaling
sysctl -w net.ipv4.tcp_sack=1
sysctl -w net.ipv4.tcp_window_scaling=1
```

---

## Root Cause Analyzer Usage

```bash
# After any failure injection
make analyze

# Or directly
python3 analyzer/root_cause_analyzer.py --input experiments/vpn_failure/diagnostics.json

# JSON only for scripts
python3 analyzer/root_cause_analyzer.py --input experiments/nat_failure/diagnostics.json --json-only
```

**Confidence score interpretation:**
- `>= 0.90`: High confidence — the evidence strongly matches the rule
- `0.70-0.89`: Moderate — rule fires but pcap/secondary evidence incomplete
- `< 0.70`: Low — rule partially matches; additional investigation needed

---

## BGP Convergence Reference

Default FRR timer behavior with BGP:
- Keepalive: 60s
- Hold timer: 180s — link must be down 180s before BGP declares session dead

Optimized for SATCOM (set in frr.conf):
```
neighbor 100.65.0.2 timers 10 30
```
- Keepalive: 10s
- Hold: 30s — detects link failure within 30s

With BFD (future work):
- Sub-second failure detection
- Requires FRR BFD daemon + BFD support on peer

---

## TCP Performance on SATCOM Reference

The Bandwidth-Delay Product (BDP) determines how much data must be "in-flight" to fill the pipe:

```
BDP = Bandwidth × RTT
BDP = 150 Mbps × 0.090s = 1.69 MB = 13.5 Mbit
```

This means TCP needs a ~13.5 Mbit (1.69 MB) window to saturate a 150 Mbps SATCOM link at 90ms RTT.

Default TCP window: 64 KB = 512 Kbit. This explains why SATCOM links appear "slow" even when bandwidth is available — the TCP window is the bottleneck, not the link.

Fix:
```bash
sysctl -w net.core.rmem_max=16777216
sysctl -w net.core.wmem_max=16777216
sysctl -w net.ipv4.tcp_rmem="4096 87380 16777216"
sysctl -w net.ipv4.tcp_wmem="4096 87380 16777216"
```

With BBR (recommended for SATCOM):
- BBR tracks bandwidth and RTT separately
- Does not back off on loss unless loss indicates actual congestion
- Maintains throughput at 1-3% loss where CUBIC collapses
- Enable: `sysctl -w net.ipv4.tcp_congestion_control=bbr`
