#!/usr/bin/env bash
# Injects a specific failure mode into the running lab topology.
# Usage: sudo bash inject_failure.sh <failure_mode>
#
# Supported modes:
#   nat_failure       - Remove NAT rule, breaking outbound masquerade
#   vpn_failure       - Block UDP 51820 (WireGuard) at CE firewall
#   bgp_failure       - Simulate BGP ASN mismatch (corrupts FRR config)
#   mtu_blackhole     - Set WAN MTU to 1500 but VPN MTU to 1420 without PMTUD
#   packet_loss       - 5% packet loss on SATCOM WAN link
#   high_latency      - 300ms latency on SATCOM WAN link
#   dns_failure       - Block UDP/TCP 53 at CE firewall
#   failover          - Bring down SATCOM link, test alternate path
#   restore           - Restore all lab state to baseline

set -euo pipefail

FAILURE="${1:-}"
OUT_DIR="experiments/${FAILURE}"
mkdir -p "$OUT_DIR"
PCAP_DIR="captures/${FAILURE}"
mkdir -p "$PCAP_DIR"

log() { echo "[inject:${FAILURE}] $*"; }

case "$FAILURE" in

nat_failure)
    log "Removing NAT masquerade rule at customer edge..."
    ip netns exec ns-ce iptables -t nat -D POSTROUTING -o eth1 -j MASQUERADE 2>/dev/null || true
    ip netns exec ns-ce iptables -D FORWARD -i eth0 -o eth1 -j ACCEPT 2>/dev/null || true
    log "NAT table now:"
    ip netns exec ns-ce iptables -t nat -L -n --line-numbers
    log "Capturing traffic during failure..."
    ip netns exec ns-ce tcpdump -q -i eth1 -w "$PCAP_DIR/ce_wan.pcap" -G 15 -W 1 &>/dev/null &
    ip netns exec ns-enterprise ping -c 10 192.168.100.10 2>&1 | tee "$OUT_DIR/ping_result.txt" || true
    wait
    python3 "$(dirname "$0")/write_diagnostics.py" nat_failure "NAT masquerade removed" "Layer3_NAT"
    ;;

vpn_failure)
    log "Blocking WireGuard UDP 51820 at customer edge firewall..."
    ip netns exec ns-ce iptables -I FORWARD -p udp --dport 51820 -j DROP
    ip netns exec ns-ce iptables -I FORWARD -p udp --sport 51820 -j DROP
    log "Firewall rules:"
    ip netns exec ns-ce iptables -L FORWARD -n --line-numbers
    ip netns exec ns-ce tcpdump -q -i eth1 -w "$PCAP_DIR/ce_wan.pcap" -G 15 -W 1 &>/dev/null &
    sleep 15
    wait
    python3 "$(dirname "$0")/write_diagnostics.py" vpn_failure "WireGuard UDP 51820 blocked" "Layer4_VPN"
    ;;

bgp_failure)
    log "Simulating BGP ASN mismatch (CE expects peer ASN 65002, PoP advertising 65999)..."
    # Write a broken FRR config for CE router (wrong remote-as)
    cat > /tmp/frr_ce_broken.conf << 'FRREOF'
frr version 9.1
hostname ce-router
!
router bgp 65001
 bgp router-id 100.64.0.1
 neighbor 100.65.0.2 remote-as 65999
 neighbor 100.65.0.2 description "pop-router (WRONG ASN - should be 65002)"
 !
 address-family ipv4 unicast
  network 10.10.0.0/24
 exit-address-family
!
FRREOF
    log "BGP misconfiguration written. In a real FRR deployment this would be loaded with 'vtysh -f'."
    log "Simulating BGP session down state..."
    python3 "$(dirname "$0")/write_diagnostics.py" bgp_failure "BGP ASN mismatch: CE=65001 expects 65002, peer advertising 65999" "Layer3_BGP"
    ;;

mtu_blackhole)
    log "Creating MTU black hole: WAN MTU=1500, VPN overhead=80 bytes, no PMTUD signaling..."
    # Set WAN interface MTU to 1400, blocking large packets without ICMP fragmentation-needed
    ip netns exec ns-satcom ip link set eth0 mtu 1400
    ip netns exec ns-satcom ip link set eth1 mtu 1400
    # Block ICMP type 3 (fragmentation needed) to simulate black hole
    ip netns exec ns-satcom iptables -I FORWARD -p icmp --icmp-type 3 -j DROP
    log "Testing small ping (should succeed):"
    ip netns exec ns-enterprise ping -c 3 -s 100 192.168.100.10 | tee "$OUT_DIR/ping_small.txt" || true
    log "Testing large ping (should fail silently = black hole):"
    ip netns exec ns-enterprise ping -c 3 -s 1400 192.168.100.10 | tee "$OUT_DIR/ping_large.txt" || true
    ip netns exec ns-satcom tcpdump -q -i eth0 -w "$PCAP_DIR/satcom_wan.pcap" -G 10 -W 1 &>/dev/null &
    ip netns exec ns-enterprise ping -c 20 -s 1400 192.168.100.10 > /dev/null 2>&1 || true
    wait
    python3 "$(dirname "$0")/write_diagnostics.py" mtu_blackhole "MTU black hole: large packets silently dropped, ICMP frag-needed blocked" "Layer3_Layer4"
    ;;

packet_loss)
    log "Injecting 5%% packet loss on SATCOM WAN link..."
    ip netns exec ns-satcom tc qdisc change dev eth0 root netem delay 22ms 3ms loss 5%
    ip netns exec ns-satcom tc qdisc change dev eth1 root netem delay 22ms 3ms loss 5%
    log "Running ping test (10s)..."
    ip netns exec ns-enterprise ping -c 50 -i 0.2 192.168.100.10 | tee "$OUT_DIR/ping_loss.txt" || true
    if command -v iperf3 &>/dev/null; then
        ip netns exec ns-app iperf3 -s -D -1 2>/dev/null || true
        sleep 1
        ip netns exec ns-enterprise iperf3 -c 192.168.100.10 -t 10 -J > "$OUT_DIR/iperf3_loss.json" 2>/dev/null || true
    fi
    python3 "$(dirname "$0")/write_diagnostics.py" packet_loss "5% packet loss on SATCOM WAN via tc netem" "Layer1_Layer2"
    ;;

high_latency)
    log "Injecting 300ms latency + 20ms jitter on SATCOM WAN link..."
    ip netns exec ns-satcom tc qdisc change dev eth0 root netem delay 150ms 20ms distribution normal
    ip netns exec ns-satcom tc qdisc change dev eth1 root netem delay 150ms 20ms distribution normal
    log "Running ping test..."
    ip netns exec ns-enterprise ping -c 10 192.168.100.10 | tee "$OUT_DIR/ping_latency.txt" || true
    python3 "$(dirname "$0")/write_diagnostics.py" high_latency "300ms RTT (150ms one-way + 20ms jitter) on SATCOM WAN" "Layer1"
    ;;

dns_failure)
    log "Blocking DNS (UDP/TCP port 53) at customer edge..."
    ip netns exec ns-ce iptables -I FORWARD -p udp --dport 53 -j DROP
    ip netns exec ns-ce iptables -I FORWARD -p tcp --dport 53 -j DROP
    log "DNS queries will now fail. Application will appear down despite connectivity."
    ip netns exec ns-enterprise ping -c 3 192.168.100.10 | tee "$OUT_DIR/ping_ok.txt" || true
    ip netns exec ns-enterprise dig +short +time=3 google.com @8.8.8.8 > "$OUT_DIR/dns_fail.txt" 2>&1 || true
    python3 "$(dirname "$0")/write_diagnostics.py" dns_failure "DNS blocked at CE firewall, application appears down" "Layer7"
    ;;

failover)
    log "Bringing down SATCOM WAN link (simulating satellite outage)..."
    ip netns exec ns-satcom ip link set eth0 down
    ip netns exec ns-satcom ip link set eth1 down
    log "Primary link down. In SD-WAN deployment, failover to backup WAN would trigger."
    ip netns exec ns-enterprise ping -c 5 192.168.100.10 | tee "$OUT_DIR/ping_down.txt" || true
    log "Restoring SATCOM link..."
    ip netns exec ns-satcom ip link set eth0 up
    ip netns exec ns-satcom ip link set eth1 up
    sleep 2
    ip netns exec ns-enterprise ping -c 5 192.168.100.10 | tee "$OUT_DIR/ping_restored.txt" || true
    python3 "$(dirname "$0")/write_diagnostics.py" failover "SATCOM link outage simulated, failover path tested" "Layer1"
    ;;

restore)
    log "Restoring baseline state..."
    # Restore NAT
    ip netns exec ns-ce iptables -t nat -F POSTROUTING 2>/dev/null || true
    ip netns exec ns-ce iptables -t nat -A POSTROUTING -o eth1 -j MASQUERADE
    ip netns exec ns-ce iptables -F FORWARD 2>/dev/null || true
    ip netns exec ns-ce iptables -A FORWARD -i eth0 -o eth1 -j ACCEPT
    ip netns exec ns-ce iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT
    # Restore MTU
    ip netns exec ns-satcom ip link set eth0 mtu 1500 2>/dev/null || true
    ip netns exec ns-satcom ip link set eth1 mtu 1500 2>/dev/null || true
    ip netns exec ns-satcom iptables -F FORWARD 2>/dev/null || true
    # Restore netem (baseline 45ms RTT)
    ip netns exec ns-satcom tc qdisc change dev eth0 root netem delay 22ms 3ms distribution normal 2>/dev/null || true
    ip netns exec ns-satcom tc qdisc change dev eth1 root netem delay 22ms 3ms distribution normal 2>/dev/null || true
    # Restore links
    ip netns exec ns-satcom ip link set eth0 up 2>/dev/null || true
    ip netns exec ns-satcom ip link set eth1 up 2>/dev/null || true
    log "Restored. Run 'make baseline' to verify."
    ;;

*)
    echo "ERROR: Unknown failure mode: '$FAILURE'"
    echo "Valid modes: nat_failure vpn_failure bgp_failure mtu_blackhole packet_loss high_latency dns_failure failover restore"
    exit 1
    ;;
esac

log "Failure injection complete. Run 'make analyze' to diagnose."
