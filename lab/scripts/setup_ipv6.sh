#!/usr/bin/env bash
# setup_ipv6.sh — Add IPv6 dual-stack to the SATCOM lab namespaces
#
# Adds IPv6 ULA (fc00::/7) addressing to all interfaces, enables IPv6
# forwarding, and configures static IPv6 routes matching the existing
# IPv4 topology.
#
# SATCOM operators are rapidly moving to IPv6-native deployments:
# - Starlink uses SLAAC + PD (prefix delegation) for customer devices
# - DHCPv6-PD allocates /56 or /60 prefixes to CE routers
# - WireGuard VPN works transparently over IPv6
#
# IPv6 address plan (ULA fc00::/7, RFC 4193):
#   enterprise LAN:    fd00:10:10::/64     (mirrors 10.10.0.0/24)
#   CE WAN (transit):  fd00:64:64::/127    (mirrors 100.64.0.0/30)
#   SATCOM-PoP:        fd00:64:65::/127    (mirrors 100.65.0.0/30)
#   PoP-Cloud:         fd00:172:16::/127   (mirrors 172.16.0.0/30)
#   Cloud VPC:         fd00:c0:a8:100::/64 (mirrors 192.168.100.0/24)
#   WireGuard:         fd00:10:200::/126   (mirrors 10.200.0.0/30)

set -euo pipefail

if [ "$(uname)" != "Linux" ]; then
    echo "ERROR: IPv6 namespace configuration requires Linux."
    exit 1
fi

if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: Must run as root."
    exit 1
fi

ns_exists() { ip netns list | grep -q "^$1"; }

enable_ipv6_fwd() {
    local ns="$1"
    ip netns exec "$ns" sysctl -qw net.ipv6.conf.all.forwarding=1
    ip netns exec "$ns" sysctl -qw net.ipv6.conf.default.forwarding=1
    ip netns exec "$ns" sysctl -qw net.ipv6.conf.all.accept_ra=0
}

add_addr() {
    local ns="$1" iface="$2" addr="$3"
    ip netns exec "$ns" ip -6 addr add "$addr" dev "$iface" 2>/dev/null || \
        echo "  (already configured: $ns $iface $addr)"
}

add_route() {
    local ns="$1" dst="$2" via="$3"
    ip netns exec "$ns" ip -6 route add "$dst" via "$3" 2>/dev/null || \
        echo "  (route exists: $ns $dst via $via)"
}

echo "=== IPv6 Dual-Stack Configuration ==="

for ns in ns-enterprise ns-ce ns-satcom ns-pop ns-cloud ns-app; do
    if ! ns_exists "$ns"; then
        echo "SKIP: $ns not found (run setup_lab.sh first)"
        continue
    fi
    enable_ipv6_fwd "$ns"
done

echo ""
echo "--- Enterprise LAN (fd00:10:10::/64) ---"
if ns_exists ns-enterprise; then
    add_addr ns-enterprise eth0 "fd00:10:10::10/64"
fi

echo ""
echo "--- CE Router ---"
if ns_exists ns-ce; then
    add_addr ns-ce eth0 "fd00:10:10::1/64"          # LAN-facing
    add_addr ns-ce eth1 "fd00:64:64::1/127"          # WAN-facing (CE side)

    # IPv6 NAT (NPTv6 / MASQUERADE6) — for CE behind CGNAT
    ip6tables -t nat -C POSTROUTING -s fd00:10:10::/64 -o eth1 -j MASQUERADE 2>/dev/null || \
        ip6tables -t nat -A POSTROUTING -s fd00:10:10::/64 -o eth1 -j MASQUERADE

    # Default IPv6 route via SATCOM WAN
    add_route ns-ce "::/0" "fd00:64:64::0"
fi

echo ""
echo "--- SATCOM WAN Emulator ---"
if ns_exists ns-satcom; then
    add_addr ns-satcom eth0 "fd00:64:64::0/127"      # CE-facing
    add_addr ns-satcom eth1 "fd00:64:65::0/127"      # PoP-facing
    # Forward between the two sides
    add_route ns-satcom "fd00:10:10::/64"  "fd00:64:64::1"
    add_route ns-satcom "fd00:c0:a8:100::/64" "fd00:64:65::1"

    # Apply IPv6 netem on the SATCOM segment (same delay as IPv4)
    ip netns exec ns-satcom tc qdisc show dev eth1 | grep -q netem && \
        echo "  netem already on eth1 (covers IPv6 too)"
fi

echo ""
echo "--- Cloud PoP Router ---"
if ns_exists ns-pop; then
    add_addr ns-pop eth0 "fd00:64:65::1/127"          # SATCOM-facing
    add_addr ns-pop eth1 "fd00:172:16::1/127"          # Cloud-facing

    # BGP IPv6 (if FRR is running, it will pick up the addresses automatically)
    add_route ns-pop "fd00:10:10::/64"        "fd00:64:65::0"
    add_route ns-pop "fd00:c0:a8:100::/64"    "fd00:172:16::0"
fi

echo ""
echo "--- Cloud VPC Router ---"
if ns_exists ns-cloud; then
    add_addr ns-cloud eth0 "fd00:172:16::0/127"        # PoP-facing
    add_addr ns-cloud eth1 "fd00:c0:a8:100::1/64"      # App server-facing

    add_route ns-cloud "fd00:10:10::/64"   "fd00:172:16::1"
    add_route ns-cloud "::/0"              "fd00:172:16::1"
fi

echo ""
echo "--- App Server ---"
if ns_exists ns-app; then
    add_addr ns-app eth0 "fd00:c0:a8:100::10/64"
    add_route ns-app "::/0" "fd00:c0:a8:100::1"
fi

echo ""
echo "=== IPv6 Verification Commands ==="
echo "Ping LAN→App (IPv6):  sudo ip netns exec ns-enterprise ping6 fd00:c0:a8:100::10"
echo "Traceroute6:          sudo ip netns exec ns-enterprise traceroute6 fd00:c0:a8:100::10"
echo "CE IPv6 routes:       sudo ip netns exec ns-ce ip -6 route show"
echo "Show all IPv6 addrs:  for ns in ns-enterprise ns-ce ns-satcom ns-pop ns-cloud ns-app; do"
echo "                        echo \"=== \$ns ===\"; sudo ip netns exec \$ns ip -6 addr show; done"
echo ""
echo "IPv6 dual-stack configuration complete."
