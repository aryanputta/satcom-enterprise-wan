#!/usr/bin/env bash
# Sets up Linux network namespaces simulating:
#   enterprise-lan -> ce-router -> satcom-wan -> pop-router -> cloud-router -> app-server
#
# Namespace topology:
#   ns-enterprise   10.10.0.0/24     (enterprise LAN)
#   ns-ce           10.10.0.1 (LAN), 100.64.0.1 (WAN toward SATCOM)
#   ns-satcom       100.64.0.2 (CE-side), 100.65.0.1 (PoP-side)  [WAN emulator]
#   ns-pop          100.65.0.2, 172.16.0.1 (toward cloud-router)
#   ns-cloud        172.16.0.2 (toward PoP), 192.168.100.1 (VPC)
#   ns-app          192.168.100.10   (application server)

set -euo pipefail

log() { echo "[setup] $*"; }

# ── Clean up any previous state ──────────────────────────────────────────────
bash "$(dirname "$0")/teardown_lab.sh" 2>/dev/null || true

# ── Create namespaces ─────────────────────────────────────────────────────────
for ns in ns-enterprise ns-ce ns-satcom ns-pop ns-cloud ns-app; do
    ip netns add "$ns"
    log "Created namespace: $ns"
done

# ── Bring up loopbacks ────────────────────────────────────────────────────────
for ns in ns-enterprise ns-ce ns-satcom ns-pop ns-cloud ns-app; do
    ip netns exec "$ns" ip link set lo up
done

# ── veth pairs ───────────────────────────────────────────────────────────────
create_veth() {
    local ns1=$1 if1=$2 ip1=$3 ns2=$4 if2=$5 ip2=$6
    ip link add "$if1" type veth peer name "$if2"
    ip link set "$if1" netns "$ns1"
    ip link set "$if2" netns "$ns2"
    ip netns exec "$ns1" ip addr add "$ip1" dev "$if1"
    ip netns exec "$ns2" ip addr add "$ip2" dev "$if2"
    ip netns exec "$ns1" ip link set "$if1" up
    ip netns exec "$ns2" ip link set "$if2" up
    log "veth $if1 ($ip1) <-> $if2 ($ip2)"
}

# enterprise-lan <-> ce-router (LAN side)
create_veth ns-enterprise eth0 10.10.0.100/24 \
            ns-ce         eth0 10.10.0.1/24

# ce-router <-> satcom-wan (WAN side)
create_veth ns-ce     eth1 100.64.0.1/30 \
            ns-satcom eth0 100.64.0.2/30

# satcom-wan <-> pop-router
create_veth ns-satcom eth1 100.65.0.1/30 \
            ns-pop    eth0 100.65.0.2/30

# pop-router <-> cloud-router
create_veth ns-pop   eth1 172.16.0.1/30 \
            ns-cloud eth0 172.16.0.2/30

# cloud-router <-> app-server
create_veth ns-cloud eth1 192.168.100.1/24 \
            ns-app   eth0 192.168.100.10/24

# ── Default routes ────────────────────────────────────────────────────────────
ip netns exec ns-enterprise ip route add default via 10.10.0.1
ip netns exec ns-ce         ip route add default via 100.64.0.2
ip netns exec ns-satcom     ip route add 10.10.0.0/24 via 100.64.0.1
ip netns exec ns-satcom     ip route add 192.168.100.0/24 via 100.65.0.2
ip netns exec ns-pop        ip route add default via 100.65.0.1
ip netns exec ns-pop        ip route add 192.168.100.0/24 via 172.16.0.2
ip netns exec ns-cloud      ip route add default via 172.16.0.1
ip netns exec ns-app        ip route add default via 192.168.100.1

# ── Enable IP forwarding in router namespaces ─────────────────────────────────
for ns in ns-ce ns-satcom ns-pop ns-cloud; do
    ip netns exec "$ns" sysctl -qw net.ipv4.ip_forward=1
done

# ── NAT at customer edge (masquerade LAN -> WAN) ──────────────────────────────
ip netns exec ns-ce iptables -t nat -A POSTROUTING -o eth1 -j MASQUERADE
ip netns exec ns-ce iptables -A FORWARD -i eth0 -o eth1 -j ACCEPT
ip netns exec ns-ce iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT

# ── Realistic SATCOM latency (baseline: 45ms one-way RTT ~90ms) ───────────────
ip netns exec ns-satcom tc qdisc add dev eth0 root netem delay 22ms 3ms distribution normal
ip netns exec ns-satcom tc qdisc add dev eth1 root netem delay 22ms 3ms distribution normal

log "Lab setup complete."
log ""
log "Topology:"
log "  ns-enterprise (10.10.0.100)"
log "    -> ns-ce (10.10.0.1 | 100.64.0.1) [NAT, firewall]"
log "    -> ns-satcom (100.64.0.2 | 100.65.0.1) [WAN emulator, netem]"
log "    -> ns-pop (100.65.0.2 | 172.16.0.1) [PoP router]"
log "    -> ns-cloud (172.16.0.2 | 192.168.100.1) [cloud VPC router]"
log "    -> ns-app (192.168.100.10) [application server]"
