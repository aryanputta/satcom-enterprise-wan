#!/usr/bin/env bash
# Generates WireGuard keys and configures tunnel between CE and PoP
# Requires: wg, ip (iproute2), namespace lab already running
set -euo pipefail

KEYS_DIR="lab/vpn/wireguard/keys"
mkdir -p "$KEYS_DIR"

log() { echo "[wireguard] $*"; }

log "Generating WireGuard key pairs..."
wg genkey | tee "$KEYS_DIR/ce_private.key" | wg pubkey > "$KEYS_DIR/ce_public.key"
wg genkey | tee "$KEYS_DIR/pop_private.key" | wg pubkey > "$KEYS_DIR/pop_public.key"
chmod 600 "$KEYS_DIR/ce_private.key" "$KEYS_DIR/pop_private.key"

CE_PRIV=$(cat "$KEYS_DIR/ce_private.key")
CE_PUB=$(cat "$KEYS_DIR/ce_public.key")
POP_PRIV=$(cat "$KEYS_DIR/pop_private.key")
POP_PUB=$(cat "$KEYS_DIR/pop_public.key")

log "CE  public key: $CE_PUB"
log "PoP public key: $POP_PUB"

# ── Configure CE namespace ────────────────────────────────────────────────────
log "Configuring WireGuard in ns-ce..."
ip netns exec ns-ce ip link add wg0 type wireguard
ip netns exec ns-ce ip addr add 10.200.0.1/30 dev wg0
ip netns exec ns-ce ip link set wg0 mtu 1280 up

ip netns exec ns-ce wg set wg0 \
    private-key "$KEYS_DIR/ce_private.key" \
    listen-port 51820 \
    peer "$POP_PUB" \
        allowed-ips "192.168.100.0/24,10.200.0.2/32" \
        endpoint "100.65.0.2:51820" \
        persistent-keepalive 25

ip netns exec ns-ce ip route add 192.168.100.0/24 dev wg0

# ── Configure PoP namespace ───────────────────────────────────────────────────
log "Configuring WireGuard in ns-pop..."
ip netns exec ns-pop ip link add wg0 type wireguard
ip netns exec ns-pop ip addr add 10.200.0.2/30 dev wg0
ip netns exec ns-pop ip link set wg0 mtu 1280 up

ip netns exec ns-pop wg set wg0 \
    private-key "$KEYS_DIR/pop_private.key" \
    listen-port 51820 \
    peer "$CE_PUB" \
        allowed-ips "10.10.0.0/24,10.200.0.1/32"

ip netns exec ns-pop ip route add 10.10.0.0/24 dev wg0

log "WireGuard configured. Testing tunnel..."
ip netns exec ns-ce ping -c 3 10.200.0.2 && log "Tunnel UP" || log "Tunnel FAILED"

log "WireGuard status (CE):"
ip netns exec ns-ce wg show

log "WireGuard status (PoP):"
ip netns exec ns-pop wg show
