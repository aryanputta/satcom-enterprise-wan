"""
VPN Tunnel Analyzer.

Diagnoses WireGuard and IPsec tunnel state including:
  - Handshake age (stale = tunnel up but not exchanging data)
  - Keepalive effectiveness on SATCOM links
  - MTU mismatch between tunnel and path
  - NAT binding expiry causing silent tunnel death
  - Rx/Tx byte ratio (asymmetric traffic = possible routing issue)

Can be imported by root_cause_analyzer.py or run standalone.
"""

from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass, field
from datetime import datetime, timezone


@dataclass
class WireGuardPeer:
    public_key: str
    endpoint: str
    allowed_ips: list[str]
    latest_handshake_seconds_ago: int | None
    rx_bytes: int
    tx_bytes: int
    keepalive_interval: int | None


@dataclass
class WireGuardInterface:
    interface: str
    public_key: str
    listen_port: int
    peers: list[WireGuardPeer]
    issues: list[str] = field(default_factory=list)
    healthy: bool = True


@dataclass
class VPNAnalysis:
    wireguard: WireGuardInterface | None
    ipsec_active: bool
    issues: list[str] = field(default_factory=list)
    healthy: bool = True

    # Derived diagnostics
    tunnel_state: str = "unknown"          # up / stale / down / not_configured
    mtu_adequate: bool | None = None
    nat_traversal_ok: bool | None = None


def parse_wg_show(output: str) -> WireGuardInterface | None:
    """Parse output of: wg show (or wg show all)"""
    if not output.strip() or "not found" in output.lower():
        return None

    # Extract interface-level info
    iface_match = re.search(r"interface: (\S+)", output)
    pubkey_match = re.search(r"public key: (\S+)", output)
    port_match = re.search(r"listening port: (\d+)", output)

    if not iface_match:
        return None

    iface = WireGuardInterface(
        interface=iface_match.group(1),
        public_key=pubkey_match.group(1) if pubkey_match else "unknown",
        listen_port=int(port_match.group(1)) if port_match else 51820,
        peers=[],
    )

    # Parse each peer block
    peer_blocks = re.split(r"\n(?=peer:)", output)
    for block in peer_blocks[1:]:
        pk_m = re.search(r"peer: (\S+)", block)
        ep_m = re.search(r"endpoint: (\S+)", block)
        allowed_m = re.search(r"allowed ips: (.+)", block)
        hs_m = re.search(r"latest handshake: (.+)", block)
        rx_m = re.search(r"transfer: ([\d.]+\s+\w+) received, ([\d.]+\s+\w+) sent", block)
        ka_m = re.search(r"persistent keepalive: every (\d+) seconds", block)

        if not pk_m:
            continue

        # Parse handshake age
        hs_seconds: int | None = None
        if hs_m:
            hs_text = hs_m.group(1).strip()
            if "never" in hs_text.lower():
                hs_seconds = None
            else:
                # Parse "X minutes, Y seconds ago" or "X seconds ago"
                total = 0
                for val, unit in re.findall(r"(\d+)\s+(minute|second|hour|day)", hs_text):
                    v = int(val)
                    if unit == "second":
                        total += v
                    elif unit == "minute":
                        total += v * 60
                    elif unit == "hour":
                        total += v * 3600
                    elif unit == "day":
                        total += v * 86400
                hs_seconds = total if total > 0 else None

        # Parse bytes (simplified: just extract numbers)
        rx_bytes = 0
        tx_bytes = 0
        tx_rx_m = re.search(r"transfer: ([\d,]+) B received, ([\d,]+) B sent", block)
        if tx_rx_m:
            rx_bytes = int(tx_rx_m.group(1).replace(",", ""))
            tx_bytes = int(tx_rx_m.group(2).replace(",", ""))

        peer = WireGuardPeer(
            public_key=pk_m.group(1),
            endpoint=ep_m.group(1) if ep_m else "unknown",
            allowed_ips=[a.strip() for a in allowed_m.group(1).split(",")] if allowed_m else [],
            latest_handshake_seconds_ago=hs_seconds,
            rx_bytes=rx_bytes,
            tx_bytes=tx_bytes,
            keepalive_interval=int(ka_m.group(1)) if ka_m else None,
        )
        iface.peers.append(peer)

    # Diagnose
    for peer in iface.peers:
        if peer.latest_handshake_seconds_ago is None:
            iface.issues.append(
                f"Peer {peer.public_key[:16]}... has NEVER completed a handshake — "
                f"tunnel is down. Check UDP {iface.listen_port} reachability and firewall."
            )
            iface.healthy = False

        elif peer.latest_handshake_seconds_ago > 180:
            iface.issues.append(
                f"Handshake stale: {peer.latest_handshake_seconds_ago}s ago (>180s). "
                f"SATCOM link reset likely caused NAT binding expiry. "
                f"Keepalive={'yes' if peer.keepalive_interval else 'NOT SET — set PersistentKeepalive=25'}."
            )
            iface.healthy = False

        if peer.rx_bytes == 0 and peer.tx_bytes > 0:
            iface.issues.append(
                f"Peer {peer.public_key[:16]}...: sending but receiving nothing. "
                "Possible asymmetric routing — return path does not use tunnel."
            )
            iface.healthy = False

        if peer.keepalive_interval is None:
            iface.issues.append(
                f"Peer {peer.public_key[:16]}...: no PersistentKeepalive configured. "
                "SATCOM CGNAT bindings expire in 30-120s. Add: PersistentKeepalive = 25"
            )

    return iface


def check_mtu_adequacy(
    namespace: str,
    interface: str,
    path_overhead_bytes: int = 80,
) -> dict:
    """
    Verify that VPN interface MTU leaves enough headroom for SATCOM path overhead.
    WireGuard overhead: 60 bytes IP+UDP header + 32 bytes Noise protocol = ~92 bytes
    SATCOM additional framing: 60-140 bytes depending on link layer
    Safe minimum MTU: 1280 (IPv6 minimum, handles all combinations)
    """
    try:
        r = subprocess.run(
            ["ip", "netns", "exec", namespace, "ip", "link", "show", interface],
            capture_output=True, text=True, timeout=5
        )
        mtu_m = re.search(r"mtu (\d+)", r.stdout)
        current_mtu = int(mtu_m.group(1)) if mtu_m else None
    except Exception:
        current_mtu = None

    if current_mtu is None:
        return {"adequate": None, "current_mtu": None, "recommended_mtu": 1280, "reason": "Could not read MTU"}

    # WireGuard overhead: 20 (IPv4) + 8 (UDP) + 4 (WG header) + 16 (auth tag) + 32 (Noise overhead) = ~80
    wg_overhead = 80
    satcom_overhead = 60  # conservative minimum
    required_outer_mtu = current_mtu + wg_overhead + satcom_overhead

    adequate = required_outer_mtu <= 1500

    return {
        "adequate": adequate,
        "current_mtu": current_mtu,
        "wg_overhead_bytes": wg_overhead,
        "satcom_overhead_bytes": satcom_overhead,
        "required_outer_mtu": required_outer_mtu,
        "recommended_mtu": 1280 if not adequate else current_mtu,
        "reason": (
            f"MTU {current_mtu} + {wg_overhead} WG overhead + {satcom_overhead} SATCOM overhead "
            f"= {required_outer_mtu} exceeds 1500 — packets will be silently dropped"
            if not adequate
            else f"MTU {current_mtu} is adequate for SATCOM path"
        ),
    }


def analyze_vpn_status(vpn_status_dict: dict, wg_show_output: str = "") -> VPNAnalysis:
    """
    Top-level VPN analysis from diagnostics.json vpn_status field
    plus optional raw wg show output.
    """
    analysis = VPNAnalysis(wireguard=None, ipsec_active=False)

    wg_state = vpn_status_dict.get("wireguard", "not_configured")
    ipsec_state = vpn_status_dict.get("ipsec", "not_configured")

    # Parse wg show if available
    if wg_show_output:
        wg_iface = parse_wg_show(wg_show_output)
        analysis.wireguard = wg_iface
        if wg_iface:
            analysis.issues.extend(wg_iface.issues)
            if not wg_iface.healthy:
                analysis.healthy = False

    # Map string states to tunnel_state
    if wg_state == "up" and not analysis.issues:
        analysis.tunnel_state = "up"
    elif wg_state == "down":
        analysis.tunnel_state = "down"
        analysis.issues.append("WireGuard tunnel is down — verify UDP 51820 is not blocked and peer is reachable")
        analysis.healthy = False
    elif wg_state == "handshaking":
        analysis.tunnel_state = "down"
        analysis.issues.append("WireGuard stuck in handshake — check firewall rules and peer public key configuration")
        analysis.healthy = False
    elif wg_state == "not_configured":
        analysis.tunnel_state = "not_configured"
    else:
        analysis.tunnel_state = wg_state

    analysis.ipsec_active = ipsec_state == "active"

    return analysis
