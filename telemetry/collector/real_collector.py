"""
Real system telemetry collector for Linux kernel interfaces.

Reads actual metrics from:
  /proc/net/dev        — interface byte/packet/error counters
  /proc/net/snmp       — TCP segment counters (retransmits, in/out segs)
  tc -j qdisc show     — active netem parameters (delay, loss, jitter)
  ip -j route          — routing table with protocol tags
  ip -j link           — interface state

All reads gracefully return None on non-Linux or missing permissions.
The collector is designed to be dropped in as a replacement for the
synthetic telemetry_generator when running on a real Linux lab.
"""

from __future__ import annotations

import json
import platform
import re
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

IS_LINUX = platform.system() == "Linux"


@dataclass
class IfaceStats:
    name: str
    rx_bytes: int = 0
    tx_bytes: int = 0
    rx_packets: int = 0
    tx_packets: int = 0
    rx_errors: int = 0
    tx_errors: int = 0
    rx_drop: int = 0
    tx_drop: int = 0
    state: str = "unknown"


@dataclass
class NetemQdisc:
    iface: str
    delay_us: int = 0
    jitter_us: int = 0
    loss_pct: float = 0.0
    duplicate_pct: float = 0.0
    corrupt_pct: float = 0.0
    bandwidth_bps: Optional[int] = None


@dataclass
class RouteEntry:
    dst: str
    gateway: Optional[str]
    iface: str
    proto: str
    metric: int


@dataclass
class TcpCounters:
    retransmits: int = 0
    in_segs: int = 0
    out_segs: int = 0
    established: int = 0


@dataclass
class RealTelemetry:
    iface_stats: dict[str, IfaceStats] = field(default_factory=dict)
    netem: dict[str, NetemQdisc] = field(default_factory=dict)
    routes: list[RouteEntry] = field(default_factory=list)
    tcp: TcpCounters = field(default_factory=TcpCounters)
    timestamp: float = field(default_factory=time.time)

    # Convenience derived fields — set by collector after parsing
    link_state: str = "unknown"
    latency_ms: Optional[float] = None
    jitter_ms: Optional[float] = None
    loss_pct: Optional[float] = None
    bandwidth_mbps: Optional[float] = None
    route_count: int = 0
    bgp_route_count: int = 0


def _run(cmd: list[str], ns: Optional[str] = None, timeout: int = 3) -> str:
    if ns:
        cmd = ["ip", "netns", "exec", ns] + cmd
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout.strip()
    except Exception:
        return ""


def read_iface_stats(ns: Optional[str] = None) -> dict[str, IfaceStats]:
    """Parse /proc/net/dev for byte/packet counters."""
    if not IS_LINUX:
        return {}

    if ns:
        # Read from namespace via nsenter
        raw = _run(["cat", "/proc/net/dev"], ns=ns)
    else:
        try:
            raw = Path("/proc/net/dev").read_text()
        except PermissionError:
            return {}

    stats: dict[str, IfaceStats] = {}
    for line in raw.splitlines()[2:]:  # skip header lines
        parts = line.split()
        if len(parts) < 17:
            continue
        name = parts[0].rstrip(":")
        s = IfaceStats(
            name=name,
            rx_bytes=int(parts[1]),
            rx_packets=int(parts[2]),
            rx_errors=int(parts[3]),
            rx_drop=int(parts[4]),
            tx_bytes=int(parts[9]),
            tx_packets=int(parts[10]),
            tx_errors=int(parts[11]),
            tx_drop=int(parts[12]),
        )
        stats[name] = s
    return stats


def read_iface_states(ns: Optional[str] = None) -> dict[str, str]:
    """Parse `ip -j link show` for interface UP/DOWN state."""
    raw = _run(["ip", "-j", "link", "show"], ns=ns)
    if not raw:
        return {}
    try:
        links = json.loads(raw)
    except json.JSONDecodeError:
        return {}
    return {
        lnk["ifname"]: ("up" if "UP" in lnk.get("flags", []) else "down")
        for lnk in links
    }


def read_netem_qdiscs(ifaces: list[str], ns: Optional[str] = None) -> dict[str, NetemQdisc]:
    """
    Parse `tc -j qdisc show dev <iface>` for each interface.
    Returns only interfaces that have an active netem qdisc.
    """
    qdiscs: dict[str, NetemQdisc] = {}

    for iface in ifaces:
        raw = _run(["tc", "-j", "qdisc", "show", "dev", iface], ns=ns)
        if not raw:
            continue
        try:
            qlist = json.loads(raw)
        except json.JSONDecodeError:
            continue

        for q in qlist:
            if q.get("kind") != "netem":
                continue
            opts = q.get("options", {})
            # tc -j reports delay in microseconds
            delay_us = opts.get("delay", 0)
            jitter_us = opts.get("jitter", 0)
            # loss is a fraction 0..1 in tc JSON; convert to percent
            loss_frac = opts.get("loss", 0.0)
            dup_frac = opts.get("duplicate", 0.0)
            corrupt_frac = opts.get("corrupt", 0.0)

            # bandwidth from tbf or netem rate
            bw_bps = opts.get("rate", None)
            if bw_bps is not None:
                # tc reports rate in bps (bits/sec)
                pass

            qdiscs[iface] = NetemQdisc(
                iface=iface,
                delay_us=int(delay_us),
                jitter_us=int(jitter_us),
                loss_pct=round(loss_frac * 100, 4),
                duplicate_pct=round(dup_frac * 100, 4),
                corrupt_pct=round(corrupt_frac * 100, 4),
                bandwidth_bps=int(bw_bps) if bw_bps else None,
            )

    return qdiscs


def read_routes(ns: Optional[str] = None) -> list[RouteEntry]:
    """Parse `ip -j route show` for all routing table entries."""
    raw = _run(["ip", "-j", "route", "show"], ns=ns)
    if not raw:
        return []
    try:
        entries = json.loads(raw)
    except json.JSONDecodeError:
        return []
    routes = []
    for e in entries:
        routes.append(RouteEntry(
            dst=e.get("dst", ""),
            gateway=e.get("gateway"),
            iface=e.get("dev", ""),
            proto=e.get("protocol", ""),
            metric=e.get("metric", 0),
        ))
    return routes


def read_tcp_counters() -> TcpCounters:
    """Parse /proc/net/snmp for TCP retransmit and segment counters."""
    if not IS_LINUX:
        return TcpCounters()
    try:
        text = Path("/proc/net/snmp").read_text()
    except (PermissionError, FileNotFoundError):
        return TcpCounters()

    tcp_keys: list[str] = []
    tcp_vals: list[str] = []
    for line in text.splitlines():
        if line.startswith("Tcp:"):
            parts = line.split()
            if not tcp_keys:
                tcp_keys = parts[1:]
            else:
                tcp_vals = parts[1:]

    if not tcp_keys or not tcp_vals:
        return TcpCounters()

    m = dict(zip(tcp_keys, tcp_vals))
    return TcpCounters(
        retransmits=int(m.get("RetransSegs", 0)),
        in_segs=int(m.get("InSegs", 0)),
        out_segs=int(m.get("OutSegs", 0)),
        established=int(m.get("CurrEstab", 0)),
    )


def read_tcp_tuning() -> dict[str, str]:
    """Read TCP kernel tuning parameters relevant to SATCOM."""
    params = [
        "net/ipv4/tcp_congestion_control",
        "net/ipv4/tcp_rmem",
        "net/ipv4/tcp_wmem",
        "net/ipv4/tcp_window_scaling",
        "net/core/rmem_max",
        "net/core/wmem_max",
    ]
    result: dict[str, str] = {}
    if not IS_LINUX:
        return result
    for p in params:
        try:
            val = Path(f"/proc/sys/{p}").read_text().strip()
            result[p.split("/")[-1]] = val
        except (FileNotFoundError, PermissionError):
            pass
    return result


def collect(
    satcom_iface: str = "eth1",
    lan_iface: str = "eth0",
    namespace: Optional[str] = None,
) -> RealTelemetry:
    """
    Main entry point. Collect full telemetry from a running Linux node.

    Args:
        satcom_iface: WAN-facing interface (default eth1 matching CE router)
        lan_iface: LAN-facing interface
        namespace: Linux network namespace name (e.g. "ns-ce")
    """
    tel = RealTelemetry()

    # Interface stats
    tel.iface_stats = read_iface_stats(ns=namespace)
    states = read_iface_states(ns=namespace)
    for name, st in tel.iface_stats.items():
        st.state = states.get(name, "unknown")

    # netem qdisc on both interfaces
    tel.netem = read_netem_qdiscs([satcom_iface, lan_iface], ns=namespace)

    # Routing table
    tel.routes = read_routes(ns=namespace)
    tel.route_count = len(tel.routes)
    tel.bgp_route_count = sum(1 for r in tel.routes if r.proto == "bgp")

    # TCP counters (host-level, not namespace-scoped)
    tel.tcp = read_tcp_counters()

    # Derive convenience fields from netem on the satcom interface
    if satcom_iface in tel.netem:
        q = tel.netem[satcom_iface]
        tel.latency_ms = q.delay_us / 1000.0
        tel.jitter_ms = q.jitter_us / 1000.0
        tel.loss_pct = q.loss_pct
        if q.bandwidth_bps:
            tel.bandwidth_mbps = q.bandwidth_bps / 1_000_000

    # Link state from satcom interface
    wan_state = states.get(satcom_iface, "unknown")
    tel.link_state = wan_state

    return tel


def to_telemetry_dict(tel: RealTelemetry) -> dict:
    """
    Convert RealTelemetry to the same shape as SatcomTerminalMetrics.dict()
    so it can be passed to the health scorer and RCA engine unchanged.
    """
    return {
        "latency_ms": tel.latency_ms or 0.0,
        "jitter_ms": tel.jitter_ms or 0.0,
        "packet_loss_percent": tel.loss_pct or 0.0,
        "downlink_mbps": tel.bandwidth_mbps or 0.0,
        "uplink_mbps": (tel.bandwidth_mbps or 0.0) * 0.22,
        "link_state": tel.link_state if tel.link_state in ("up", "down", "degraded") else "unknown",
        "route_count": tel.route_count,
        "bgp_route_count": tel.bgp_route_count,
        "tcp_retransmits": tel.tcp.retransmits,
        "tcp_established": tel.tcp.established,
        "timestamp": tel.timestamp,
    }
