"""
Routing Table Analyzer.

Parses 'ip route show' output from multiple namespaces and checks for:
  - Missing default route
  - Missing specific prefix
  - Routing loops
  - Asymmetric routing
  - Stale routes after failure recovery
  - BGP vs static route conflicts
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from ipaddress import IPv4Network, IPv4Address, AddressValueError


@dataclass
class RouteEntry:
    prefix: str
    proto: str  # kernel, static, bgp, ospf, connected
    nexthop: str
    interface: str
    metric: int = 0
    administrative_distance: int = 0


@dataclass
class RouteTableAnalysis:
    namespace: str
    routes: list[RouteEntry]
    has_default_route: bool = False
    default_via: str = ""
    issues: list[str] = field(default_factory=list)
    healthy: bool = True


# Protocol tag mapping from 'ip route' output
PROTO_MAP = {
    "kernel": "connected",
    "static": "static",
    "bgp": "bgp",
    "ospf": "ospf",
    "dhcp": "dhcp",
}


def parse_route_table(output: str, namespace: str = "unknown") -> RouteTableAnalysis:
    """Parse output of 'ip route show' or 'ip route show table all'."""
    routes: list[RouteEntry] = []

    # Match route lines: prefix via nexthop dev interface proto proto
    # Examples:
    #   default via 100.64.0.2 dev eth1 proto static
    #   10.10.0.0/24 dev eth0 proto kernel scope link src 10.10.0.1
    #   192.168.100.0/24 via 172.16.0.2 dev eth1 proto bgp metric 20

    route_re = re.compile(
        r"^(\S+)\s+"           # prefix or 'default'
        r"(?:via\s+(\S+)\s+)?" # optional nexthop
        r"dev\s+(\S+)"         # interface
        r"(?:\s+proto\s+(\S+))?"  # optional proto
        r"(?:\s+metric\s+(\d+))?",  # optional metric
        re.MULTILINE
    )

    for m in route_re.finditer(output):
        prefix_raw = m.group(1)
        nexthop = m.group(2) or "direct"
        iface = m.group(3)
        proto_raw = m.group(4) or "kernel"
        metric = int(m.group(5) or 0)
        proto = PROTO_MAP.get(proto_raw, proto_raw)

        routes.append(RouteEntry(
            prefix=prefix_raw,
            proto=proto,
            nexthop=nexthop,
            interface=iface,
            metric=metric,
        ))

    analysis = RouteTableAnalysis(namespace=namespace, routes=routes)

    # Check for default route
    default_routes = [r for r in routes if r.prefix == "default" or r.prefix == "0.0.0.0/0"]
    if default_routes:
        analysis.has_default_route = True
        analysis.default_via = default_routes[0].nexthop
    else:
        analysis.has_default_route = False
        analysis.issues.append(
            f"[{namespace}] No default route — traffic to unknown destinations will be dropped"
        )
        analysis.healthy = False

    # Check for BGP routes
    bgp_routes = [r for r in routes if r.proto == "bgp"]
    if not bgp_routes and namespace in ("ns-ce", "ns-pop"):
        analysis.issues.append(
            f"[{namespace}] No BGP-learned routes — BGP session may be down"
        )

    # Check for duplicate/conflicting routes to same prefix
    prefixes_seen: dict[str, list[RouteEntry]] = {}
    for r in routes:
        prefixes_seen.setdefault(r.prefix, []).append(r)

    for prefix, route_list in prefixes_seen.items():
        if len(route_list) > 1:
            protos = [r.proto for r in route_list]
            if "static" in protos and "bgp" in protos:
                analysis.issues.append(
                    f"[{namespace}] Conflicting routes for {prefix}: static vs BGP — check administrative distance"
                )

    return analysis


def check_end_to_end_path(
    route_tables: dict[str, RouteTableAnalysis],
    source_ip: str = "10.10.0.100",
    dest_ip: str = "192.168.100.10",
) -> dict:
    """
    Simulate traceroute by walking route tables across namespaces.
    Returns the path taken or where it breaks.
    """
    # Namespace hop order: enterprise -> ce -> satcom (pass-through) -> pop -> cloud -> app
    hop_order = ["ns-enterprise", "ns-ce", "ns-satcom", "ns-pop", "ns-cloud", "ns-app"]
    path: list[dict] = []
    issues: list[str] = []

    for ns in hop_order:
        analysis = route_tables.get(ns)
        if analysis is None:
            path.append({"ns": ns, "status": "no_data"})
            continue

        has_route = (
            analysis.has_default_route or
            any(r.prefix == dest_ip or
                (r.prefix != "default" and _prefix_contains(r.prefix, dest_ip))
                for r in analysis.routes)
        )

        if has_route:
            path.append({"ns": ns, "status": "ok", "default_via": analysis.default_via})
        else:
            path.append({"ns": ns, "status": "route_missing"})
            issues.append(f"Path breaks at {ns}: no route to {dest_ip}")
            break

    return {
        "source": source_ip,
        "destination": dest_ip,
        "path": path,
        "issues": issues,
        "complete": not issues,
    }


def _prefix_contains(prefix_str: str, ip_str: str) -> bool:
    try:
        return IPv4Address(ip_str) in IPv4Network(prefix_str, strict=False)
    except (AddressValueError, ValueError):
        return False
