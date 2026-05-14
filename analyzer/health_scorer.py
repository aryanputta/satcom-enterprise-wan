"""
SATCOM WAN Health Scorer.

Produces a composite 0-100 health score from telemetry + routing + VPN + BGP state.
Based on the technical mindset: "where is the bottleneck, what are the constraints,
and how can this be improved under real conditions?"

Score breakdown:
  - Physical link health (L1):   30 points
  - Routing health (L3):         25 points
  - VPN health (L4):             20 points
  - BGP health (L3 control):     15 points
  - Application health (L7):     10 points

Each component scores 0-100 which is then weighted into the final score.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field


@dataclass
class HealthDimension:
    name: str
    score: float          # 0-100
    weight: float         # contribution to total
    issues: list[str] = field(default_factory=list)
    details: str = ""


@dataclass
class HealthReport:
    total_score: float    # 0-100, weighted sum
    grade: str            # A/B/C/D/F
    dimensions: list[HealthDimension]
    critical_issues: list[str]
    summary: str

    @property
    def healthy(self) -> bool:
        return self.total_score >= 70


def score_link_health(telemetry: dict) -> HealthDimension:
    """Layer 1 + 2: physical link quality."""
    issues = []
    score = 100.0

    link_state = telemetry.get("link_state", "unknown")
    if link_state == "down":
        return HealthDimension("Physical Link", 0.0, 0.30, ["Link is completely down"], "link_state=down")
    elif link_state == "degraded":
        score -= 30
        issues.append(f"Link degraded (state={link_state})")

    loss = telemetry.get("packet_loss_percent", 0.0)
    if loss >= 10:
        score -= 55; issues.append(f"Critical packet loss: {loss:.1f}%")
    elif loss >= 5:
        score -= 30; issues.append(f"High packet loss: {loss:.1f}%")
    elif loss >= 1:
        score -= 12; issues.append(f"Elevated packet loss: {loss:.1f}%")

    sig = telemetry.get("signal_quality", 1.0)
    if sig < 0.3:
        score -= 30; issues.append(f"Critical signal quality: {sig:.2f}")
    elif sig < 0.7:
        score -= 15; issues.append(f"Low signal quality: {sig:.2f}")

    temp = telemetry.get("modem_temperature_c", 42.0)
    if temp >= 80:
        score -= 20; issues.append(f"Critical modem temperature: {temp:.0f}°C")
    elif temp >= 70:
        score -= 8; issues.append(f"High modem temperature: {temp:.0f}°C")

    obst = telemetry.get("obstruction_percent", 0.0)
    if obst >= 20:
        score -= 20; issues.append(f"High obstruction: {obst:.1f}%")
    elif obst >= 10:
        score -= 8; issues.append(f"Moderate obstruction: {obst:.1f}%")

    return HealthDimension(
        "Physical Link", max(0.0, score), 0.30, issues,
        f"loss={loss:.2f}% sig={sig:.3f} temp={temp:.0f}°C"
    )


def score_routing_health(telemetry: dict, routes: dict, nat_table: str) -> HealthDimension:
    """Layer 3: routing, NAT, and addressing."""
    issues = []
    score = 100.0

    # NAT check
    if nat_table and "MASQUERADE" not in nat_table:
        score -= 35
        issues.append("NAT MASQUERADE rule missing — outbound traffic will be dropped by upstream")

    # Route count sanity
    route_count = telemetry.get("route_count", 0)
    if route_count == 0:
        score -= 40
        issues.append("No routes in routing table")
    elif route_count < 3:
        score -= 15
        issues.append(f"Low route count ({route_count}) — BGP routes may be missing")

    # Check for default route at CE
    ce_routes = routes.get("ns-ce", routes.get("ce", ""))
    if ce_routes and "default" not in ce_routes and "0.0.0.0/0" not in ce_routes:
        score -= 25
        issues.append("No default route at CE router")

    # Latency (routing delay adds up)
    lat = telemetry.get("latency_ms", 0.0)
    if lat >= 500:
        score -= 15; issues.append(f"Very high latency: {lat:.0f}ms — TCP will suffer severely")
    elif lat >= 200:
        score -= 5; issues.append(f"High latency: {lat:.0f}ms")

    return HealthDimension(
        "Routing / NAT", max(0.0, score), 0.25, issues,
        f"routes={route_count} lat={lat:.0f}ms"
    )


def score_vpn_health(telemetry: dict) -> HealthDimension:
    """Layer 4: VPN tunnel state."""
    vpn_state = telemetry.get("vpn_state", "not_configured")
    issues = []

    if vpn_state == "not_configured":
        return HealthDimension("VPN Tunnel", 100.0, 0.20, [], "not configured (not a fault)")
    if vpn_state == "up":
        return HealthDimension("VPN Tunnel", 100.0, 0.20, [], "tunnel up")
    if vpn_state == "handshaking":
        return HealthDimension("VPN Tunnel", 30.0, 0.20,
                               ["VPN stuck in handshake — check firewall and peer config"],
                               "handshaking")
    if vpn_state == "down":
        return HealthDimension("VPN Tunnel", 0.0, 0.20,
                               ["VPN tunnel is down — check UDP 51820 and peer reachability"],
                               "down")
    return HealthDimension("VPN Tunnel", 50.0, 0.20, [f"Unknown VPN state: {vpn_state}"], vpn_state)


def score_bgp_health(telemetry: dict) -> HealthDimension:
    """Layer 3 control plane: BGP session state."""
    bgp_state = telemetry.get("bgp_state", "not_configured")
    issues = []

    if bgp_state == "not_configured":
        return HealthDimension("BGP Session", 100.0, 0.15, [], "not configured (not a fault)")
    if bgp_state == "established":
        return HealthDimension("BGP Session", 100.0, 0.15, [], "session established")
    if bgp_state in ("active", "connect"):
        return HealthDimension("BGP Session", 20.0, 0.15,
                               [f"BGP stuck in {bgp_state} — check remote-as config and TCP 179"],
                               bgp_state)
    if bgp_state == "idle":
        return HealthDimension("BGP Session", 10.0, 0.15,
                               ["BGP in idle — check BGP daemon and peer configuration"],
                               bgp_state)
    return HealthDimension("BGP Session", 50.0, 0.15, [f"Unknown BGP state: {bgp_state}"], bgp_state)


def score_application_health(telemetry: dict, pcap_summary: dict) -> HealthDimension:
    """Layer 7: DNS, application reachability indicators."""
    issues = []
    score = 100.0

    pcap_text = str(pcap_summary).lower()
    if "dns" in pcap_text and ("no response" in pcap_text or "timeout" in pcap_text):
        score -= 40
        issues.append("DNS failures detected in packet captures")
    if "nxdomain" in pcap_text:
        score -= 15
        issues.append("DNS NXDOMAIN responses detected")

    # High latency degrades application experience even if network is technically up
    lat = telemetry.get("latency_ms", 0)
    if lat >= 400:
        score -= 20; issues.append(f"Latency {lat:.0f}ms will cause application timeouts with default settings")

    return HealthDimension("Application Layer", max(0.0, score), 0.10, issues, f"lat={lat:.0f}ms")


def compute_health_score(
    telemetry: dict,
    routes: dict,
    nat_table: str,
    pcap_summary: dict,
) -> HealthReport:
    """Compute composite health score from all available diagnostics."""
    dimensions = [
        score_link_health(telemetry),
        score_routing_health(telemetry, routes, nat_table),
        score_vpn_health(telemetry),
        score_bgp_health(telemetry),
        score_application_health(telemetry, pcap_summary),
    ]

    total = sum(d.score * d.weight for d in dimensions)
    total = round(total, 1)

    # Link-down is a hard cap — if physical link is completely down, overall score <= 40
    link_dim = next((d for d in dimensions if d.name == "Physical Link"), None)
    if link_dim and link_dim.score == 0.0:
        total = min(total, 40.0)

    if total >= 90: grade = "A"
    elif total >= 80: grade = "B"
    elif total >= 70: grade = "C"
    elif total >= 50: grade = "D"
    else: grade = "F"

    critical = [issue for d in dimensions for issue in d.issues if d.score < 50]

    if total >= 90:
        summary = "System healthy — all layers operating normally"
    elif total >= 70:
        summary = f"System degraded — {sum(1 for d in dimensions if d.issues)} layer(s) with issues"
    elif total >= 50:
        summary = f"System impaired — significant failures in {sum(1 for d in dimensions if d.score < 50)} layer(s)"
    else:
        summary = f"System critically impaired — grade {grade}, {len(critical)} critical issue(s)"

    return HealthReport(
        total_score=total,
        grade=grade,
        dimensions=dimensions,
        critical_issues=critical,
        summary=summary,
    )
