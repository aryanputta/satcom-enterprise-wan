"""
SD-WAN Policy Engine for SATCOM enterprise edge.

Makes real-time WAN link selection decisions based on telemetry SLA thresholds.
Supports SATCOM primary / LTE backup / MPLS tertiary topology with per-traffic-class
routing via Linux ip rule + ip route policy routing tables.

Architecture:
  Telemetry feed → LinkScorer → PolicyDecision → RouteInjector
                                                 → ip rule (fwmark)
                                                 → ip route table <N>

Traffic classes (based on DSCP / iptables fwmark):
  VOICE  — EF DSCP 46 — budget: <200ms, <0.5% loss
  VIDEO  — AF41 DSCP 34 — budget: <400ms, <2% loss, ≥10 Mbps
  BULK   — CS1 DSCP 8  — best-effort, tolerates >500ms, >5% loss
  DEFAULT — CS0 DSCP 0 — general traffic, intermediate thresholds

Link scoring (0.0–1.0):
  Each link is scored per traffic class based on how well it meets SLA.
  Score = w_latency * latency_score + w_loss * loss_score + w_bw * bw_score
  where each sub-score is 1.0 if within budget, declining linearly outside.

Route injection uses Linux policy routing (RFC 1812):
  ip rule add fwmark <mark> lookup <table>
  ip route add default via <gateway> dev <iface> table <table>
  iptables -t mangle -A PREROUTING -p tcp --sport 5060 -j MARK --set-mark <mark>
"""

from __future__ import annotations

import json
import logging
import subprocess
import time
from dataclasses import dataclass, field
from enum import IntEnum
from pathlib import Path
from typing import Optional

log = logging.getLogger(__name__)


# ── Traffic Classes ───────────────────────────────────────────────────────────

class DSCP(IntEnum):
    EF   = 46   # Expedited Forwarding — voice
    AF41 = 34   # Assured Forwarding 4.1 — video
    CS1  = 8    # Class Selector 1 — bulk/scavenger
    CS0  = 0    # Default


@dataclass
class TrafficClass:
    name: str
    dscp: DSCP
    fwmark: int                # iptables mark for policy routing
    route_table: int           # Linux routing table number

    # SLA budgets — used for link scoring
    latency_budget_ms: float
    loss_budget_pct: float
    bw_min_mbps: float

    # Scoring weights (must sum to 1.0)
    w_latency: float = 0.50
    w_loss: float    = 0.35
    w_bw: float      = 0.15


TRAFFIC_CLASSES: dict[str, TrafficClass] = {
    "voice": TrafficClass(
        name="voice", dscp=DSCP.EF, fwmark=10, route_table=110,
        latency_budget_ms=150, loss_budget_pct=0.5, bw_min_mbps=1.0,
        w_latency=0.60, w_loss=0.35, w_bw=0.05,
    ),
    "video": TrafficClass(
        name="video", dscp=DSCP.AF41, fwmark=20, route_table=120,
        latency_budget_ms=400, loss_budget_pct=2.0, bw_min_mbps=10.0,
        w_latency=0.35, w_loss=0.35, w_bw=0.30,
    ),
    "bulk": TrafficClass(
        name="bulk", dscp=DSCP.CS1, fwmark=30, route_table=130,
        latency_budget_ms=2000, loss_budget_pct=10.0, bw_min_mbps=0.5,
        w_latency=0.10, w_loss=0.20, w_bw=0.70,
    ),
    "default": TrafficClass(
        name="default", dscp=DSCP.CS0, fwmark=40, route_table=140,
        latency_budget_ms=500, loss_budget_pct=5.0, bw_min_mbps=5.0,
        w_latency=0.40, w_loss=0.35, w_bw=0.25,
    ),
}


# ── WAN Link model ────────────────────────────────────────────────────────────

@dataclass
class LinkMetrics:
    latency_ms: float = 0.0
    loss_pct: float = 0.0
    bandwidth_mbps: float = 0.0
    jitter_ms: float = 0.0
    available: bool = True
    timestamp: float = field(default_factory=time.time)

    @property
    def age_s(self) -> float:
        return time.time() - self.timestamp

    @property
    def stale(self) -> bool:
        return self.age_s > 30.0


@dataclass
class WanLink:
    name: str                    # "satcom", "lte_backup", "mpls"
    iface: str                   # Linux interface (e.g. "eth1", "wwan0")
    gateway: str                 # Next-hop IP
    priority: int                # Lower = preferred when scores are equal
    metrics: LinkMetrics = field(default_factory=LinkMetrics)
    admin_up: bool = True

    @property
    def available(self) -> bool:
        return self.admin_up and self.metrics.available and not self.metrics.stale


# ── Scoring engine ────────────────────────────────────────────────────────────

def _score_latency(lat_ms: float, budget_ms: float) -> float:
    if lat_ms <= budget_ms:
        return 1.0
    # Linear decay: 2x budget → 0.5 score, 4x budget → 0.0
    return max(0.0, 1.0 - (lat_ms - budget_ms) / (3 * budget_ms))


def _score_loss(loss_pct: float, budget_pct: float) -> float:
    if loss_pct <= budget_pct:
        return 1.0
    return max(0.0, 1.0 - (loss_pct - budget_pct) / (5 * budget_pct + 0.01))


def _score_bandwidth(bw_mbps: float, min_mbps: float) -> float:
    if bw_mbps >= min_mbps:
        return 1.0
    return max(0.0, bw_mbps / (min_mbps + 0.01))


def score_link(link: WanLink, tc: TrafficClass) -> float:
    """
    Score a WAN link for a given traffic class.
    Returns 0.0 if the link is unavailable.
    """
    if not link.available:
        return 0.0
    m = link.metrics
    s_lat = _score_latency(m.latency_ms, tc.latency_budget_ms)
    s_loss = _score_loss(m.loss_pct, tc.loss_budget_pct)
    s_bw = _score_bandwidth(m.bandwidth_mbps, tc.bw_min_mbps)
    return tc.w_latency * s_lat + tc.w_loss * s_loss + tc.w_bw * s_bw


# ── Policy decision ───────────────────────────────────────────────────────────

@dataclass
class PolicyDecision:
    tc_name: str
    selected_link: str
    score: float
    fallback_link: Optional[str]
    fallback_score: float
    reason: str
    timestamp: float = field(default_factory=time.time)


def make_decision(
    tc: TrafficClass,
    links: list[WanLink],
) -> PolicyDecision:
    """Select the best available link for a traffic class."""
    scored = sorted(
        [(link, score_link(link, tc)) for link in links if link.available],
        key=lambda x: (-x[1], x[0].priority),
    )
    if not scored:
        return PolicyDecision(
            tc_name=tc.name,
            selected_link="none",
            score=0.0,
            fallback_link=None,
            fallback_score=0.0,
            reason="no links available",
        )
    best = scored[0]
    fallback = scored[1] if len(scored) > 1 else None
    reason = (
        f"lat={best[0].metrics.latency_ms:.0f}ms "
        f"loss={best[0].metrics.loss_pct:.1f}% "
        f"bw={best[0].metrics.bandwidth_mbps:.0f}Mbps"
    )
    return PolicyDecision(
        tc_name=tc.name,
        selected_link=best[0].name,
        score=round(best[1], 4),
        fallback_link=fallback[0].name if fallback else None,
        fallback_score=round(fallback[1], 4) if fallback else 0.0,
        reason=reason,
    )


# ── Route injector ────────────────────────────────────────────────────────────

def _run_cmd(cmd: list[str], dry_run: bool = False) -> tuple[bool, str]:
    if dry_run:
        return True, " ".join(cmd)
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        if r.returncode != 0:
            log.warning("cmd failed: %s — %s", " ".join(cmd), r.stderr.strip())
        return r.returncode == 0, r.stdout.strip()
    except Exception as exc:
        log.error("cmd error: %s — %s", " ".join(cmd), exc)
        return False, str(exc)


def build_route_commands(
    decision: PolicyDecision,
    tc: TrafficClass,
    links_by_name: dict[str, WanLink],
    ns: Optional[str] = None,
) -> list[list[str]]:
    """
    Build ip rule + ip route commands to enforce a policy decision.
    Prefix with `ip netns exec <ns>` when namespace is given.
    """
    prefix = ["ip", "netns", "exec", ns] if ns else []
    cmds: list[list[str]] = []
    link = links_by_name.get(decision.selected_link)
    if not link:
        return cmds

    # Flush existing route for this table
    cmds.append(prefix + ["ip", "route", "flush", "table", str(tc.route_table)])

    # Add default via selected link into policy table
    cmds.append(prefix + [
        "ip", "route", "add", "default",
        "via", link.gateway,
        "dev", link.iface,
        "table", str(tc.route_table),
    ])

    # Ensure ip rule exists for this fwmark
    cmds.append(prefix + [
        "ip", "rule", "add",
        "fwmark", str(tc.fwmark),
        "lookup", str(tc.route_table),
        "prio", str(10000 + tc.fwmark),
    ])

    return cmds


def inject_routes(
    decisions: list[PolicyDecision],
    links_by_name: dict[str, WanLink],
    dry_run: bool = False,
    ns: Optional[str] = None,
) -> list[str]:
    """
    Apply all policy routing decisions.
    Returns list of commands that were run (useful for dry-run audit).
    """
    executed: list[str] = []
    for dec in decisions:
        tc = TRAFFIC_CLASSES.get(dec.tc_name)
        if not tc:
            continue
        cmds = build_route_commands(dec, tc, links_by_name, ns=ns)
        for cmd in cmds:
            ok, out = _run_cmd(cmd, dry_run=dry_run)
            executed.append(" ".join(cmd))
            if not ok and not dry_run:
                log.warning("route injection failed: %s", " ".join(cmd))
    return executed


# ── Main engine class ─────────────────────────────────────────────────────────

class PolicyEngine:
    """
    Stateful SD-WAN policy engine.

    Typical usage in a telemetry loop:
        engine = PolicyEngine(links=[satcom_link, lte_link])
        while True:
            engine.update_metrics("satcom", satcom_metrics)
            engine.update_metrics("lte_backup", lte_metrics)
            decisions = engine.run_policy()
            engine.apply(decisions, dry_run=False)
            time.sleep(5)
    """

    def __init__(
        self,
        links: list[WanLink],
        traffic_classes: Optional[dict[str, TrafficClass]] = None,
        failover_threshold: float = 0.30,
        namespace: Optional[str] = None,
    ):
        self.links = links
        self.links_by_name = {l.name: l for l in links}
        self.tcs = traffic_classes or TRAFFIC_CLASSES
        self.failover_threshold = failover_threshold
        self.namespace = namespace
        self._last_decisions: list[PolicyDecision] = []
        self._event_log: list[dict] = []

    def update_metrics(self, link_name: str, metrics: LinkMetrics) -> None:
        link = self.links_by_name.get(link_name)
        if link:
            old = link.metrics
            link.metrics = metrics
            # Log failover events
            if old.available and not metrics.available:
                self._log_event(f"{link_name}: LINK DOWN")
            elif not old.available and metrics.available:
                self._log_event(f"{link_name}: LINK RESTORED")

    def update_from_telemetry_dict(self, link_name: str, telemetry: dict) -> None:
        """Accept a telemetry dict (from synthetic or real_collector)."""
        self.update_metrics(link_name, LinkMetrics(
            latency_ms=telemetry.get("latency_ms", 0.0),
            loss_pct=telemetry.get("packet_loss_percent", 0.0),
            bandwidth_mbps=telemetry.get("downlink_mbps", 0.0),
            jitter_ms=telemetry.get("jitter_ms", 0.0),
            available=telemetry.get("link_state", "down") != "down",
        ))

    def run_policy(self) -> list[PolicyDecision]:
        decisions = [
            make_decision(tc, self.links)
            for tc in self.tcs.values()
        ]
        self._detect_failovers(decisions)
        self._last_decisions = decisions
        return decisions

    def apply(self, decisions: list[PolicyDecision], dry_run: bool = False) -> list[str]:
        return inject_routes(decisions, self.links_by_name,
                             dry_run=dry_run, ns=self.namespace)

    def get_summary(self) -> dict:
        return {
            "links": [
                {
                    "name": l.name,
                    "available": l.available,
                    "latency_ms": l.metrics.latency_ms,
                    "loss_pct": l.metrics.loss_pct,
                    "bw_mbps": l.metrics.bandwidth_mbps,
                    "metrics_age_s": round(l.metrics.age_s, 1),
                }
                for l in self.links
            ],
            "decisions": [
                {
                    "class": d.tc_name,
                    "link": d.selected_link,
                    "score": d.score,
                    "fallback": d.fallback_link,
                }
                for d in self._last_decisions
            ],
            "events": self._event_log[-10:],
        }

    def _detect_failovers(self, decisions: list[PolicyDecision]) -> None:
        if not self._last_decisions:
            return
        prev = {d.tc_name: d.selected_link for d in self._last_decisions}
        for d in decisions:
            if prev.get(d.tc_name) != d.selected_link:
                self._log_event(
                    f"FAILOVER [{d.tc_name}]: "
                    f"{prev.get(d.tc_name, '?')} → {d.selected_link} "
                    f"(score {d.score:.2f})"
                )

    def _log_event(self, msg: str) -> None:
        entry = {"ts": time.strftime("%H:%M:%S"), "event": msg}
        self._event_log.append(entry)
        log.info("SD-WAN event: %s", msg)


# ── Default topology for the SATCOM lab ───────────────────────────────────────

def default_lab_links() -> list[WanLink]:
    """
    Standard 2-link topology matching the lab setup:
      SATCOM primary  — CE eth1, gateway 100.64.0.2 (SATCOM WAN)
      LTE backup      — CE eth2, gateway 10.99.0.1  (simulated cellular)
    """
    return [
        WanLink(
            name="satcom",
            iface="eth1",
            gateway="100.64.0.2",
            priority=1,
            metrics=LinkMetrics(latency_ms=45, loss_pct=0.1,
                                bandwidth_mbps=140, available=True),
        ),
        WanLink(
            name="lte_backup",
            iface="eth2",
            gateway="10.99.0.1",
            priority=2,
            metrics=LinkMetrics(latency_ms=25, loss_pct=0.3,
                                bandwidth_mbps=50, available=True),
        ),
    ]
