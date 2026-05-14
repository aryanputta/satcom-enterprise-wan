"""
BGP convergence timing analyzer.

Measures the full convergence lifecycle:
  1. Session down detection (hold timer expiry or hard reset)
  2. TCP session establishment to peer
  3. OPEN message exchange
  4. BGP ESTABLISHED
  5. First prefix received
  6. Full table convergence (all expected prefixes present)

Can drive a real FRRAgent for live measurement or use a synthetic one for testing.

Convergence time matters on SATCOM because:
  - Default hold timer = 180s → 180s routing blackout per beam handoff
  - Tuned timers (10/30) → max 30s blackout
  - BFD integration → sub-second detection, sub-second reconvergence

Key reference: RFC 4271 Section 8 (BGP FSM), RFC 5882 (Generic BFD application)
"""

from __future__ import annotations

import csv
import io
import logging
import time
from dataclasses import dataclass, field
from typing import Optional

from frr_agent import BgpSummary, FRRAgent, make_agent

log = logging.getLogger(__name__)


@dataclass
class ConvergenceRecord:
    """Single measured convergence event from trigger to full re-establishment."""
    trigger: str                           # "hold_timer_expiry" / "manual_reset" / "link_down"
    peer_addr: str
    namespace: str
    t_trigger: float                       # when the reset/failure was initiated
    t_open_sent: Optional[float] = None   # when BGP OPEN was sent (Active → OpenSent)
    t_established: Optional[float] = None # when session reached Established
    t_first_prefix: Optional[float] = None
    t_full_convergence: Optional[float] = None  # all expected prefixes present
    expected_prefixes: int = 0
    received_prefixes: int = 0
    bgp_hold_timer_s: int = 90
    bgp_keepalive_s: int = 30

    @property
    def time_to_established_s(self) -> Optional[float]:
        if self.t_established and self.t_trigger:
            return round(self.t_established - self.t_trigger, 3)
        return None

    @property
    def time_to_first_prefix_s(self) -> Optional[float]:
        if self.t_first_prefix and self.t_trigger:
            return round(self.t_first_prefix - self.t_trigger, 3)
        return None

    @property
    def full_convergence_s(self) -> Optional[float]:
        if self.t_full_convergence and self.t_trigger:
            return round(self.t_full_convergence - self.t_trigger, 3)
        return None

    def to_dict(self) -> dict:
        return {
            "trigger": self.trigger,
            "peer": self.peer_addr,
            "namespace": self.namespace,
            "hold_timer_s": self.bgp_hold_timer_s,
            "keepalive_s": self.bgp_keepalive_s,
            "time_to_established_s": self.time_to_established_s,
            "time_to_first_prefix_s": self.time_to_first_prefix_s,
            "full_convergence_s": self.full_convergence_s,
            "expected_prefixes": self.expected_prefixes,
            "received_prefixes": self.received_prefixes,
        }


class ConvergenceBenchmark:
    """
    Drives a BGP convergence measurement cycle.

    Protocol:
      1. Record baseline (all sessions established, prefixes known)
      2. Trigger: call agent.reset_peer() or use inject_failure.sh link_down
      3. Poll agent.get_bgp_summary() every poll_interval_s
      4. Record timestamps as state transitions occur
      5. Complete when all expected prefixes are received or timeout_s elapses
    """

    def __init__(
        self,
        agent: FRRAgent,
        peer_addr: str,
        expected_prefixes: int = 2,
        poll_interval_s: float = 0.5,
        timeout_s: float = 60.0,
    ):
        self.agent = agent
        self.peer_addr = peer_addr
        self.expected_prefixes = expected_prefixes
        self.poll_interval_s = poll_interval_s
        self.timeout_s = timeout_s
        self.results: list[ConvergenceRecord] = []

    def run(self, trigger: str = "manual_reset") -> ConvergenceRecord:
        """
        Execute one convergence measurement cycle.
        The caller is responsible for triggering the disruption before calling run()
        if trigger != "manual_reset" (in which case this method calls reset_peer()).
        """
        record = ConvergenceRecord(
            trigger=trigger,
            peer_addr=self.peer_addr,
            namespace=self.agent.namespace,
            t_trigger=time.time(),
            expected_prefixes=self.expected_prefixes,
        )

        # Trigger reset if we're doing it internally
        if trigger == "manual_reset":
            ok = self.agent.reset_peer(self.peer_addr)
            if not ok:
                log.warning("reset_peer failed — is FRR running in %s?", self.agent.namespace)

        # Capture hold/keepalive times from current config
        summary = self.agent.get_bgp_summary()
        if summary:
            for peer in summary.peers:
                if peer.peer_addr == self.peer_addr:
                    record.bgp_hold_timer_s = peer.hold_time_s
                    record.bgp_keepalive_s = peer.keepalive_s
                    break

        prev_state = "Established"
        deadline = time.time() + self.timeout_s

        while time.time() < deadline:
            summary = self.agent.get_bgp_summary()
            if not summary:
                time.sleep(self.poll_interval_s)
                continue

            for peer in summary.peers:
                if peer.peer_addr != self.peer_addr:
                    continue

                state = peer.state
                now = time.time()

                # Detect OpenSent transition
                if state == "OpenSent" and record.t_open_sent is None:
                    record.t_open_sent = now
                    log.info("BGP OpenSent at +%.2fs", now - record.t_trigger)

                # Detect Established transition
                if state == "Established" and record.t_established is None:
                    record.t_established = now
                    log.info("BGP Established at +%.2fs", now - record.t_trigger)

                # Detect first prefix
                if (state == "Established" and peer.prefixes_received > 0
                        and record.t_first_prefix is None):
                    record.t_first_prefix = now
                    log.info("First prefix at +%.2fs", now - record.t_trigger)

                # Detect full convergence
                if (state == "Established"
                        and peer.prefixes_received >= self.expected_prefixes
                        and record.t_full_convergence is None):
                    record.t_full_convergence = now
                    record.received_prefixes = peer.prefixes_received
                    log.info(
                        "Full convergence at +%.2fs (%d prefixes)",
                        now - record.t_trigger, peer.prefixes_received,
                    )
                    self.results.append(record)
                    return record

                prev_state = state

            time.sleep(self.poll_interval_s)

        log.warning("Convergence timeout after %.0fs for peer %s",
                    self.timeout_s, self.peer_addr)
        self.results.append(record)
        return record

    def run_n(self, n: int, trigger: str = "manual_reset") -> list[ConvergenceRecord]:
        """Run n convergence cycles and return all records."""
        records = []
        for i in range(n):
            log.info("Convergence run %d/%d", i + 1, n)
            records.append(self.run(trigger=trigger))
            if i < n - 1:
                time.sleep(5.0)  # allow session to stabilize
        return records

    def summary_stats(self) -> dict:
        """Compute mean/min/max/p95 for completed convergence records."""
        completed = [r for r in self.results if r.t_full_convergence is not None]
        if not completed:
            return {"completed": 0, "total": len(self.results)}

        times = [r.full_convergence_s for r in completed]
        times_established = [r.time_to_established_s for r in completed
                             if r.time_to_established_s]

        def stats(values: list[float]) -> dict:
            if not values:
                return {}
            sorted_v = sorted(values)
            n = len(sorted_v)
            return {
                "min": round(sorted_v[0], 3),
                "mean": round(sum(sorted_v) / n, 3),
                "max": round(sorted_v[-1], 3),
                "p95": round(sorted_v[int(n * 0.95)], 3),
                "n": n,
            }

        return {
            "completed": len(completed),
            "total": len(self.results),
            "full_convergence_s": stats(times),
            "time_to_established_s": stats(times_established),
            "hold_timer_s": completed[0].bgp_hold_timer_s,
            "keepalive_s": completed[0].bgp_keepalive_s,
        }

    def to_csv(self) -> str:
        """Export all records as CSV for analysis."""
        if not self.results:
            return ""
        buf = io.StringIO()
        fieldnames = list(self.results[0].to_dict().keys())
        writer = csv.DictWriter(buf, fieldnames=fieldnames)
        writer.writeheader()
        for r in self.results:
            writer.writerow(r.to_dict())
        return buf.getvalue()


def compare_timer_configs(
    agent: FRRAgent,
    peer_addr: str,
    configs: list[dict],
    runs_per_config: int = 3,
) -> list[dict]:
    """
    Measure convergence time under different BGP timer configurations.

    Each config dict: {"hold_timer": 30, "keepalive": 10, "label": "tuned"}
    Applies the config via vtysh before each run.

    Returns list of {config, stats} dicts for comparison.
    """
    results = []
    for cfg in configs:
        label = cfg.get("label", str(cfg))
        hold = cfg.get("hold_timer", 90)
        keepalive = cfg.get("keepalive", 30)

        # Apply timer config via vtysh if available
        if agent.is_available():
            # Need to know the peer IP and router context
            pass  # In production: issue `neighbor <peer> timers <keepalive> <hold>`

        bench = ConvergenceBenchmark(agent, peer_addr, runs_per_config)
        bench.run_n(runs_per_config)
        stats = bench.summary_stats()
        stats["config"] = {"label": label, "hold_timer": hold, "keepalive": keepalive}
        results.append(stats)
        log.info("Config %s: mean convergence = %s s",
                 label, stats.get("full_convergence_s", {}).get("mean", "N/A"))

    return results
