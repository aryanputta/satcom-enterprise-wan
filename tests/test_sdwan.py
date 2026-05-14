"""Tests for sdwan/policy_engine.py"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "sdwan"))

from policy_engine import (
    TRAFFIC_CLASSES, WanLink, LinkMetrics, PolicyEngine,
    score_link, make_decision, default_lab_links,
    _score_latency, _score_loss, _score_bandwidth,
)


def healthy_metrics(**overrides) -> LinkMetrics:
    base = LinkMetrics(latency_ms=45, loss_pct=0.1, bandwidth_mbps=140, available=True)
    for k, v in overrides.items():
        setattr(base, k, v)
    return base


def degraded_metrics(**overrides) -> LinkMetrics:
    base = LinkMetrics(latency_ms=580, loss_pct=7.0, bandwidth_mbps=20, available=True)
    for k, v in overrides.items():
        setattr(base, k, v)
    return base


class TestScoringFunctions:
    def test_latency_within_budget_scores_1(self):
        assert _score_latency(45, 150) == 1.0

    def test_latency_at_budget_scores_1(self):
        assert _score_latency(150, 150) == 1.0

    def test_latency_beyond_budget_less_than_1(self):
        assert _score_latency(400, 150) < 1.0

    def test_latency_at_4x_budget_scores_near_zero(self):
        assert _score_latency(600, 150) <= 0.1

    def test_loss_within_budget_scores_1(self):
        assert _score_loss(0.1, 0.5) == 1.0

    def test_loss_zero_scores_1(self):
        assert _score_loss(0.0, 0.5) == 1.0

    def test_loss_high_scores_low(self):
        assert _score_loss(10.0, 0.5) < 0.3

    def test_bandwidth_above_min_scores_1(self):
        assert _score_bandwidth(140, 10) == 1.0

    def test_bandwidth_zero_scores_zero(self):
        assert _score_bandwidth(0, 10) == 0.0

    def test_bandwidth_half_min_scores_half(self):
        score = _score_bandwidth(5.0, 10.0)
        assert 0.45 < score < 0.55


class TestLinkScoring:
    def test_healthy_satcom_scores_high_for_bulk(self):
        link = WanLink("satcom", "eth1", "100.64.0.2", 1, metrics=healthy_metrics())
        tc = TRAFFIC_CLASSES["bulk"]
        s = score_link(link, tc)
        assert s >= 0.8

    def test_high_latency_scores_low_for_voice(self):
        link = WanLink("satcom", "eth1", "100.64.0.2", 1, metrics=degraded_metrics())
        tc = TRAFFIC_CLASSES["voice"]
        s = score_link(link, tc)
        assert s < 0.5

    def test_unavailable_link_scores_zero(self):
        link = WanLink("satcom", "eth1", "100.64.0.2", 1,
                       metrics=healthy_metrics(available=False))
        s = score_link(link, TRAFFIC_CLASSES["default"])
        assert s == 0.0

    def test_admin_down_scores_zero(self):
        link = WanLink("satcom", "eth1", "100.64.0.2", 1,
                       metrics=healthy_metrics(), admin_up=False)
        s = score_link(link, TRAFFIC_CLASSES["voice"])
        assert s == 0.0

    def test_lte_beats_satcom_for_voice_when_satcom_degraded(self):
        satcom = WanLink("satcom", "eth1", "100.64.0.2", 1, metrics=degraded_metrics())
        lte = WanLink("lte", "eth2", "10.99.0.1", 2,
                      metrics=LinkMetrics(latency_ms=25, loss_pct=0.2,
                                         bandwidth_mbps=50, available=True))
        tc = TRAFFIC_CLASSES["voice"]
        assert score_link(lte, tc) > score_link(satcom, tc)


class TestPolicyDecision:
    def test_selects_best_link(self):
        satcom = WanLink("satcom", "eth1", "100.64.0.2", 1, metrics=healthy_metrics())
        lte    = WanLink("lte",    "eth2", "10.99.0.1",  2,
                         metrics=LinkMetrics(latency_ms=580, loss_pct=7, bandwidth_mbps=20))
        dec = make_decision(TRAFFIC_CLASSES["voice"], [satcom, lte])
        assert dec.selected_link == "satcom"

    def test_failover_when_primary_down(self):
        satcom = WanLink("satcom", "eth1", "100.64.0.2", 1,
                         metrics=LinkMetrics(available=False))
        lte    = WanLink("lte",    "eth2", "10.99.0.1",  2,
                         metrics=LinkMetrics(latency_ms=25, loss_pct=0.2,
                                            bandwidth_mbps=50, available=True))
        dec = make_decision(TRAFFIC_CLASSES["voice"], [satcom, lte])
        assert dec.selected_link == "lte"

    def test_no_links_returns_none_selected(self):
        dec = make_decision(TRAFFIC_CLASSES["voice"], [])
        assert dec.selected_link == "none"

    def test_provides_fallback_link(self):
        satcom = WanLink("satcom", "eth1", "100.64.0.2", 1, metrics=healthy_metrics())
        lte    = WanLink("lte",    "eth2", "10.99.0.1",  2,
                         metrics=LinkMetrics(latency_ms=25, loss_pct=0.2,
                                            bandwidth_mbps=50, available=True))
        dec = make_decision(TRAFFIC_CLASSES["bulk"], [satcom, lte])
        assert dec.fallback_link is not None


class TestPolicyEngine:
    def test_run_policy_returns_decision_per_tc(self):
        engine = PolicyEngine(links=default_lab_links())
        decisions = engine.run_policy()
        assert len(decisions) == len(TRAFFIC_CLASSES)

    def test_update_metrics_changes_decision(self):
        engine = PolicyEngine(links=default_lab_links())
        # Make satcom unavailable
        engine.update_metrics("satcom", LinkMetrics(available=False))
        decisions = engine.run_policy()
        for d in decisions:
            if d.selected_link != "none":
                assert d.selected_link == "lte_backup"

    def test_summary_contains_links_and_decisions(self):
        engine = PolicyEngine(links=default_lab_links())
        engine.run_policy()
        summary = engine.get_summary()
        assert "links" in summary
        assert "decisions" in summary
        assert len(summary["links"]) == 2

    def test_failover_event_logged(self):
        engine = PolicyEngine(links=default_lab_links())
        engine.run_policy()  # baseline
        engine.update_metrics("satcom", LinkMetrics(available=False))
        engine.run_policy()  # should detect failover
        assert any("FAILOVER" in ev["event"] or "LINK DOWN" in ev["event"]
                   for ev in engine._event_log)

    def test_dry_run_returns_commands_not_executed(self):
        engine = PolicyEngine(links=default_lab_links())
        decisions = engine.run_policy()
        cmds = engine.apply(decisions, dry_run=True)
        assert isinstance(cmds, list)
        assert all(isinstance(c, str) for c in cmds)

    def test_update_from_telemetry_dict(self):
        engine = PolicyEngine(links=default_lab_links())
        engine.update_from_telemetry_dict("satcom", {
            "latency_ms": 580.0,
            "packet_loss_percent": 7.0,
            "downlink_mbps": 15.0,
            "link_state": "degraded",
        })
        link = engine.links_by_name["satcom"]
        assert link.metrics.latency_ms == 580.0

    def test_score_between_0_and_1(self):
        for link in default_lab_links():
            for tc in TRAFFIC_CLASSES.values():
                s = score_link(link, tc)
                assert 0.0 <= s <= 1.0
