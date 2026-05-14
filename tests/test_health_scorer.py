"""Tests for health_scorer.py"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "analyzer"))

from health_scorer import compute_health_score, score_link_health, score_bgp_health, score_vpn_health


def healthy_telemetry(**overrides):
    base = {
        "latency_ms": 45.0, "packet_loss_percent": 0.1, "signal_quality": 0.97,
        "downlink_mbps": 140.0, "uplink_mbps": 28.0, "modem_temperature_c": 44.0,
        "link_state": "up", "vpn_state": "not_configured", "bgp_state": "not_configured",
        "route_count": 5, "nat_table_size": 120, "obstruction_percent": 1.0,
    }
    base.update(overrides)
    return base


GOOD_ROUTES = {"ns-ce": "default via 100.64.0.2 dev eth1 proto static\n10.10.0.0/24 dev eth0"}
GOOD_NAT    = "Chain POSTROUTING\nMASQUERADE all -- 10.10.0.0/24"
BAD_NAT     = "Chain POSTROUTING (policy ACCEPT)\n"


class TestLinkScorer:
    def test_healthy_link_scores_100(self):
        d = score_link_health(healthy_telemetry())
        assert d.score == 100.0

    def test_link_down_scores_zero(self):
        d = score_link_health(healthy_telemetry(link_state="down"))
        assert d.score == 0.0

    def test_high_loss_reduces_score(self):
        d = score_link_health(healthy_telemetry(packet_loss_percent=5.0))
        assert d.score < 80

    def test_critical_loss_reduces_heavily(self):
        d = score_link_health(healthy_telemetry(packet_loss_percent=15.0))
        assert d.score < 50

    def test_thermal_issue_reduces_score(self):
        d = score_link_health(healthy_telemetry(modem_temperature_c=82.0))
        assert d.score < 90

    def test_obstruction_reduces_score(self):
        d = score_link_health(healthy_telemetry(obstruction_percent=25.0))
        assert d.score < 90


class TestBgpScorer:
    def test_not_configured_is_healthy(self):
        d = score_bgp_health(healthy_telemetry(bgp_state="not_configured"))
        assert d.score == 100.0

    def test_established_is_healthy(self):
        d = score_bgp_health(healthy_telemetry(bgp_state="established"))
        assert d.score == 100.0

    def test_active_state_low_score(self):
        d = score_bgp_health(healthy_telemetry(bgp_state="active"))
        assert d.score <= 30

    def test_idle_state_very_low(self):
        d = score_bgp_health(healthy_telemetry(bgp_state="idle"))
        assert d.score <= 15


class TestVpnScorer:
    def test_not_configured_is_healthy(self):
        d = score_vpn_health(healthy_telemetry(vpn_state="not_configured"))
        assert d.score == 100.0

    def test_up_is_healthy(self):
        d = score_vpn_health(healthy_telemetry(vpn_state="up"))
        assert d.score == 100.0

    def test_down_scores_zero(self):
        d = score_vpn_health(healthy_telemetry(vpn_state="down"))
        assert d.score == 0.0

    def test_handshaking_low_score(self):
        d = score_vpn_health(healthy_telemetry(vpn_state="handshaking"))
        assert d.score <= 40


class TestCompositeScore:
    def test_healthy_system_grade_a(self):
        report = compute_health_score(healthy_telemetry(), GOOD_ROUTES, GOOD_NAT, {})
        assert report.total_score >= 90
        assert report.grade == "A"
        assert report.healthy

    def test_link_down_grade_f(self):
        report = compute_health_score(
            healthy_telemetry(link_state="down", packet_loss_percent=100.0),
            GOOD_ROUTES, GOOD_NAT, {}
        )
        assert report.grade in ("D", "F")
        assert not report.healthy

    def test_nat_missing_reduces_score(self):
        healthy = compute_health_score(healthy_telemetry(), GOOD_ROUTES, GOOD_NAT, {})
        broken  = compute_health_score(healthy_telemetry(), GOOD_ROUTES, BAD_NAT, {})
        assert broken.total_score < healthy.total_score

    def test_bgp_down_reduces_score(self):
        healthy = compute_health_score(healthy_telemetry(bgp_state="established"), GOOD_ROUTES, GOOD_NAT, {})
        broken  = compute_health_score(healthy_telemetry(bgp_state="idle"), GOOD_ROUTES, GOOD_NAT, {})
        assert broken.total_score < healthy.total_score

    def test_multiple_failures_accumulate(self):
        report = compute_health_score(
            healthy_telemetry(
                link_state="degraded",
                packet_loss_percent=5.0,
                bgp_state="active",
                vpn_state="down",
            ),
            GOOD_ROUTES, BAD_NAT, {}
        )
        assert report.total_score < 50
        assert len(report.critical_issues) >= 2

    def test_score_between_0_and_100(self):
        for loss in [0, 1, 5, 10, 50, 100]:
            tm = healthy_telemetry(packet_loss_percent=float(loss))
            if loss >= 100:
                tm["link_state"] = "down"
            report = compute_health_score(tm, GOOD_ROUTES, GOOD_NAT, {})
            assert 0.0 <= report.total_score <= 100.0

    def test_dimensions_sum_to_correct_weight(self):
        report = compute_health_score(healthy_telemetry(), GOOD_ROUTES, GOOD_NAT, {})
        total_weight = sum(d.weight for d in report.dimensions)
        assert abs(total_weight - 1.0) < 0.001
