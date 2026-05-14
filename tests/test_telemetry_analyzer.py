"""Tests for telemetry_analyzer.py"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "analyzer"))
sys.path.insert(0, str(Path(__file__).parent.parent / "telemetry/api"))

from telemetry_analyzer import analyze_telemetry_history, compute_stats, detect_degradation_events
from telemetry_generator import generate, IMPAIRMENT_PROFILES


def make_snapshots(profile: str, count: int = 60) -> list[dict]:
    return [generate(profile_name=profile, uptime_seconds=i).model_dump(mode="json")
            for i in range(count)]


class TestComputeStats:
    def test_empty(self):
        stats = compute_stats([], "test")
        assert stats.mean == 0

    def test_normal_distribution(self):
        values = [10.0] * 100
        stats = compute_stats(values, "test")
        assert stats.mean == 10.0
        assert stats.stddev == 0.0
        assert stats.anomaly_count == 0

    def test_anomaly_detection(self):
        values = [10.0] * 99 + [100.0]
        stats = compute_stats(values, "test")
        assert stats.anomaly_count >= 1


class TestDegradationEvents:
    def test_no_events_when_below_threshold(self):
        values = [0.5] * 100
        events = detect_degradation_events(
            values, "loss", threshold=1.0,
            severity_levels={"low": 1.0, "medium": 5.0}
        )
        assert len(events) == 0

    def test_event_detected_above_threshold(self):
        values = [0.1] * 10 + [5.0] * 20 + [0.1] * 10
        events = detect_degradation_events(
            values, "loss", threshold=1.0,
            severity_levels={"low": 1.0, "medium": 5.0}
        )
        assert len(events) == 1
        assert events[0].duration_samples == 20
        assert events[0].severity == "medium"


class TestAnalyzeTelemetry:
    def test_baseline_profile_healthy(self):
        snapshots = make_snapshots("baseline", count=120)
        report = analyze_telemetry_history(snapshots)
        assert report.sample_count == 120
        assert report.link_stability_score > 0.95
        assert report.stats["packet_loss_percent"].mean < 1.0

    def test_link_down_profile_triggers_alerts(self):
        snapshots = make_snapshots("link_down", count=60)
        report = analyze_telemetry_history(snapshots)
        assert report.link_stability_score < 0.1
        assert len(report.alerts) >= 1

    def test_high_latency_profile(self):
        snapshots = make_snapshots("high_latency", count=60)
        report = analyze_telemetry_history(snapshots)
        assert report.stats["latency_ms"].mean > 100

    def test_packet_loss_profile(self):
        snapshots = make_snapshots("packet_loss", count=60)
        report = analyze_telemetry_history(snapshots)
        assert report.stats["packet_loss_percent"].mean > 3.0

    def test_empty_input(self):
        report = analyze_telemetry_history([])
        assert report.sample_count == 0


class TestTelemetryGenerator:
    def test_all_profiles_generate_valid_output(self):
        for profile_name in IMPAIRMENT_PROFILES:
            m = generate(profile_name=profile_name)
            assert 0.0 <= m.packet_loss_percent <= 100.0
            assert m.latency_ms >= 0
            assert 0.0 <= m.signal_quality <= 1.0
            assert m.downlink_mbps >= 0

    def test_link_down_has_zero_throughput(self):
        m = generate(profile_name="link_down")
        assert m.link_state == "down"
        assert m.downlink_mbps == 0.0

    def test_baseline_has_reasonable_latency(self):
        # 10 samples, all should be near 45ms
        latencies = [generate(profile_name="baseline").latency_ms for _ in range(10)]
        avg = sum(latencies) / len(latencies)
        assert 20 < avg < 100, f"Baseline latency mean {avg} out of expected range"
