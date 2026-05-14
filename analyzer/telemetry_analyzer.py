"""
Telemetry stream analyzer.

Processes historical telemetry JSON (list of SatcomTerminalMetrics snapshots)
and produces trend analysis including:
  - Rolling average latency/loss
  - Anomaly detection using Z-score on latency and loss
  - Link stability score
  - Degradation event detection (e.g., rain fade onset)
  - Throughput efficiency (actual vs theoretical max)
"""

from __future__ import annotations

import json
import math
import statistics
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


@dataclass
class TelemetryStats:
    metric: str
    mean: float
    stddev: float
    min_val: float
    max_val: float
    p95: float
    p99: float
    anomaly_count: int
    anomaly_threshold_z: float = 2.5


@dataclass
class DegradationEvent:
    start_index: int
    end_index: int
    duration_samples: int
    trigger_metric: str
    trigger_value: float
    threshold: float
    severity: str  # low / medium / high / critical


@dataclass
class TelemetryReport:
    sample_count: int
    duration_seconds: float
    stats: dict[str, TelemetryStats]
    link_stability_score: float  # 0..1 (1 = perfectly stable)
    degradation_events: list[DegradationEvent]
    vpn_flaps: int
    bgp_flaps: int
    throughput_efficiency_percent: float
    summary: str
    alerts: list[str] = field(default_factory=list)


def _percentile(data: list[float], p: float) -> float:
    if not data:
        return 0.0
    sorted_data = sorted(data)
    index = (p / 100) * (len(sorted_data) - 1)
    lower = int(index)
    upper = min(lower + 1, len(sorted_data) - 1)
    return sorted_data[lower] + (index - lower) * (sorted_data[upper] - sorted_data[lower])


def compute_stats(values: list[float], metric: str) -> TelemetryStats:
    if not values:
        return TelemetryStats(metric=metric, mean=0, stddev=0,
                             min_val=0, max_val=0, p95=0, p99=0, anomaly_count=0)
    mean = statistics.mean(values)
    stddev = statistics.pstdev(values) if len(values) > 1 else 0.0
    z_thresh = 2.5
    anomaly_count = sum(1 for v in values if stddev > 0 and abs(v - mean) / stddev > z_thresh)
    return TelemetryStats(
        metric=metric,
        mean=round(mean, 3),
        stddev=round(stddev, 3),
        min_val=round(min(values), 3),
        max_val=round(max(values), 3),
        p95=round(_percentile(values, 95), 3),
        p99=round(_percentile(values, 99), 3),
        anomaly_count=anomaly_count,
    )


def detect_degradation_events(
    values: list[float], metric: str, threshold: float, severity_levels: dict
) -> list[DegradationEvent]:
    """Detect contiguous windows where metric exceeds threshold."""
    events: list[DegradationEvent] = []
    in_event = False
    start = 0

    for i, v in enumerate(values):
        if v > threshold and not in_event:
            in_event = True
            start = i
        elif v <= threshold and in_event:
            in_event = False
            duration = i - start
            if duration >= 2:  # minimum 2 samples to be an event
                peak = max(values[start:i])
                severity = "low"
                for lvl, lvl_thresh in sorted(severity_levels.items(), key=lambda x: x[1], reverse=True):
                    if peak >= lvl_thresh:
                        severity = lvl
                        break
                events.append(DegradationEvent(
                    start_index=start, end_index=i,
                    duration_samples=duration,
                    trigger_metric=metric,
                    trigger_value=round(peak, 3),
                    threshold=threshold,
                    severity=severity,
                ))

    return events


def analyze_telemetry_history(snapshots: list[dict]) -> TelemetryReport:
    if not snapshots:
        return TelemetryReport(
            sample_count=0, duration_seconds=0,
            stats={}, link_stability_score=1.0,
            degradation_events=[], vpn_flaps=0, bgp_flaps=0,
            throughput_efficiency_percent=100.0,
            summary="No telemetry data available",
        )

    # Extract time series
    latency   = [s.get("latency_ms", 0) for s in snapshots]
    loss      = [s.get("packet_loss_percent", 0) for s in snapshots]
    signal    = [s.get("signal_quality", 1) for s in snapshots]
    downlink  = [s.get("downlink_mbps", 0) for s in snapshots]
    uplink    = [s.get("uplink_mbps", 0) for s in snapshots]
    temp      = [s.get("modem_temperature_c", 40) for s in snapshots]

    # State transitions (flap detection)
    link_states  = [s.get("link_state", "up") for s in snapshots]
    vpn_states   = [s.get("vpn_state", "not_configured") for s in snapshots]
    bgp_states   = [s.get("bgp_state", "not_configured") for s in snapshots]

    vpn_flaps = sum(1 for i in range(1, len(vpn_states))
                   if vpn_states[i] != vpn_states[i-1]
                   and vpn_states[i] not in ("not_configured",))
    bgp_flaps = sum(1 for i in range(1, len(bgp_states))
                   if bgp_states[i] != bgp_states[i-1]
                   and bgp_states[i] not in ("not_configured",))

    # Duration
    n = len(snapshots)
    duration = n  # 1 sample/second

    # Link stability: fraction of time link_state == "up"
    up_count = sum(1 for s in link_states if s == "up")
    stability = round(up_count / max(n, 1), 4)

    # Throughput efficiency vs theoretical max
    max_dl = max(downlink) if downlink else 1
    avg_dl = statistics.mean(downlink) if downlink else 0
    throughput_eff = round((avg_dl / max(max_dl, 1)) * 100, 1)

    # Stats
    stats = {
        "latency_ms":          compute_stats(latency, "latency_ms"),
        "packet_loss_percent": compute_stats(loss, "packet_loss_percent"),
        "signal_quality":      compute_stats(signal, "signal_quality"),
        "downlink_mbps":       compute_stats(downlink, "downlink_mbps"),
        "uplink_mbps":         compute_stats(uplink, "uplink_mbps"),
        "modem_temperature_c": compute_stats(temp, "modem_temperature_c"),
    }

    # Degradation events
    degradation_events = []
    degradation_events += detect_degradation_events(
        latency, "latency_ms", threshold=100,
        severity_levels={"low": 100, "medium": 200, "high": 400, "critical": 600}
    )
    degradation_events += detect_degradation_events(
        loss, "packet_loss_percent", threshold=1.0,
        severity_levels={"low": 1.0, "medium": 5.0, "high": 10.0, "critical": 50.0}
    )
    degradation_events += detect_degradation_events(
        signal, "signal_quality", threshold=0.7,  # below threshold = degraded
        severity_levels={"low": 0.7, "medium": 0.5, "high": 0.3, "critical": 0.1}
    )

    # Alerts
    alerts: list[str] = []
    if stats["latency_ms"].p95 > 200:
        alerts.append(f"P95 latency {stats['latency_ms'].p95}ms exceeds 200ms — application timeouts likely")
    if stats["packet_loss_percent"].mean > 1.0:
        alerts.append(f"Mean loss {stats['packet_loss_percent'].mean:.2f}% — TCP throughput severely degraded")
    if vpn_flaps > 3:
        alerts.append(f"VPN state flapped {vpn_flaps} times — link instability causing tunnel resets")
    if bgp_flaps > 2:
        alerts.append(f"BGP flapped {bgp_flaps} times — route instability, possible traffic black hole")
    if stats["modem_temperature_c"].max_val > 75:
        alerts.append(f"Peak modem temperature {stats['modem_temperature_c'].max_val}C — thermal throttle possible")

    summary_parts = [
        f"{n} samples ({duration}s)",
        f"Avg latency {stats['latency_ms'].mean:.1f}ms",
        f"Avg loss {stats['packet_loss_percent'].mean:.2f}%",
        f"Stability {stability:.1%}",
        f"Throughput efficiency {throughput_eff}%",
    ]
    if alerts:
        summary_parts.append(f"{len(alerts)} alert(s)")

    return TelemetryReport(
        sample_count=n,
        duration_seconds=float(duration),
        stats=stats,
        link_stability_score=stability,
        degradation_events=degradation_events,
        vpn_flaps=vpn_flaps,
        bgp_flaps=bgp_flaps,
        throughput_efficiency_percent=throughput_eff,
        summary=" | ".join(summary_parts),
        alerts=alerts,
    )


def load_and_analyze(path: str | Path) -> TelemetryReport:
    with Path(path).open() as f:
        snapshots = json.load(f)
    if isinstance(snapshots, dict):
        snapshots = [snapshots]
    return analyze_telemetry_history(snapshots)
