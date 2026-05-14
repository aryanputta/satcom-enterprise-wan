"""
Generates synthetic Starlink-style SATCOM terminal telemetry.
Models realistic degradation curves for:
  - baseline (clear sky, geostationary-class latency for LEO simulation)
  - rain_fade (weather event)
  - high_latency (LEO congestion / handoff)
  - packet_loss (interference)
  - link_down (full outage)
  - vpn_degraded (VPN thrash under high loss)
  - bgp_instability (route flap under link instability)
"""

import math
import random
import time
from datetime import datetime, timezone
from typing import Literal

from models import SatcomTerminalMetrics, ImpairmentProfile

# Impairment presets matching tc netem configs in inject_failure.sh
IMPAIRMENT_PROFILES: dict[str, ImpairmentProfile] = {
    "baseline": ImpairmentProfile(
        name="baseline", description="Clear sky LEO SATCOM",
        latency_ms=45, jitter_ms=3, loss_percent=0.1, bandwidth_kbps=150_000
    ),
    "rain_fade": ImpairmentProfile(
        name="rain_fade", description="Rain fade / weather degradation",
        latency_ms=65, jitter_ms=12, loss_percent=2.5, bandwidth_kbps=40_000
    ),
    "high_latency": ImpairmentProfile(
        name="high_latency", description="Congestion / beam handoff",
        latency_ms=150, jitter_ms=20, loss_percent=0.5, bandwidth_kbps=80_000
    ),
    "packet_loss": ImpairmentProfile(
        name="packet_loss", description="Interference / obstruction",
        latency_ms=50, jitter_ms=5, loss_percent=5.0, bandwidth_kbps=100_000
    ),
    "link_down": ImpairmentProfile(
        name="link_down", description="Full satellite link outage",
        latency_ms=0, jitter_ms=0, loss_percent=100.0, bandwidth_kbps=0
    ),
    "mtu_blackhole": ImpairmentProfile(
        name="mtu_blackhole", description="MTU black hole — VPN fragmentation issue",
        latency_ms=45, jitter_ms=3, loss_percent=0.1, bandwidth_kbps=150_000
    ),
}


def _gaussian_noise(value: float, sigma: float) -> float:
    return max(0.0, value + random.gauss(0, sigma))


def generate(
    profile_name: str = "baseline",
    uptime_seconds: int | None = None,
    vpn_state: Literal["up", "handshaking", "down", "not_configured"] = "not_configured",
    bgp_state: Literal["established", "active", "idle", "connect", "not_configured"] = "not_configured",
    route_count: int = 5,
    nat_table_size: int = 120,
) -> SatcomTerminalMetrics:

    profile = IMPAIRMENT_PROFILES.get(profile_name, IMPAIRMENT_PROFILES["baseline"])
    t = uptime_seconds if uptime_seconds is not None else int(time.time()) % 86400

    # Derive link state from loss
    if profile.loss_percent >= 100:
        link_state = "down"
    elif profile.loss_percent >= 10 or profile.latency_ms >= 200:
        link_state = "degraded"
    else:
        link_state = "up"

    # Simulate thermal sag: temperature rises with throughput under load
    base_temp = 42.0
    load_temp = (profile.bandwidth_kbps or 0) / 150_000 * 18.0
    modem_temp = _gaussian_noise(base_temp + load_temp, 1.2)

    # Signal quality inversely proportional to loss + obstruction
    obstruction = _gaussian_noise(profile.loss_percent * 2.5, 1.5)
    obstruction = min(obstruction, 99.0)
    signal_quality = max(0.0, 1.0 - (profile.loss_percent / 100) - (obstruction / 200))

    # SNR: models Ka-band link budget roughly
    snr = _gaussian_noise(28.0 - profile.loss_percent * 2 - (profile.latency_ms - 45) * 0.05, 0.8)

    # Throughput: bandwidth * (1 - loss) * signal_quality with noise
    # Use 0 noise when bandwidth is 0 (link fully down) to avoid spurious non-zero values
    bw_mbps = (profile.bandwidth_kbps or 0) / 1000
    dl_mean = bw_mbps * (1 - profile.loss_percent / 100) * signal_quality
    dl = _gaussian_noise(dl_mean, 2.0) if dl_mean > 0 else 0.0
    ul = _gaussian_noise(dl * 0.22, 0.5) if dl > 0 else 0.0

    return SatcomTerminalMetrics(
        timestamp=datetime.now(timezone.utc),
        latency_ms=_gaussian_noise(profile.latency_ms, profile.jitter_ms * 0.3),
        jitter_ms=_gaussian_noise(profile.jitter_ms, 0.5),
        packet_loss_percent=min(100.0, _gaussian_noise(profile.loss_percent, 0.1)),
        obstruction_percent=round(obstruction, 2),
        signal_quality=round(min(1.0, signal_quality), 4),
        snr_db=round(snr, 2),
        downlink_mbps=round(max(0, dl), 2),
        uplink_mbps=round(max(0, ul), 2),
        modem_temperature_c=round(modem_temp, 1),
        uptime_seconds=t,
        link_state=link_state,
        vpn_state=vpn_state,
        bgp_state=bgp_state,
        route_count=route_count,
        nat_table_size=nat_table_size + random.randint(-10, 20),
        satellite_id=f"SAT-{(t // 300) % 12 + 1:03d}",
        beam_id=f"BEAM-US-E-{(t // 600) % 4 + 1}",
        pop_location="us-east-1-pop",
    )
