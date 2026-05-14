from pydantic import BaseModel, Field
from typing import Literal
from datetime import datetime


class SatcomTerminalMetrics(BaseModel):
    """Simulates Starlink-style terminal telemetry."""
    timestamp: datetime = Field(default_factory=datetime.utcnow)

    # Physical layer
    latency_ms: float = Field(ge=0, description="One-way latency in milliseconds")
    jitter_ms: float = Field(ge=0, description="Latency variance in milliseconds")
    packet_loss_percent: float = Field(ge=0, le=100)
    obstruction_percent: float = Field(ge=0, le=100, description="Sky obstruction from dishes perspective")
    signal_quality: float = Field(ge=0, le=1.0, description="Normalized signal quality 0..1")
    snr_db: float = Field(description="Signal-to-noise ratio in dB")

    # Throughput
    downlink_mbps: float = Field(ge=0)
    uplink_mbps: float = Field(ge=0)

    # Hardware
    modem_temperature_c: float = Field(description="Terminal board temperature in Celsius")
    uptime_seconds: int = Field(ge=0)

    # Link/session state
    link_state: Literal["up", "degraded", "down", "recovering"]
    vpn_state: Literal["up", "handshaking", "down", "not_configured"]
    bgp_state: Literal["established", "active", "idle", "connect", "not_configured"]

    # Routing
    route_count: int = Field(ge=0)
    nat_table_size: int = Field(ge=0)

    # Satellite-specific
    satellite_id: str
    beam_id: str
    pop_location: str


class ImpairmentProfile(BaseModel):
    """tc netem impairment parameters for SATCOM emulation."""
    name: str
    description: str
    latency_ms: int
    jitter_ms: int
    loss_percent: float
    bandwidth_kbps: int | None = None
    duplicate_percent: float = 0.0
    corrupt_percent: float = 0.0


class DiagnosticsSnapshot(BaseModel):
    experiment: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    telemetry: SatcomTerminalMetrics
    failure_mode: str = "none"
    notes: str = ""
