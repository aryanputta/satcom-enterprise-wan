"""
SATCOM Enterprise WAN - Telemetry API

FastAPI service exposing:
  GET /metrics/current    - live terminal metrics JSON
  GET /metrics/stream     - SSE stream (1s interval)
  GET /metrics/history    - last N snapshots
  POST /simulate          - change impairment profile
  GET /health             - service health
  GET /metrics            - Prometheus scrape endpoint
"""

import asyncio
import json
import time
from collections import deque
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Literal

from fastapi import FastAPI, Response
from fastapi.responses import StreamingResponse
from prometheus_client import (
    Counter, Gauge, Histogram, generate_latest, CONTENT_TYPE_LATEST
)
from pydantic import BaseModel

from telemetry_generator import generate, IMPAIRMENT_PROFILES
from models import SatcomTerminalMetrics

# ── Prometheus metrics ────────────────────────────────────────────────────────
SATCOM_LATENCY       = Gauge("satcom_latency_ms",           "One-way latency ms")
SATCOM_JITTER        = Gauge("satcom_jitter_ms",            "Latency jitter ms")
SATCOM_LOSS          = Gauge("satcom_packet_loss_percent",  "Packet loss %")
SATCOM_OBSTRUCTION   = Gauge("satcom_obstruction_percent",  "Sky obstruction %")
SATCOM_SIGNAL        = Gauge("satcom_signal_quality",       "Signal quality 0..1")
SATCOM_SNR           = Gauge("satcom_snr_db",               "Signal-to-noise ratio dB")
SATCOM_DOWNLINK      = Gauge("satcom_downlink_mbps",        "Downlink throughput Mbps")
SATCOM_UPLINK        = Gauge("satcom_uplink_mbps",          "Uplink throughput Mbps")
SATCOM_TEMP          = Gauge("satcom_modem_temperature_c",  "Modem temperature Celsius")
SATCOM_LINK_STATE    = Gauge("satcom_link_up",              "Link state (1=up)")
SATCOM_VPN_STATE     = Gauge("satcom_vpn_up",               "VPN state (1=up)")
SATCOM_BGP_STATE     = Gauge("satcom_bgp_established",      "BGP session (1=established)")
SATCOM_ROUTES        = Gauge("satcom_route_count",          "Active route count")
SATCOM_NAT_TABLE     = Gauge("satcom_nat_table_size",       "NAT table entry count")
SATCOM_SCRAPE_TOTAL  = Counter("satcom_telemetry_scrapes_total", "Total telemetry scrape count")

# ── In-memory state ───────────────────────────────────────────────────────────
_state = {
    "profile": "baseline",
    "vpn_state": "not_configured",
    "bgp_state": "not_configured",
    "route_count": 5,
    "nat_table_size": 120,
    "start_time": time.time(),
}
_history: deque[dict] = deque(maxlen=3600)  # 1 hour at 1s


def _update_prom(m: SatcomTerminalMetrics) -> None:
    SATCOM_LATENCY.set(m.latency_ms)
    SATCOM_JITTER.set(m.jitter_ms)
    SATCOM_LOSS.set(m.packet_loss_percent)
    SATCOM_OBSTRUCTION.set(m.obstruction_percent)
    SATCOM_SIGNAL.set(m.signal_quality)
    SATCOM_SNR.set(m.snr_db)
    SATCOM_DOWNLINK.set(m.downlink_mbps)
    SATCOM_UPLINK.set(m.uplink_mbps)
    SATCOM_TEMP.set(m.modem_temperature_c)
    SATCOM_LINK_STATE.set(1 if m.link_state == "up" else 0)
    SATCOM_VPN_STATE.set(1 if m.vpn_state == "up" else 0)
    SATCOM_BGP_STATE.set(1 if m.bgp_state == "established" else 0)
    SATCOM_ROUTES.set(m.route_count)
    SATCOM_NAT_TABLE.set(m.nat_table_size)
    SATCOM_SCRAPE_TOTAL.inc()


async def _background_generator() -> None:
    while True:
        uptime = int(time.time() - _state["start_time"])
        m = generate(
            profile_name=_state["profile"],
            uptime_seconds=uptime,
            vpn_state=_state["vpn_state"],
            bgp_state=_state["bgp_state"],
            route_count=_state["route_count"],
            nat_table_size=_state["nat_table_size"],
        )
        _update_prom(m)
        _history.append(m.model_dump(mode="json"))
        await asyncio.sleep(1)


@asynccontextmanager
async def lifespan(app: FastAPI):
    task = asyncio.create_task(_background_generator())
    yield
    task.cancel()


app = FastAPI(
    title="SATCOM WAN Telemetry API",
    description="Starlink-style enterprise terminal telemetry simulator",
    version="1.0.0",
    lifespan=lifespan,
)


# ── Request/response models ───────────────────────────────────────────────────
class SimulateRequest(BaseModel):
    profile: Literal["baseline", "rain_fade", "high_latency", "packet_loss",
                     "link_down", "mtu_blackhole"]
    vpn_state: Literal["up", "handshaking", "down", "not_configured"] = "not_configured"
    bgp_state: Literal["established", "active", "idle", "connect", "not_configured"] = "not_configured"
    route_count: int = 5
    nat_table_size: int = 120


# ── Routes ────────────────────────────────────────────────────────────────────
@app.get("/health")
def health():
    return {"status": "ok", "uptime_s": int(time.time() - _state["start_time"])}


@app.get("/metrics/current", response_model=SatcomTerminalMetrics)
def current_metrics():
    uptime = int(time.time() - _state["start_time"])
    return generate(
        profile_name=_state["profile"],
        uptime_seconds=uptime,
        vpn_state=_state["vpn_state"],
        bgp_state=_state["bgp_state"],
        route_count=_state["route_count"],
        nat_table_size=_state["nat_table_size"],
    )


@app.get("/metrics/history")
def history(n: int = 60):
    return list(_history)[-n:]


@app.get("/metrics/profiles")
def profiles():
    return {k: v.model_dump() for k, v in IMPAIRMENT_PROFILES.items()}


@app.post("/simulate")
def simulate(req: SimulateRequest):
    _state.update({
        "profile": req.profile,
        "vpn_state": req.vpn_state,
        "bgp_state": req.bgp_state,
        "route_count": req.route_count,
        "nat_table_size": req.nat_table_size,
    })
    return {"status": "ok", "active_profile": req.profile}


@app.get("/metrics/stream")
async def stream():
    """Server-Sent Events stream for real-time dashboard consumption."""
    async def event_generator():
        while True:
            if _history:
                data = json.dumps(_history[-1], default=str)
                yield f"data: {data}\n\n"
            await asyncio.sleep(1)

    return StreamingResponse(event_generator(), media_type="text/event-stream")


@app.get("/metrics", include_in_schema=False)
def prom_metrics():
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)
