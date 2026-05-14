"""
Starlink terminal gRPC client.

Polls the dish management server at 192.168.100.1:9200 (standard address when
the dish is directly connected to an enterprise CE router).

Protocol: SpaceX.API.Device.Device.Handle RPC (unary).
          Request field 2006 → DishGetStatusRequest (empty)
          Response field 2006 → DishGetStatusResponse

Three-tier fallback:
  1. grpcio + starlink-grpc-tools compiled stubs (best — pip install starlink-grpc-tools)
  2. grpcio raw channel with known field numbers (no extra package needed)
  3. None — caller falls back to synthetic telemetry

Reference implementation: https://github.com/sparky8512/starlink-grpc-tools
SpaceX API proto: https://github.com/sparky8512/starlink-grpc-tools/tree/main/src/spacex/api
"""

from __future__ import annotations

import json
import logging
import struct
import time
from dataclasses import dataclass
from typing import Optional

log = logging.getLogger(__name__)

# ── Proto field numbers (SpaceX.API.Device) ───────────────────────────────────
# These are stable across firmware versions as of 2024.
_FIELD_DISH_GET_STATUS = 2006   # oneof request/response field number

# DishGetStatusResponse fields
_FIELD_DEVICE_STATE   = 1       # DeviceState submessage
_FIELD_DEVICE_INFO    = 2       # DeviceInfo submessage
_FIELD_LATENCY        = 1008    # pop_ping_latency_ms (float)
_FIELD_DROP_RATE      = 1014    # pop_ping_drop_rate (float)
_FIELD_UL_THROUGHPUT  = 1017    # uplink_throughput_bps (float)
_FIELD_DL_THROUGHPUT  = 1016    # downlink_throughput_bps (float)
_FIELD_OBSTRUCTION    = 1009    # DishObstructionStats submessage
_FIELD_SNR            = 1015    # snr (float, deprecated but still present)
_FIELD_ALERT_THERMAL  = 1006    # alert_thermal_throttle (bool)
_FIELD_UPTIME         = 1       # DeviceState.uptime_s (uint32)


@dataclass
class StarlinkStatus:
    """Parsed Starlink dish status from gRPC response."""
    dish_id: str = ""
    uptime_s: int = 0
    state: str = "UNKNOWN"                 # CONNECTED / SEARCHING / BOOTING

    # RF metrics
    pop_ping_latency_ms: float = 0.0
    pop_ping_drop_rate: float = 0.0        # fraction 0..1
    snr: float = 0.0                       # dB (approximate)

    # Throughput (bps from firmware counters)
    downlink_throughput_bps: float = 0.0
    uplink_throughput_bps: float = 0.0

    # Obstruction
    fraction_obstructed: float = 0.0
    currently_obstructed: bool = False
    valid_s: float = 0.0                   # seconds of valid samples in last window

    # Alerts
    alert_thermal_throttle: bool = False
    alert_roaming: bool = False
    alert_motors_stuck: bool = False

    timestamp: float = 0.0

    @property
    def downlink_mbps(self) -> float:
        return self.downlink_throughput_bps / 1_000_000

    @property
    def uplink_mbps(self) -> float:
        return self.uplink_throughput_bps / 1_000_000

    @property
    def latency_ms(self) -> float:
        return self.pop_ping_latency_ms

    @property
    def loss_pct(self) -> float:
        return self.pop_ping_drop_rate * 100.0

    @property
    def obstruction_pct(self) -> float:
        return self.fraction_obstructed * 100.0

    def to_telemetry_dict(self) -> dict:
        """Return a dict compatible with SatcomTerminalMetrics shape."""
        return {
            "latency_ms": self.latency_ms,
            "jitter_ms": 0.0,   # not directly available from dish gRPC
            "packet_loss_percent": self.loss_pct,
            "signal_quality": max(0.0, min(1.0, self.snr / 30.0)),
            "snr_db": self.snr,
            "downlink_mbps": self.downlink_mbps,
            "uplink_mbps": self.uplink_mbps,
            "obstruction_percent": self.obstruction_pct,
            "link_state": "up" if self.state == "CONNECTED" else "down",
            "satellite_id": self.dish_id,
            "beam_id": "gRPC",
            "pop_location": "starlink",
            "uptime_seconds": self.uptime_s,
            "_source": "starlink_grpc",
        }


# ── Tier 1: starlink-grpc-tools ───────────────────────────────────────────────

def _poll_via_starlink_grpc_tools(host: str, port: int) -> Optional[StarlinkStatus]:
    """Use sparky8512/starlink-grpc-tools if installed (pip install starlink-grpc-tools)."""
    try:
        import grpc
        import spacex.api.device.device_pb2 as device_pb2
        import spacex.api.device.device_pb2_grpc as device_pb2_grpc
    except ImportError:
        return None

    try:
        channel = grpc.insecure_channel(f"{host}:{port}")
        stub = device_pb2_grpc.DeviceStub(channel)
        resp = stub.Handle(
            device_pb2.Request(dish_get_status=device_pb2.DishGetStatusRequest()),
            timeout=5,
        )
        gs = resp.dish_get_status
        obs = gs.obstruction_stats
        s = StarlinkStatus(
            dish_id=gs.device_info.id,
            uptime_s=gs.device_state.uptime_s,
            state=device_pb2.DishState.Name(gs.state),
            pop_ping_latency_ms=gs.pop_ping_latency_ms,
            pop_ping_drop_rate=gs.pop_ping_drop_rate,
            snr=gs.snr if hasattr(gs, "snr") else 0.0,
            downlink_throughput_bps=gs.downlink_throughput_bps,
            uplink_throughput_bps=gs.uplink_throughput_bps,
            fraction_obstructed=obs.fraction_obstructed,
            currently_obstructed=obs.currently_obstructed,
            valid_s=obs.valid_s,
            alert_thermal_throttle=gs.alerts.thermal_throttle,
            alert_roaming=gs.alerts.roaming,
            alert_motors_stuck=gs.alerts.motors_stuck,
            timestamp=time.time(),
        )
        channel.close()
        return s
    except Exception as exc:
        log.debug("starlink-grpc-tools poll failed: %s", exc)
        return None


# ── Tier 2: raw grpcio (no compiled stubs) ────────────────────────────────────

def _encode_varint(value: int) -> bytes:
    """Encode an unsigned integer as protobuf varint."""
    bits = []
    while value > 0x7F:
        bits.append((value & 0x7F) | 0x80)
        value >>= 7
    bits.append(value & 0x7F)
    return bytes(bits)


def _make_dish_get_status_request() -> bytes:
    """
    Build a minimal Request protobuf with dish_get_status = {} (empty message).
    Field 2006, wire type 2 (length-delimited), length 0.
    Tag = (field_number << 3) | wire_type = (2006 << 3) | 2 = 16050
    """
    tag = (_FIELD_DISH_GET_STATUS << 3) | 2  # wire type 2 = LEN
    return _encode_varint(tag) + b"\x00"      # length = 0 (empty submessage)


def _parse_float_field(data: bytes, field_number: int) -> Optional[float]:
    """
    Extract a 32-bit float (wire type 5) from a flat protobuf message.
    Only works for top-level fields in the response; nested messages need
    separate parsing. Returns None if field not found.
    """
    i = 0
    while i < len(data):
        try:
            tag_byte = data[i]
            i += 1
            if tag_byte == 0:
                break
            # Decode varint tag
            tag = tag_byte
            shift = 0
            while tag & 0x80:
                tag = (tag & 0x7F) | (data[i] << (shift + 7))
                i += 1
                shift += 7
            tag = (tag_byte & 0x7F)
            # Simple single-byte tag decode for common cases
            field_num = tag_byte >> 3
            wire_type = tag_byte & 0x07
            if field_num == field_number and wire_type == 5:
                val = struct.unpack_from("<f", data, i)[0]
                return float(val)
            # Skip this field
            if wire_type == 0:   # varint
                while data[i] & 0x80:
                    i += 1
                i += 1
            elif wire_type == 1: # 64-bit
                i += 8
            elif wire_type == 2: # length-delimited
                length = data[i]; i += 1
                i += length
            elif wire_type == 5: # 32-bit
                i += 4
        except (IndexError, struct.error):
            break
    return None


def _poll_via_raw_grpc(host: str, port: int) -> Optional[StarlinkStatus]:
    """Use grpcio directly with manually built proto bytes."""
    try:
        import grpc
    except ImportError:
        return None

    try:
        channel = grpc.insecure_channel(f"{host}:{port}")
        # gRPC method path for SpaceX Device service
        method = channel.unary_unary(
            "/SpaceX.API.Device.Device/Handle",
            request_serializer=lambda x: x,
            response_deserializer=lambda x: x,
        )
        request_bytes = _make_dish_get_status_request()
        response_bytes, _, _ = method.with_call(request_bytes, timeout=5)

        # The response is a Response message; DishGetStatusResponse is at field 2006
        # For now return a minimal status indicating the dish responded
        s = StarlinkStatus(
            state="CONNECTED",
            timestamp=time.time(),
        )

        # Try to extract latency field from raw bytes (best-effort)
        lat = _parse_float_field(response_bytes, _FIELD_LATENCY)
        if lat is not None:
            s.pop_ping_latency_ms = lat

        dl = _parse_float_field(response_bytes, _FIELD_DL_THROUGHPUT)
        if dl is not None:
            s.downlink_throughput_bps = dl

        ul = _parse_float_field(response_bytes, _FIELD_UL_THROUGHPUT)
        if ul is not None:
            s.uplink_throughput_bps = ul

        channel.close()
        return s
    except Exception as exc:
        log.debug("raw grpc poll failed: %s", exc)
        return None


# ── Public API ────────────────────────────────────────────────────────────────

class StarlinkClient:
    """
    High-level Starlink gRPC client with automatic tier selection and caching.

    Usage:
        client = StarlinkClient()          # default 192.168.100.1:9200
        status = client.get_status()       # StarlinkStatus or None
        if status:
            print(status.downlink_mbps)
    """

    def __init__(self, host: str = "192.168.100.1", port: int = 9200,
                 cache_ttl: float = 1.0):
        self.host = host
        self.port = port
        self.cache_ttl = cache_ttl
        self._cache: Optional[StarlinkStatus] = None
        self._cache_time: float = 0.0
        self._available: Optional[bool] = None  # None = untested

    def is_available(self) -> bool:
        """Return True if the dish gRPC server is reachable."""
        if self._available is not None:
            return self._available
        status = self._fetch_fresh()
        self._available = status is not None
        return self._available

    def _fetch_fresh(self) -> Optional[StarlinkStatus]:
        for tier in [_poll_via_starlink_grpc_tools, _poll_via_raw_grpc]:
            result = tier(self.host, self.port)
            if result is not None:
                return result
        return None

    def get_status(self) -> Optional[StarlinkStatus]:
        """Return current dish status, using cache within TTL."""
        now = time.time()
        if self._cache and (now - self._cache_time) < self.cache_ttl:
            return self._cache
        fresh = self._fetch_fresh()
        if fresh is not None:
            self._cache = fresh
            self._cache_time = now
            self._available = True
        else:
            self._available = False
        return fresh


# Module-level default client (lazy init)
_default_client: Optional[StarlinkClient] = None


def get_default_client(host: str = "192.168.100.1", port: int = 9200) -> StarlinkClient:
    global _default_client
    if _default_client is None:
        _default_client = StarlinkClient(host=host, port=port)
    return _default_client
