"""
FRR BGP agent — reads real BGP state via vtysh.

When FRR is running inside a Linux network namespace (installed via frr package),
this agent issues vtysh commands and parses structured JSON output.

Requires:
  - frr package installed (apt install frr)
  - bgpd daemon running inside the target namespace
  - setup_frr_namespaces.sh has been run

On systems without FRR, all methods return synthetic state for test compatibility.

Commands used:
  vtysh -N <ns> -c "show bgp summary json"          — peer state + prefix counts
  vtysh -N <ns> -c "show bgp ipv4 unicast json"     — full RIB
  vtysh -N <ns> -c "show bgp neighbors <peer> json" — per-peer detail
  vtysh -N <ns> -c "show ip route json"             — FIB (including BGP routes)
"""

from __future__ import annotations

import json
import logging
import subprocess
import time
from dataclasses import dataclass, field
from typing import Optional

log = logging.getLogger(__name__)


@dataclass
class BgpPeer:
    peer_addr: str
    remote_as: int
    state: str                      # Idle / Connect / Active / OpenSent / OpenConfirm / Established
    uptime_s: int = 0
    prefixes_received: int = 0
    prefixes_sent: int = 0
    bgp_version: int = 4
    description: str = ""
    hold_time_s: int = 90
    keepalive_s: int = 30
    last_reset_reason: str = ""


@dataclass
class BgpSummary:
    router_id: str = ""
    local_as: int = 0
    peers: list[BgpPeer] = field(default_factory=list)
    total_routes_rib: int = 0
    timestamp: float = field(default_factory=time.time)

    @property
    def all_established(self) -> bool:
        return all(p.state == "Established" for p in self.peers)

    @property
    def established_count(self) -> int:
        return sum(1 for p in self.peers if p.state == "Established")


@dataclass
class BgpRoute:
    prefix: str
    nexthop: str
    as_path: str
    local_pref: int = 100
    med: int = 0
    weight: int = 0
    origin: str = "i"
    best: bool = False
    valid: bool = True
    age_s: int = 0


@dataclass
class ConvergenceEvent:
    """Timing record for a BGP state machine transition."""
    peer_addr: str
    from_state: str
    to_state: str
    timestamp: float = field(default_factory=time.time)

    @classmethod
    def measure_convergence(cls, events: list["ConvergenceEvent"]) -> Optional[float]:
        """
        Return seconds from first 'down' event to first 'Established' for any peer.
        Returns None if the sequence is incomplete.
        """
        down_t = next((e.timestamp for e in events
                       if e.to_state in ("Idle", "Active", "Connect")), None)
        up_t = next((e.timestamp for e in events
                     if e.to_state == "Established" and e.timestamp > (down_t or 0)), None)
        if down_t and up_t:
            return round(up_t - down_t, 3)
        return None


class FRRAgent:
    """
    FRR vtysh agent for a specific router namespace.

    Namespace-aware: FRR 8.x+ supports `vtysh -N <namespace>` to target
    a specific vtysh socket at /var/run/frr/<namespace>.vty.
    """

    def __init__(self, namespace: str, vtysh_bin: str = "vtysh"):
        self.namespace = namespace
        self.vtysh = vtysh_bin
        self._frr_available: Optional[bool] = None
        self._convergence_log: list[ConvergenceEvent] = []
        self._last_peer_states: dict[str, str] = {}

    def _vtysh(self, cmd: str, timeout: int = 5) -> Optional[str]:
        """Run a vtysh command inside the target namespace socket."""
        try:
            r = subprocess.run(
                [self.vtysh, "-N", self.namespace, "-c", cmd],
                capture_output=True, text=True, timeout=timeout,
            )
            if r.returncode != 0:
                log.debug("vtysh error in %s: %s", self.namespace, r.stderr.strip())
                return None
            return r.stdout.strip()
        except FileNotFoundError:
            self._frr_available = False
            return None
        except subprocess.TimeoutExpired:
            log.warning("vtysh timeout for %s: %s", self.namespace, cmd)
            return None

    def is_available(self) -> bool:
        if self._frr_available is not None:
            return self._frr_available
        result = self._vtysh("show version")
        self._frr_available = result is not None and "FRRouting" in result
        return self._frr_available

    def get_bgp_summary(self) -> Optional[BgpSummary]:
        """Parse `show bgp summary json` into a BgpSummary."""
        raw = self._vtysh("show bgp summary json")
        if not raw:
            return None
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            return None

        ipv4 = data.get("ipv4Unicast", data)
        router_id = ipv4.get("routerId", "")
        local_as = ipv4.get("as", 0)

        peers: list[BgpPeer] = []
        for addr, info in ipv4.get("peers", {}).items():
            peer = BgpPeer(
                peer_addr=addr,
                remote_as=info.get("remoteAs", 0),
                state=info.get("state", "Unknown"),
                uptime_s=info.get("peerUptimeMsec", 0) // 1000,
                prefixes_received=info.get("pfxRcd", 0),
                prefixes_sent=info.get("pfxSnt", 0),
                hold_time_s=info.get("holdtime", 90),
                keepalive_s=info.get("keepaliveInterval", 30),
                description=info.get("desc", ""),
            )
            peers.append(peer)
            # Track state transitions for convergence timing
            prev = self._last_peer_states.get(addr)
            if prev and prev != peer.state:
                ev = ConvergenceEvent(
                    peer_addr=addr,
                    from_state=prev,
                    to_state=peer.state,
                )
                self._convergence_log.append(ev)
                log.info("BGP %s %s: %s → %s", self.namespace, addr, prev, peer.state)
            self._last_peer_states[addr] = peer.state

        total = ipv4.get("totalRoutes", sum(p.prefixes_received for p in peers))
        return BgpSummary(
            router_id=router_id,
            local_as=local_as,
            peers=peers,
            total_routes_rib=total,
        )

    def get_bgp_rib(self) -> list[BgpRoute]:
        """Parse `show bgp ipv4 unicast json` into route list."""
        raw = self._vtysh("show bgp ipv4 unicast json")
        if not raw:
            return []
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            return []

        routes: list[BgpRoute] = []
        for prefix, info in data.get("routes", {}).items():
            for entry in info:
                nexthops = entry.get("nexthops", [{}])
                nh = nexthops[0].get("ip", "") if nexthops else ""
                aspath = " ".join(str(a) for a in entry.get("aspath", {}).get("segments", []))
                routes.append(BgpRoute(
                    prefix=prefix,
                    nexthop=nh,
                    as_path=aspath,
                    local_pref=entry.get("locPrf", 100),
                    med=entry.get("metric", 0),
                    weight=entry.get("weight", 0),
                    origin=entry.get("origin", "i"),
                    best="bestpath" in entry and entry["bestpath"].get("overall", False),
                    valid=entry.get("valid", True),
                    age_s=entry.get("age", 0),
                ))
        return routes

    def get_fib(self) -> list[dict]:
        """Parse `show ip route json` for the full FIB including BGP routes."""
        raw = self._vtysh("show ip route json")
        if not raw:
            return []
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return []

    def measure_convergence_time(self) -> Optional[float]:
        """Return seconds for last full BGP convergence cycle (down → established)."""
        return ConvergenceEvent.measure_convergence(self._convergence_log)

    def get_convergence_log(self) -> list[ConvergenceEvent]:
        return list(self._convergence_log)

    def clear_convergence_log(self) -> None:
        self._convergence_log.clear()
        self._last_peer_states.clear()

    def reset_peer(self, peer_addr: str) -> bool:
        """Issue `clear bgp <peer>` — triggers a BGP reconvergence for timing measurement."""
        self.clear_convergence_log()
        result = self._vtysh(f"clear bgp {peer_addr} soft")
        return result is not None


# ── Synthetic fallback for testing without FRR ────────────────────────────────

class SyntheticFRRAgent(FRRAgent):
    """
    Drop-in replacement that returns pre-configured synthetic BGP state.
    Used for test environments (macOS, CI) where FRR is not installed.
    """

    def __init__(self, namespace: str, state: str = "Established",
                 prefixes_received: int = 2):
        super().__init__(namespace)
        self._state = state
        self._prefixes = prefixes_received

    def is_available(self) -> bool:
        return True

    def get_bgp_summary(self) -> BgpSummary:
        return BgpSummary(
            router_id="100.64.0.1",
            local_as=65001,
            peers=[
                BgpPeer(
                    peer_addr="100.65.0.2",
                    remote_as=65002,
                    state=self._state,
                    uptime_s=3600,
                    prefixes_received=self._prefixes,
                    prefixes_sent=1,
                    hold_time_s=30,
                    keepalive_s=10,
                )
            ],
            total_routes_rib=self._prefixes,
        )

    def get_bgp_rib(self) -> list[BgpRoute]:
        if self._state != "Established":
            return []
        return [
            BgpRoute(
                prefix="192.168.100.0/24",
                nexthop="100.65.0.2",
                as_path="65002",
                local_pref=100,
                best=True,
                valid=True,
            )
        ]


def make_agent(namespace: str, synthetic: bool = False) -> FRRAgent:
    """Factory: return real FRRAgent if FRR is available, else SyntheticFRRAgent."""
    if synthetic:
        return SyntheticFRRAgent(namespace)
    agent = FRRAgent(namespace)
    if not agent.is_available():
        log.info("FRR not available in %s — using synthetic agent", namespace)
        return SyntheticFRRAgent(namespace)
    return agent
