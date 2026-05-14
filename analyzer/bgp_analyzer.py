"""
BGP State Analyzer.

Parses FRRouting vtysh output ('show bgp summary', 'show ip route bgp')
and produces structured session state with diagnosis.

Can be run standalone or imported by root_cause_analyzer.py.
"""

from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal


BGP_STATE_T = Literal["Established", "Active", "Idle", "Connect", "OpenConfirm",
                       "OpenSent", "Unknown"]


@dataclass
class BGPPeerState:
    peer_ip: str
    remote_as: int
    state: BGP_STATE_T
    uptime: str
    prefixes_received: int
    prefixes_sent: int
    msg_rcvd: int
    msg_sent: int
    hold_time: int = 90
    issues: list[str] = field(default_factory=list)


@dataclass
class BGPAnalysis:
    router_id: str
    local_as: int
    peers: list[BGPPeerState]
    advertised_prefixes: list[str]
    received_prefixes: list[str]
    issues: list[str] = field(default_factory=list)
    healthy: bool = True


def parse_bgp_summary(vtysh_output: str) -> BGPAnalysis:
    """Parse output of: vtysh -c 'show bgp summary'"""
    analysis = BGPAnalysis(
        router_id="unknown",
        local_as=0,
        peers=[],
        advertised_prefixes=[],
        received_prefixes=[],
    )

    # Extract router-id and local AS
    rid_match = re.search(r"BGP router identifier (\S+), local AS number (\d+)", vtysh_output)
    if rid_match:
        analysis.router_id = rid_match.group(1)
        analysis.local_as = int(rid_match.group(2))

    # Parse peer table
    # Format: Neighbor V AS MsgRcvd MsgSent TblVer InQ OutQ Up/Down State/PfxRcd
    peer_pattern = re.compile(
        r"(\d+\.\d+\.\d+\.\d+)\s+4\s+(\d+)\s+(\d+)\s+(\d+)\s+\S+\s+\d+\s+\d+\s+(\S+)\s+(\S+)"
    )
    for m in peer_pattern.finditer(vtysh_output):
        peer_ip = m.group(1)
        remote_as = int(m.group(2))
        msg_rcvd = int(m.group(3))
        msg_sent = int(m.group(4))
        uptime = m.group(5)
        state_or_pfx = m.group(6)

        # State/PfxRcd: if numeric = Established (it's the prefix count)
        # If string (Active/Idle/Connect etc) = not established
        if state_or_pfx.isdigit():
            state: BGP_STATE_T = "Established"
            prefixes_rcvd = int(state_or_pfx)
        else:
            state = state_or_pfx  # type: ignore
            prefixes_rcvd = 0

        issues: list[str] = []
        if state != "Established":
            if msg_rcvd == 0 and msg_sent == 0:
                issues.append(f"No BGP messages exchanged with {peer_ip} — TCP to port 179 may be blocked")
            elif state == "Active":
                issues.append(f"Peer {peer_ip} stuck in Active — CE is sending OPEN but not receiving response")
                issues.append("Check remote-as configuration — ASN mismatch causes immediate NOTIFICATION and reset to Active")
            elif state == "Idle":
                issues.append(f"Peer {peer_ip} in Idle — BGP not attempting connection. Check timers or admindown.")

        peer = BGPPeerState(
            peer_ip=peer_ip,
            remote_as=remote_as,
            state=state,
            uptime=uptime,
            prefixes_received=prefixes_rcvd,
            prefixes_sent=0,
            msg_rcvd=msg_rcvd,
            msg_sent=msg_sent,
            issues=issues,
        )
        analysis.peers.append(peer)
        if issues:
            analysis.issues.extend(issues)
            analysis.healthy = False

    if not analysis.peers:
        analysis.issues.append("No BGP peers found in output — BGP may not be configured")
        analysis.healthy = False

    return analysis


def run_bgp_diagnostics_in_ns(namespace: str) -> dict:
    """Run vtysh BGP commands inside a namespace (requires FRR running in ns)."""
    results = {}
    commands = {
        "bgp_summary": "show bgp summary",
        "bgp_routes": "show ip route bgp",
        "bgp_neighbors": "show bgp neighbors",
        "route_table": "show ip route",
    }
    for key, cmd in commands.items():
        try:
            r = subprocess.run(
                ["ip", "netns", "exec", namespace, "vtysh", "-c", cmd],
                capture_output=True, text=True, timeout=5
            )
            results[key] = r.stdout if r.returncode == 0 else f"ERROR: {r.stderr.strip()}"
        except FileNotFoundError:
            results[key] = "vtysh not found — FRRouting not installed in this environment"
        except subprocess.TimeoutExpired:
            results[key] = "TIMEOUT"
        except Exception as e:
            results[key] = f"ERROR: {e}"
    return results


def check_bgp_port_reachability(peer_ip: str, namespace: str | None = None) -> dict:
    """Test TCP port 179 reachability to BGP peer."""
    cmd = ["nc", "-zv", "-w", "3", peer_ip, "179"]
    if namespace:
        cmd = ["ip", "netns", "exec", namespace] + cmd
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        reachable = r.returncode == 0
        return {"reachable": reachable, "output": (r.stdout + r.stderr).strip()}
    except Exception as e:
        return {"reachable": False, "output": str(e)}
