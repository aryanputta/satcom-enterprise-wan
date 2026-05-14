#!/usr/bin/env python3
"""
SATCOM Enterprise WAN — Live Terminal Monitor

Real-time dashboard showing:
  - Starlink-style terminal telemetry (from API)
  - OSI layer health at a glance
  - Link impairment trend (last 60s rolling window)
  - Active experiment status
  - Root cause analyzer output (if diagnostics present)
  - Lab namespace status (if running on Linux)

Usage:
  python3 monitor.py                        # connects to localhost:8000
  python3 monitor.py --api http://host:8000 # remote API
  python3 monitor.py --profile rain_fade    # switch impairment profile
  python3 monitor.py --no-api               # show only local lab/diagnostics state
  python3 monitor.py --demo                 # auto-start API + cycle all failure scenarios
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import threading
import time
from collections import deque
from datetime import datetime, timezone
from pathlib import Path

try:
    import httpx
    HTTP_AVAILABLE = True
except ImportError:
    HTTP_AVAILABLE = False

from rich.console import Console
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.progress import BarColumn, Progress, TextColumn
from rich.table import Table
from rich.text import Text
from rich import box

# ── Constants ─────────────────────────────────────────────────────────────────
HISTORY_WINDOW = 60       # seconds of rolling history for sparkline
REFRESH_RATE   = 1.0      # seconds between screen updates
API_TIMEOUT    = 2.0      # seconds for API request timeout

console = Console()

# ── Helpers ───────────────────────────────────────────────────────────────────

def _run(cmd: list[str], timeout: int = 3) -> str:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout.strip()
    except Exception:
        return ""


def _ns_run(ns: str, cmd: str) -> str:
    return _run(["ip", "netns", "exec", ns] + cmd.split())


def _sparkline(values: list[float], width: int = 20, low: float = 0, high: float = 100) -> str:
    bars = " ▁▂▃▄▅▆▇█"
    if not values:
        return " " * width
    span = max(high - low, 1e-9)
    samples = values[-width:]
    result = ""
    for v in samples:
        idx = int(((v - low) / span) * (len(bars) - 1))
        idx = max(0, min(len(bars) - 1, idx))
        result += bars[idx]
    return result.ljust(width)


def _state_badge(state: str) -> Text:
    UP_STATES   = {"up", "established", "active", "connected"}
    DOWN_STATES = {"down", "idle", "connect", "handshaking"}
    if state in UP_STATES:
        return Text(f" {state.upper()} ", style="bold white on green")
    elif state in DOWN_STATES:
        return Text(f" {state.upper()} ", style="bold white on red")
    elif state == "degraded":
        return Text(f" {state.upper()} ", style="bold white on yellow")
    else:
        return Text(f" {state} ", style="dim")


def _threshold_color(value: float, warn: float, crit: float, invert: bool = False) -> str:
    """Return a Rich color string based on threshold levels."""
    if invert:
        if value < crit:   return "red"
        if value < warn:   return "yellow"
        return "green"
    else:
        if value >= crit:  return "red"
        if value >= warn:  return "yellow"
        return "green"


# ── API client ────────────────────────────────────────────────────────────────

class TelemetryClient:
    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip("/")
        self._client = None

    def _get_client(self):
        if not HTTP_AVAILABLE:
            return None
        if self._client is None:
            self._client = httpx.Client(timeout=API_TIMEOUT)
        return self._client

    def get_current(self) -> dict | None:
        c = self._get_client()
        if c is None:
            return None
        try:
            r = c.get(f"{self.base_url}/metrics/current")
            return r.json()
        except Exception:
            return None

    def get_history(self, n: int = 60) -> list[dict]:
        c = self._get_client()
        if c is None:
            return []
        try:
            r = c.get(f"{self.base_url}/metrics/history?n={n}")
            return r.json()
        except Exception:
            return []

    def switch_profile(self, profile: str, **kwargs) -> bool:
        c = self._get_client()
        if c is None:
            return False
        try:
            payload = {"profile": profile, **kwargs}
            r = c.post(f"{self.base_url}/simulate", json=payload)
            return r.status_code == 200
        except Exception:
            return False

    def is_reachable(self) -> bool:
        c = self._get_client()
        if c is None:
            return False
        try:
            r = c.get(f"{self.base_url}/health", timeout=1.0)
            return r.status_code == 200
        except Exception:
            return False


# ── Lab namespace status ───────────────────────────────────────────────────────

def get_lab_status() -> dict:
    """Get live namespace and interface status. Requires Linux root."""
    status = {}
    namespaces = ["ns-enterprise", "ns-ce", "ns-satcom", "ns-pop", "ns-cloud", "ns-app"]
    ns_list = _run(["ip", "netns", "list"])
    for ns in namespaces:
        if ns in ns_list:
            links = _ns_run(ns, "ip link show")
            routes = _ns_run(ns, "ip route show")
            status[ns] = {
                "exists": True,
                "interfaces": _parse_interfaces(links),
                "route_count": len([l for l in routes.splitlines() if l.strip()]),
            }
        else:
            status[ns] = {"exists": False}
    return status


def _parse_interfaces(ip_link_output: str) -> list[dict]:
    interfaces = []
    for line in ip_link_output.splitlines():
        m = __import__("re").search(
            r"^\d+: (\S+):.*<([^>]+)>.*state (\S+)", line
        )
        if m:
            name = m.group(1).rstrip("@")
            flags = m.group(2)
            state = m.group(3)
            interfaces.append({
                "name": name,
                "up": "UP" in flags and state in ("UP", "UNKNOWN"),
                "state": state,
            })
    return interfaces


# ── Diagnostics loader ────────────────────────────────────────────────────────

def get_latest_diagnostics() -> dict | None:
    exp_dir = Path("experiments")
    if not exp_dir.exists():
        return None
    candidates = sorted(exp_dir.glob("*/diagnostics.json"), key=lambda p: p.stat().st_mtime, reverse=True)
    if not candidates:
        return None
    try:
        with candidates[0].open() as f:
            return json.load(f)
    except Exception:
        return None


# ── RCA runner (cached) ───────────────────────────────────────────────────────

_rca_cache: dict = {}
_rca_last_path: str = ""

def get_rca_for(diag: dict | None) -> dict | None:
    global _rca_cache, _rca_last_path
    if diag is None:
        return None
    exp = diag.get("experiment", "")
    if exp == _rca_last_path and _rca_cache:
        return _rca_cache
    # Run analyzer in-process
    try:
        sys.path.insert(0, str(Path(__file__).parent / "analyzer"))
        from root_cause_analyzer import analyze_diagnostics, format_output
        findings = analyze_diagnostics(diag)
        result = format_output(diag, findings)
        _rca_cache = result
        _rca_last_path = exp
        return result
    except Exception as e:
        return {"error": str(e)}


# ── Renderers ─────────────────────────────────────────────────────────────────

def render_telemetry_panel(metrics: dict | None, history: list[dict]) -> Panel:
    if metrics is None:
        return Panel("[dim]Telemetry API not reachable — start with: make up[/dim]",
                     title="[bold]Terminal Telemetry[/bold]", border_style="dim")

    latency_hist  = [s.get("latency_ms", 0) for s in history]
    loss_hist     = [s.get("packet_loss_percent", 0) for s in history]
    dl_hist       = [s.get("downlink_mbps", 0) for s in history]

    lat = metrics.get("latency_ms", 0)
    loss = metrics.get("packet_loss_percent", 0)
    sig = metrics.get("signal_quality", 1.0)
    dl = metrics.get("downlink_mbps", 0)
    ul = metrics.get("uplink_mbps", 0)
    temp = metrics.get("modem_temperature_c", 0)
    obst = metrics.get("obstruction_percent", 0)
    snr = metrics.get("snr_db", 0)

    link_state = metrics.get("link_state", "unknown")
    vpn_state  = metrics.get("vpn_state", "unknown")
    bgp_state  = metrics.get("bgp_state", "unknown")

    lat_color  = _threshold_color(lat, 100, 250)
    loss_color = _threshold_color(loss, 1, 5)
    sig_color  = _threshold_color(sig, 0.8, 0.5, invert=True)
    temp_color = _threshold_color(temp, 65, 80)

    grid = Table.grid(padding=(0, 2))
    grid.add_column(min_width=28)
    grid.add_column(min_width=28)

    # Left column
    left = Table(show_header=False, box=None, padding=(0, 1))
    left.add_column(style="dim", width=22)
    left.add_column(min_width=20)
    left.add_row("Latency",       f"[{lat_color}]{lat:>7.1f} ms[/{lat_color}]  {_sparkline(latency_hist, 20, 0, 300)}")
    left.add_row("Packet Loss",   f"[{loss_color}]{loss:>7.2f}%[/{loss_color}]   {_sparkline(loss_hist, 20, 0, 10)}")
    left.add_row("Downlink",      f"[cyan]{dl:>7.1f} Mbps[/cyan]  {_sparkline(dl_hist, 20, 0, 200)}")
    left.add_row("Uplink",        f"[cyan]{ul:>7.1f} Mbps[/cyan]")
    left.add_row("Signal Quality",f"[{sig_color}]{sig:>7.3f}[/{sig_color}]")
    left.add_row("SNR",           f"[white]{snr:>7.1f} dB[/white]")

    # Right column
    right = Table(show_header=False, box=None, padding=(0, 1))
    right.add_column(style="dim", width=20)
    right.add_column()
    right.add_row("Link State",   _state_badge(link_state))
    right.add_row("VPN State",    _state_badge(vpn_state))
    right.add_row("BGP State",    _state_badge(bgp_state))
    right.add_row("Modem Temp",   f"[{temp_color}]{temp:.1f}°C[/{temp_color}]")
    right.add_row("Obstruction",  f"{obst:.1f}%")
    right.add_row("Routes",       str(metrics.get("route_count", "?")))
    right.add_row("NAT Entries",  str(metrics.get("nat_table_size", "?")))
    right.add_row("Satellite",    metrics.get("satellite_id", "?"))
    right.add_row("Beam",         metrics.get("beam_id", "?"))
    right.add_row("PoP",          metrics.get("pop_location", "?"))

    grid.add_row(left, right)

    ts = metrics.get("timestamp", "")
    return Panel(grid, title=f"[bold cyan]SATCOM Terminal Telemetry[/bold cyan]  [dim]{ts}[/dim]",
                 border_style="cyan")


def render_osi_health(metrics: dict | None, rca: dict | None) -> Panel:
    table = Table(show_header=True, header_style="bold", box=box.SIMPLE_HEAVY, padding=(0, 1))
    table.add_column("OSI Layer", width=14)
    table.add_column("Indicator", width=18)
    table.add_column("Value", width=16)
    table.add_column("Status", width=14)

    if metrics is None:
        table.add_row("N/A", "API offline", "", "[dim]unknown[/dim]")
    else:
        link_up = metrics.get("link_state") == "up"
        loss    = metrics.get("packet_loss_percent", 0)
        lat     = metrics.get("latency_ms", 0)
        sig     = metrics.get("signal_quality", 1)
        temp    = metrics.get("modem_temperature_c", 0)
        vpn     = metrics.get("vpn_state", "not_configured")
        bgp     = metrics.get("bgp_state", "not_configured")

        def status(ok: bool | None, na: bool = False) -> str:
            if na:          return "[dim]N/A[/dim]"
            if ok is None:  return "[dim]?[/dim]"
            return "[green]OK[/green]" if ok else "[red]FAULT[/red]"

        table.add_row("Layer 1", "Link state",     metrics.get("link_state", "?"),   status(link_up))
        table.add_row("",        "Packet loss",    f"{loss:.2f}%",                   status(loss < 1.0))
        table.add_row("",        "Signal quality", f"{sig:.3f}",                     status(sig > 0.7))
        table.add_row("",        "Modem temp",     f"{temp:.1f}°C",                  status(temp < 75))
        table.add_row("Layer 2", "Interface",      "veth pairs",                     status(link_up))
        table.add_row("Layer 3", "Latency",        f"{lat:.1f} ms",                  status(lat < 200))
        table.add_row("",        "BGP session",    bgp,                              status(bgp == "established", na=bgp == "not_configured"))
        table.add_row("",        "NAT table",      str(metrics.get("nat_table_size","?")), status(metrics.get("nat_table_size", 1) > 0))
        table.add_row("Layer 4", "VPN tunnel",     vpn,                              status(vpn == "up", na=vpn == "not_configured"))

    title = "[bold]OSI Health[/bold]"
    if rca and rca.get("confidence", 0) > 0:
        conf = rca["confidence"]
        col = "red" if conf > 0.8 else "yellow"
        title += f"  [{col}]RCA: {rca.get('probable_cause','?')} ({conf:.0%})[/{col}]"

    return Panel(table, title=title, border_style="blue")


def render_lab_status(lab: dict) -> Panel:
    table = Table(show_header=True, header_style="bold", box=box.SIMPLE, padding=(0, 1))
    table.add_column("Namespace", width=18)
    table.add_column("Status",    width=10)
    table.add_column("Interfaces", width=28)
    table.add_column("Routes", width=8)

    for ns, info in lab.items():
        if not info.get("exists"):
            table.add_row(ns, "[red]DOWN[/red]", "namespace missing", "—")
            continue

        ifaces = info.get("interfaces", [])
        iface_str = "  ".join(
            f"[green]{i['name']}[/green]" if i["up"] else f"[red]{i['name']}[/red]"
            for i in ifaces if i["name"] != "lo"
        )
        table.add_row(
            f"[bold]{ns}[/bold]",
            "[green]UP[/green]",
            iface_str or "[dim]no interfaces[/dim]",
            str(info.get("route_count", 0)),
        )

    all_up = all(v.get("exists", False) for v in lab.values())
    if not lab:
        return Panel("[dim]Lab not running. Run: sudo make lab-up[/dim]",
                     title="[bold]Network Namespace Lab[/bold]", border_style="dim")

    border = "green" if all_up else "yellow"
    return Panel(table, title="[bold]Network Namespace Lab[/bold]", border_style=border)


def render_rca_panel(rca: dict | None, diag: dict | None) -> Panel:
    if diag is None:
        return Panel("[dim]No diagnostics found. Run an experiment first.[/dim]",
                     title="[bold]Root Cause Analyzer[/bold]", border_style="dim")
    if rca is None:
        return Panel("[dim]RCA not available.[/dim]",
                     title="[bold]Root Cause Analyzer[/bold]", border_style="dim")

    if "error" in rca:
        return Panel(f"[red]RCA error: {rca['error']}[/red]",
                     title="[bold]Root Cause Analyzer[/bold]", border_style="red")

    conf = rca.get("confidence", 0)
    color = "green" if conf >= 0.85 else "yellow" if conf >= 0.6 else "red"
    cause = rca.get("probable_cause", "N/A")
    layer = rca.get("osi_layer", "N/A")
    exp   = rca.get("incident", "unknown")

    grid = Table.grid(padding=(0, 1))
    grid.add_column(min_width=18, style="dim")
    grid.add_column()

    grid.add_row("Experiment",   f"[bold]{exp}[/bold]")
    grid.add_row("Probable Cause", f"[bold {color}]{cause}[/bold {color}]")
    grid.add_row("OSI Layer",    f"[cyan]{layer}[/cyan]")
    grid.add_row("Confidence",   f"[{color}]{conf:.1%}[/{color}]")

    if rca.get("evidence"):
        ev_text = "\n".join(f"  • {e}" for e in rca["evidence"][:3])
        grid.add_row("Evidence",   ev_text)

    fix = rca.get("recommended_fix", "")
    if fix:
        first_fix = fix.strip().splitlines()[0]
        grid.add_row("Fix",        f"[dim]{first_fix}[/dim]")

    border = "green" if conf == 0 else color
    return Panel(grid, title=f"[bold]Root Cause Analyzer[/bold]  [dim]← {exp}[/dim]",
                 border_style=border)


def render_header(api_ok: bool, profile: str, uptime: int) -> Panel:
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    api_status = "[green]API LIVE[/green]" if api_ok else "[red]API OFFLINE[/red]"
    return Panel(
        f"[bold cyan]SATCOM Enterprise WAN[/bold cyan]  |  {api_status}  |  "
        f"Profile: [yellow]{profile}[/yellow]  |  Uptime: {uptime}s  |  {ts}",
        style="bold", padding=(0, 1), border_style="cyan"
    )


# ── Demo mode ─────────────────────────────────────────────────────────────────

DEMO_SCENARIOS: list[dict] = [
    {
        "profile": "baseline",
        "duration": 18,
        "title": "Healthy LEO link",
        "narration": (
            "SATCOM terminal locked to LEO constellation. "
            "Latency ~45ms (LEO), throughput 140/28 Mbps, loss 0.1%. "
            "BGP session established, NAT MASQUERADE active."
        ),
    },
    {
        "profile": "rain_fade",
        "duration": 20,
        "title": "Ka-band rain fade",
        "narration": (
            "Ka-band (26.5-40 GHz) is highly susceptible to rain attenuation. "
            "Signal quality dropping below 0.45, SNR falling. "
            "Adaptive coding shifts to QPSK 3/4 — throughput halved."
        ),
    },
    {
        "profile": "high_latency",
        "duration": 20,
        "title": "SATCOM congestion / BDP mismatch",
        "narration": (
            "Latency spike to 580ms. BDP = 150Mbps × 0.580s = 10.9 MB. "
            "Default 64KB TCP window is 170x too small — link is idle 94% of the time. "
            "BBR congestion control + tcp_rmem tuning required."
        ),
    },
    {
        "profile": "packet_loss",
        "duration": 20,
        "title": "RF interference — elevated packet loss",
        "narration": (
            "7% packet loss from adjacent-beam interference. "
            "TCP CUBIC interprets loss as congestion — halves cwnd on every drop. "
            "Effective throughput collapses to <5 Mbps despite healthy physical layer."
        ),
    },
    {
        "profile": "mtu_blackhole",
        "duration": 20,
        "title": "MTU black hole — PMTUD blocked",
        "narration": (
            "SATCOM WAN MTU set to 1400 (WireGuard overhead). "
            "Upstream CGNAT firewall drops ICMP type-3 code-4 (frag-needed). "
            "PMTUD fails silently — large packets dropped, TCP stalls. "
            "Fix: iptables mangle --clamp-mss-to-pmtu on CE."
        ),
    },
    {
        "profile": "link_down",
        "duration": 15,
        "title": "Complete link failure — beam handoff timeout",
        "narration": (
            "Beam handoff exceeded 30s hold timer. BGP session torn down. "
            "No default route at CE — enterprise LAN is fully isolated. "
            "BGP timers 10/30 (vs default 60/180) will limit blackout to 30s max."
        ),
    },
    {
        "profile": "baseline",
        "duration": 15,
        "title": "Link restored — BGP reconvergence",
        "narration": (
            "Physical link restored. BGP OPEN/KEEPALIVE exchanged. "
            "CE (AS65001) re-advertises 10.10.0.0/24, PoP reflects 192.168.100.0/24. "
            "Routing converged — enterprise traffic flowing again."
        ),
    },
]


def _start_api_server(api_url: str) -> subprocess.Popen | None:
    """Start uvicorn telemetry API as a subprocess. Returns Popen handle."""
    api_dir = Path(__file__).parent / "telemetry" / "api"
    if not (api_dir / "main.py").exists():
        return None
    try:
        proc = subprocess.Popen(
            [sys.executable, "-m", "uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"],
            cwd=api_dir,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        return proc
    except Exception:
        return None


def _wait_for_api(client: "TelemetryClient", timeout: float = 15.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if client.is_reachable():
            return True
        time.sleep(0.5)
    return False


def render_demo_banner(scenario: dict, elapsed: float, remaining: float) -> Panel:
    bar_width = 40
    filled = int((elapsed / (elapsed + remaining)) * bar_width)
    bar = "[cyan]" + "█" * filled + "[/cyan]" + "[dim]" + "░" * (bar_width - filled) + "[/dim]"
    countdown = f"{remaining:.0f}s"

    grid = Table.grid(padding=(0, 1))
    grid.add_column(style="dim", width=12)
    grid.add_column()
    grid.add_row("Scenario",   f"[bold yellow]{scenario['title']}[/bold yellow]")
    grid.add_row("Profile",    f"[cyan]{scenario['profile']}[/cyan]  →  next in {countdown}")
    grid.add_row("",           bar)
    grid.add_row("",           f"[dim]{scenario['narration']}[/dim]")

    return Panel(grid, title="[bold magenta]DEMO MODE[/bold magenta]  [dim]— auto-cycling failure scenarios[/dim]",
                 border_style="magenta")


# ── Main loop ─────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(description="SATCOM WAN Live Terminal Monitor")
    parser.add_argument("--api", default="http://localhost:8000", help="Telemetry API URL")
    parser.add_argument("--profile", help="Switch to this impairment profile on start")
    parser.add_argument("--no-api", action="store_true", help="Skip API, show only lab/diagnostics state")
    parser.add_argument("--refresh", type=float, default=REFRESH_RATE, help="Refresh interval seconds")
    parser.add_argument("--demo", action="store_true",
                        help="Demo mode: auto-start API and cycle through all failure scenarios")
    args = parser.parse_args()

    if not HTTP_AVAILABLE:
        console.print("[yellow]httpx not installed. Install with: pip install httpx[/yellow]")
        console.print("Continuing with API disabled...")
        args.no_api = True

    # ── Demo mode: start API server if not already up ─────────────────────────
    _api_proc: subprocess.Popen | None = None
    if args.demo and not args.no_api:
        client_probe = TelemetryClient(args.api)
        if not client_probe.is_reachable():
            console.print("[cyan]Demo mode: starting telemetry API...[/cyan]")
            _api_proc = _start_api_server(args.api)
            if _api_proc is None:
                console.print("[red]Could not start API. Check telemetry/api/main.py exists.[/red]")
                args.no_api = True
            else:
                if not _wait_for_api(client_probe, timeout=15.0):
                    console.print("[yellow]API did not start in time — continuing without it.[/yellow]")
                    _api_proc.terminate()
                    _api_proc = None
                    args.no_api = True
                else:
                    console.print("[green]API ready.[/green]")

    client = TelemetryClient(args.api) if not args.no_api else None

    if client and args.profile and not args.demo:
        if client.switch_profile(args.profile):
            console.print(f"[green]Switched to profile: {args.profile}[/green]")
        else:
            console.print(f"[yellow]Could not switch profile (API offline?)[/yellow]")

    history: deque[dict] = deque(maxlen=HISTORY_WINDOW)
    active_profile = args.profile or "baseline"
    start_time = time.time()

    # ── Demo scenario state ────────────────────────────────────────────────────
    demo_scenario_idx = 0
    demo_scenario_start = time.time()
    demo_banner: Panel | None = None

    if args.demo and client:
        first = DEMO_SCENARIOS[0]
        client.switch_profile(first["profile"])
        active_profile = first["profile"]

    # ── Layout ─────────────────────────────────────────────────────────────────
    layout = Layout()
    if args.demo:
        layout.split_column(
            Layout(name="demo_banner", size=7),
            Layout(name="header", size=3),
            Layout(name="main"),
            Layout(name="bottom", size=20),
        )
    else:
        layout.split_column(
            Layout(name="header", size=3),
            Layout(name="main"),
            Layout(name="bottom", size=20),
        )

    layout["main"].split_row(
        Layout(name="telemetry"),
        Layout(name="osi", ratio=1),
    )
    layout["bottom"].split_row(
        Layout(name="lab"),
        Layout(name="rca"),
    )

    try:
        with Live(layout, refresh_per_second=int(1 / args.refresh), screen=True):
            while True:
                now = time.time()
                uptime = int(now - start_time)
                api_ok = False
                metrics = None

                if client:
                    api_ok = client.is_reachable()
                    if api_ok:
                        metrics = client.get_current()
                        new_history = client.get_history(HISTORY_WINDOW)
                        if new_history:
                            history.clear()
                            history.extend(new_history)
                        if metrics:
                            active_profile = metrics.get("link_state", active_profile)

                # ── Demo: advance scenario when timer expires ──────────────────
                if args.demo and client and api_ok:
                    scenario = DEMO_SCENARIOS[demo_scenario_idx]
                    elapsed_in_scenario = now - demo_scenario_start
                    remaining = scenario["duration"] - elapsed_in_scenario

                    if remaining <= 0:
                        demo_scenario_idx = (demo_scenario_idx + 1) % len(DEMO_SCENARIOS)
                        scenario = DEMO_SCENARIOS[demo_scenario_idx]
                        client.switch_profile(scenario["profile"])
                        active_profile = scenario["profile"]
                        demo_scenario_start = now
                        elapsed_in_scenario = 0.0
                        remaining = float(scenario["duration"])

                    demo_banner = render_demo_banner(scenario, elapsed_in_scenario, remaining)
                elif args.demo:
                    scenario = DEMO_SCENARIOS[demo_scenario_idx]
                    demo_banner = render_demo_banner(scenario, 0, float(scenario["duration"]))

                lab_status = get_lab_status()
                diag = get_latest_diagnostics()
                rca  = get_rca_for(diag)

                if args.demo and demo_banner is not None:
                    layout["demo_banner"].update(demo_banner)

                layout["header"].update(render_header(api_ok, active_profile, uptime))
                layout["telemetry"].update(render_telemetry_panel(metrics, list(history)))
                layout["osi"].update(render_osi_health(metrics, rca))
                layout["lab"].update(render_lab_status(lab_status))
                layout["rca"].update(render_rca_panel(rca, diag))

                time.sleep(args.refresh)
    finally:
        if _api_proc is not None:
            _api_proc.terminate()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[dim]Monitor stopped.[/dim]")
