"""Tests for vpn_analyzer.py"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "analyzer"))

from vpn_analyzer import parse_wg_show, analyze_vpn_status, WireGuardInterface


# Sample wg show outputs
WG_HEALTHY = """
interface: wg0
  public key: abc123pubkey==
  private key: (hidden)
  listening port: 51820

peer: xyz789peerkey==
  endpoint: 100.65.0.2:51820
  allowed ips: 192.168.100.0/24, 10.200.0.2/32
  latest handshake: 30 seconds ago
  transfer: 1024 B received, 2048 B sent
  persistent keepalive: every 25 seconds
"""

WG_NEVER_HANDSHAKE = """
interface: wg0
  public key: abc123pubkey==
  listening port: 51820

peer: xyz789peerkey==
  endpoint: 100.65.0.2:51820
  allowed ips: 192.168.100.0/24
  latest handshake: never
  transfer: 0 B received, 256 B sent
"""

WG_STALE = """
interface: wg0
  public key: abc123pubkey==
  listening port: 51820

peer: xyz789peerkey==
  endpoint: 100.65.0.2:51820
  allowed ips: 192.168.100.0/24
  latest handshake: 5 minutes, 30 seconds ago
  transfer: 1024 B received, 1024 B sent
  persistent keepalive: every 25 seconds
"""

WG_NO_KEEPALIVE = """
interface: wg0
  public key: abc123pubkey==
  listening port: 51820

peer: xyz789peerkey==
  endpoint: 100.65.0.2:51820
  allowed ips: 192.168.100.0/24
  latest handshake: 10 seconds ago
  transfer: 1024 B received, 512 B sent
"""


class TestParseWgShow:
    def test_healthy_tunnel_parsed(self):
        iface = parse_wg_show(WG_HEALTHY)
        assert iface is not None
        assert iface.interface == "wg0"
        assert iface.listen_port == 51820
        assert len(iface.peers) == 1

    def test_healthy_tunnel_no_issues(self):
        iface = parse_wg_show(WG_HEALTHY)
        assert iface.healthy
        assert len(iface.issues) == 0

    def test_handshake_parsed_correctly(self):
        iface = parse_wg_show(WG_HEALTHY)
        assert iface.peers[0].latest_handshake_seconds_ago == 30

    def test_never_handshake_detected(self):
        iface = parse_wg_show(WG_NEVER_HANDSHAKE)
        assert iface is not None
        assert not iface.healthy
        assert iface.peers[0].latest_handshake_seconds_ago is None
        assert any("NEVER" in issue for issue in iface.issues)

    def test_stale_handshake_detected(self):
        iface = parse_wg_show(WG_STALE)
        assert not iface.healthy
        assert any("stale" in issue.lower() for issue in iface.issues)
        # 5 min 30 sec = 330 seconds
        assert iface.peers[0].latest_handshake_seconds_ago == 330

    def test_missing_keepalive_flagged(self):
        iface = parse_wg_show(WG_NO_KEEPALIVE)
        # No keepalive = issue
        assert any("PersistentKeepalive" in issue for issue in iface.issues)

    def test_empty_output(self):
        result = parse_wg_show("")
        assert result is None

    def test_not_found_output(self):
        result = parse_wg_show("wg: not found\nwireguard module not loaded")
        assert result is None

    def test_keepalive_interval_parsed(self):
        iface = parse_wg_show(WG_HEALTHY)
        assert iface.peers[0].keepalive_interval == 25


class TestAnalyzeVpnStatus:
    def test_not_configured(self):
        analysis = analyze_vpn_status({"wireguard": "not_configured"})
        assert analysis.tunnel_state == "not_configured"
        assert analysis.healthy  # not configured is not a fault

    def test_tunnel_up(self):
        analysis = analyze_vpn_status({"wireguard": "up"}, wg_show_output=WG_HEALTHY)
        assert analysis.tunnel_state == "up"
        assert analysis.healthy

    def test_tunnel_down_flagged(self):
        analysis = analyze_vpn_status({"wireguard": "down"})
        assert not analysis.healthy
        assert analysis.tunnel_state == "down"
        assert len(analysis.issues) > 0

    def test_handshaking_flagged(self):
        analysis = analyze_vpn_status({"wireguard": "handshaking"})
        assert not analysis.healthy
        assert any("handshake" in i.lower() for i in analysis.issues)

    def test_wg_show_stale_propagates_to_analysis(self):
        analysis = analyze_vpn_status({"wireguard": "up"}, wg_show_output=WG_STALE)
        assert not analysis.healthy
        assert len(analysis.issues) > 0
