"""Tests for bgp_analyzer.py"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "analyzer"))

from bgp_analyzer import parse_bgp_summary


BGP_ESTABLISHED = """
BGP router identifier 100.64.0.1, local AS number 65001

Neighbor        V         AS MsgRcvd MsgSent   TblVer  InQ OutQ Up/Down  State/PfxRcd   PfxSnt
100.65.0.2      4      65002     120     115        1    0    0 00:08:22        1          1
"""

BGP_ACTIVE = """
BGP router identifier 100.64.0.1, local AS number 65001

Neighbor        V         AS MsgRcvd MsgSent   TblVer  InQ OutQ Up/Down  State/PfxRcd   PfxSnt
100.65.0.2      4      65999       3       3        0    0    0 00:00:05  Active
"""

BGP_IDLE_NO_MSGS = """
BGP router identifier 100.64.0.1, local AS number 65001

Neighbor        V         AS MsgRcvd MsgSent   TblVer  InQ OutQ Up/Down  State/PfxRcd   PfxSnt
100.65.0.2      4      65002       0       0        0    0    0 never     Idle
"""

BGP_EMPTY = "BGP router identifier 0.0.0.0, local AS number 0\n"


class TestParseBgpSummary:
    def test_established_session_is_healthy(self):
        analysis = parse_bgp_summary(BGP_ESTABLISHED)
        assert analysis.healthy
        assert len(analysis.issues) == 0
        assert analysis.local_as == 65001
        assert analysis.router_id == "100.64.0.1"

    def test_established_peer_state(self):
        analysis = parse_bgp_summary(BGP_ESTABLISHED)
        assert len(analysis.peers) == 1
        peer = analysis.peers[0]
        assert peer.state == "Established"
        assert peer.prefixes_received == 1

    def test_active_state_is_unhealthy(self):
        analysis = parse_bgp_summary(BGP_ACTIVE)
        assert not analysis.healthy
        assert len(analysis.issues) > 0

    def test_active_state_asn_mismatch_hint(self):
        analysis = parse_bgp_summary(BGP_ACTIVE)
        # Peer has wrong ASN (65999 vs expected 65002)
        # Issue should mention ASN or Open Message
        assert any("ASN" in i or "Active" in i or "OPEN" in i.upper() for i in analysis.issues)

    def test_idle_no_messages_blocked_hint(self):
        analysis = parse_bgp_summary(BGP_IDLE_NO_MSGS)
        assert not analysis.healthy
        # 0 messages means TCP 179 may be blocked
        assert any("179" in i or "blocked" in i.lower() or "TCP" in i for i in analysis.issues)

    def test_empty_output_no_peers(self):
        analysis = parse_bgp_summary(BGP_EMPTY)
        assert not analysis.healthy
        assert any("No BGP peers" in i for i in analysis.issues)

    def test_router_id_parsed(self):
        analysis = parse_bgp_summary(BGP_ESTABLISHED)
        assert analysis.router_id == "100.64.0.1"

    def test_local_as_parsed(self):
        analysis = parse_bgp_summary(BGP_ESTABLISHED)
        assert analysis.local_as == 65001
