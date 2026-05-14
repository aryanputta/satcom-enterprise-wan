"""
Integration tests — full pipeline without root/Linux.

These tests build realistic diagnostics.json fixtures and run the complete
pipeline: diagnostics -> pcap analysis -> BGP analysis -> VPN analysis -> RCA.

No root access, no network namespaces, no real packet captures needed.
"""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "analyzer"))
sys.path.insert(0, str(Path(__file__).parent.parent / "telemetry/api"))

from root_cause_analyzer import analyze_diagnostics, format_output
from route_analyzer import parse_route_table, check_end_to_end_path
from bgp_analyzer import parse_bgp_summary
from vpn_analyzer import analyze_vpn_status
from telemetry_analyzer import analyze_telemetry_history
from telemetry_generator import generate


# ── Fixture factory ────────────────────────────────────────────────────────────

def build_diagnostics(
    experiment: str,
    failure_mode: str = "none",
    link_state: str = "up",
    vpn_state: str = "not_configured",
    bgp_state: str = "not_configured",
    packet_loss: float = 0.1,
    latency: float = 45.0,
    nat_table_has_masquerade: bool = True,
    route_table_has_default: bool = True,
    nat_table_size: int = 120,
    signal_quality: float = 0.97,
    modem_temp: float = 44.0,
    pcap_keywords: str = "",
) -> dict:
    nat_table = (
        "Chain POSTROUTING (policy ACCEPT)\n"
        "target  prot opt source  destination\n"
        "MASQUERADE  all  --  10.10.0.0/24  0.0.0.0/0\n"
        if nat_table_has_masquerade else
        "Chain POSTROUTING (policy ACCEPT)\n"
        "target  prot opt source  destination\n"
    )

    ce_routes = (
        "default via 100.64.0.2 dev eth1 proto static\n"
        "10.10.0.0/24 dev eth0 proto kernel\n"
        "192.168.100.0/24 via 100.65.0.2 dev eth1 proto bgp metric 20\n"
        if route_table_has_default else
        "10.10.0.0/24 dev eth0 proto kernel\n"
    )

    return {
        "experiment": experiment,
        "timestamp": "2026-05-14T12:00:00",
        "failure_mode": failure_mode,
        "telemetry": {
            "latency_ms": latency,
            "jitter_ms": 3.0,
            "packet_loss_percent": packet_loss,
            "signal_quality": signal_quality,
            "downlink_mbps": 0.0 if link_state == "down" else 140.0,
            "uplink_mbps": 0.0 if link_state == "down" else 28.0,
            "modem_temperature_c": modem_temp,
            "link_state": link_state,
            "vpn_state": vpn_state,
            "bgp_state": bgp_state,
            "route_count": 3 if route_table_has_default else 1,
            "nat_table_size": nat_table_size,
        },
        "routes": {
            "ns-enterprise": "default via 10.10.0.1 dev eth0 proto static",
            "ns-ce": ce_routes,
            "ns-satcom": "default via 100.64.0.1 dev eth0 proto static",
            "ns-pop": "default via 100.65.0.1 dev eth0 proto static",
            "ns-cloud": "default via 172.16.0.1 dev eth0 proto static",
            "ns-app": "default via 192.168.100.1 dev eth0 proto static",
        },
        "interface_status": {
            "ns-ce": "1: lo: <LOOPBACK,UP> mtu 65536 state UNKNOWN\n"
                     "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 state UP\n"
                     "3: eth1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 state UP\n",
        },
        "nat_table": nat_table,
        "vpn_status": {"wireguard": vpn_state, "ipsec": "not_configured"},
        "bgp_status": {"ce_to_pop": bgp_state},
        "pcap_summary": {"issues": pcap_keywords, "keywords": pcap_keywords},
        "failure_mode": failure_mode,
    }


# ── Scenario-level integration tests ─────────────────────────────────────────

class TestScenario1_Baseline:
    def test_healthy_system_no_faults(self):
        diag = build_diagnostics("baseline")
        findings = analyze_diagnostics(diag)
        result = format_output(diag, findings)
        assert result["confidence"] == 0.0
        assert "no anomalies" in result["probable_cause"].lower()

    def test_healthy_route_path(self):
        diag = build_diagnostics("baseline")
        tables = {
            ns: parse_route_table(routes, ns)
            for ns, routes in diag["routes"].items()
        }
        path = check_end_to_end_path(tables)
        assert path["complete"], f"Path broken: {path['issues']}"


class TestScenario2_NatFailure:
    def test_nat_missing_classified_as_l3(self):
        diag = build_diagnostics(
            "nat_failure", failure_mode="nat_failure",
            nat_table_has_masquerade=False, nat_table_size=0
        )
        findings = analyze_diagnostics(diag)
        result = format_output(diag, findings)
        assert result["confidence"] > 0
        assert "NAT" in result["probable_cause"] or "nat" in result["probable_cause"].lower()
        assert "Layer 3" in result["osi_layer"]

    def test_nat_evidence_present(self):
        diag = build_diagnostics("nat_failure", nat_table_has_masquerade=False)
        findings = analyze_diagnostics(diag)
        nat_findings = [f for f in findings if f.rule_id == "L3_NAT_BROKEN"]
        assert nat_findings, "L3_NAT_BROKEN rule should fire"
        assert len(nat_findings[0].evidence) > 0


class TestScenario3_VpnFailure:
    def test_vpn_down_classified_l4(self):
        diag = build_diagnostics(
            "vpn_failure", failure_mode="vpn_failure",
            vpn_state="down",
            pcap_keywords="UDP 51820 blocked DROP"
        )
        findings = analyze_diagnostics(diag)
        result = format_output(diag, findings)
        assert result["confidence"] > 0
        # VPN blocked rule should be in findings even if not top (DNS keywords absent here)
        vpn_findings = [f for f in findings if f.rule_id == "L4_VPN_BLOCKED"]
        assert vpn_findings, f"L4_VPN_BLOCKED not in findings: {[f.rule_id for f in findings]}"

    def test_vpn_analysis_standalone(self):
        analysis = analyze_vpn_status({"wireguard": "down"})
        assert not analysis.healthy
        assert any("51820" in i or "firewall" in i.lower() for i in analysis.issues)


class TestScenario4_BgpFailure:
    def test_bgp_active_classified_l3(self):
        diag = build_diagnostics(
            "bgp_failure", failure_mode="bgp_failure",
            bgp_state="active"
        )
        findings = analyze_diagnostics(diag)
        result = format_output(diag, findings)
        assert result["confidence"] > 0
        assert "BGP" in result["probable_cause"]
        assert "Layer 3" in result["osi_layer"]

    def test_bgp_parse_active_state(self):
        bgp_output = """
BGP router identifier 100.64.0.1, local AS number 65001

Neighbor        V         AS MsgRcvd MsgSent   TblVer  InQ OutQ Up/Down  State/PfxRcd
100.65.0.2      4      65999       3       3        0    0    0 00:00:05  Active
"""
        analysis = parse_bgp_summary(bgp_output)
        assert not analysis.healthy
        assert any("Active" in i or "ASN" in i for i in analysis.issues)

    def test_bgp_missing_routes_when_down(self):
        # When BGP is down, route to 192.168.100.0/24 disappears
        diag = build_diagnostics(
            "bgp_failure",
            bgp_state="idle",
            route_table_has_default=False
        )
        tables = {ns: parse_route_table(routes, ns) for ns, routes in diag["routes"].items()}
        ce_analysis = tables.get("ns-ce")
        assert ce_analysis is not None
        assert not ce_analysis.has_default_route


class TestScenario5_MtuBlackhole:
    def test_mtu_blackhole_classified(self):
        diag = build_diagnostics(
            "mtu_blackhole", failure_mode="mtu_blackhole",
            vpn_state="up",
            pcap_keywords="TCP Retransmission no ICMP frag-needed silent drop"
        )
        findings = analyze_diagnostics(diag)
        result = format_output(diag, findings)
        assert result["confidence"] > 0

    def test_high_retransmissions_with_no_frag_needed(self):
        # Packet loss >= 1% needed to trigger L4_HIGH_RETRANSMISSIONS rule
        diag = build_diagnostics(
            "mtu_blackhole",
            vpn_state="up",
            packet_loss=3.0,
            pcap_keywords="TCP Retransmission large packets Dup ACK"
        )
        findings = analyze_diagnostics(diag)
        l4_findings = [f for f in findings if "RETRANSMISSION" in f.rule_id]
        assert l4_findings, f"L4_HIGH_RETRANSMISSIONS not fired. Rules triggered: {[f.rule_id for f in findings]}"


class TestScenario6_PacketLoss:
    def test_5pct_loss_classified_l1(self):
        diag = build_diagnostics(
            "packet_loss", failure_mode="packet_loss",
            link_state="degraded",
            packet_loss=5.0
        )
        findings = analyze_diagnostics(diag)
        result = format_output(diag, findings)
        assert result["confidence"] > 0
        assert "Layer 1" in result["osi_layer"]

    def test_telemetry_history_under_loss(self):
        snapshots = [generate("packet_loss", i).model_dump(mode="json") for i in range(60)]
        report = analyze_telemetry_history(snapshots)
        assert report.stats["packet_loss_percent"].mean > 3.0
        assert len(report.alerts) >= 1


class TestScenario7_DnsFailure:
    def test_dns_failure_classified_l7(self):
        diag = build_diagnostics(
            "dns_failure", failure_mode="dns_failure",
            pcap_keywords="DNS No response query unanswered NXDOMAIN"
        )
        findings = analyze_diagnostics(diag)
        result = format_output(diag, findings)
        assert result["confidence"] > 0
        assert "DNS" in result["probable_cause"]
        assert "Layer 7" in result["osi_layer"]


class TestScenario8_LinkDown:
    def test_full_outage_classified_l1_highest_confidence(self):
        diag = build_diagnostics(
            "failover", failure_mode="failover",
            link_state="down",
            packet_loss=100.0,
            signal_quality=0.0
        )
        findings = analyze_diagnostics(diag)
        result = format_output(diag, findings)
        assert result["confidence"] > 0.9
        assert "Layer 1" in result["osi_layer"]
        # Link down should beat all other rules in confidence
        if len(result["all_findings"]) > 0:
            assert result["all_findings"][0]["confidence"] >= 0.95


class TestMultiLayerFaults:
    def test_multiple_failures_all_detected(self):
        """Simultaneous BGP down + high loss should produce multiple findings."""
        diag = build_diagnostics(
            "multi_fault",
            link_state="degraded",
            packet_loss=5.0,
            bgp_state="active",
            nat_table_has_masquerade=False,
        )
        findings = analyze_diagnostics(diag)
        assert len(findings) >= 3, f"Expected 3+ findings, got {len(findings)}: {[f.rule_id for f in findings]}"

    def test_findings_sorted_by_confidence_descending(self):
        diag = build_diagnostics(
            "multi_fault",
            link_state="down",
            packet_loss=99.0,
            bgp_state="idle",
        )
        findings = analyze_diagnostics(diag)
        for i in range(len(findings) - 1):
            assert findings[i].confidence >= findings[i + 1].confidence

    def test_output_json_is_serializable(self):
        diag = build_diagnostics("baseline")
        findings = analyze_diagnostics(diag)
        result = format_output(diag, findings)
        # Should serialize to JSON without errors
        serialized = json.dumps(result)
        assert isinstance(serialized, str)
        deserialized = json.loads(serialized)
        assert "probable_cause" in deserialized
        assert "confidence" in deserialized
