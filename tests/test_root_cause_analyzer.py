"""Tests for root_cause_analyzer.py"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "analyzer"))

from root_cause_analyzer import analyze_diagnostics, format_output


def _make_diag(overrides: dict) -> dict:
    base = {
        "experiment": "test",
        "timestamp": "2026-01-01T00:00:00",
        "telemetry": {
            "latency_ms": 45.0,
            "jitter_ms": 3.0,
            "packet_loss_percent": 0.1,
            "signal_quality": 0.95,
            "downlink_mbps": 140.0,
            "uplink_mbps": 28.0,
            "modem_temperature_c": 44.0,
            "link_state": "up",
            "vpn_state": "not_configured",
            "bgp_state": "not_configured",
            "route_count": 5,
            "nat_table_size": 120,
        },
        "routes": {
            "ns-ce": "default via 100.64.0.2 dev eth1 proto static\n10.10.0.0/24 dev eth0 proto kernel"
        },
        "interface_status": {"ns-ce": "eth0: <BROADCAST,MULTICAST,UP,LOWER_UP>"},
        "nat_table": "Chain POSTROUTING (policy ACCEPT)\nMASQUERADE  all -- 10.10.0.0/24 0.0.0.0/0",
        "vpn_status": {"wireguard": "not_configured"},
        "bgp_status": {},
        "pcap_summary": {},
        "failure_mode": "test",
    }
    # Deep merge telemetry overrides
    if "telemetry" in overrides:
        base["telemetry"].update(overrides.pop("telemetry"))
    base.update(overrides)
    return base


class TestL1Rules:
    def test_link_down_detected(self):
        diag = _make_diag({"telemetry": {"link_state": "down", "packet_loss_percent": 99.9}})
        findings = analyze_diagnostics(diag)
        assert any(f.rule_id == "L1_LINK_DOWN" for f in findings), "L1_LINK_DOWN should fire"

    def test_high_loss_detected(self):
        diag = _make_diag({"telemetry": {"packet_loss_percent": 7.5, "link_state": "degraded"}})
        findings = analyze_diagnostics(diag)
        assert any(f.rule_id == "L1_HIGH_LOSS" for f in findings)

    def test_signal_degraded(self):
        diag = _make_diag({"telemetry": {"signal_quality": 0.5}})
        findings = analyze_diagnostics(diag)
        assert any(f.rule_id == "L1_SIGNAL_DEGRADED" for f in findings)

    def test_thermal_alert(self):
        diag = _make_diag({"telemetry": {"modem_temperature_c": 82.0}})
        findings = analyze_diagnostics(diag)
        assert any(f.rule_id == "L1_THERMAL" for f in findings)

    def test_healthy_no_l1_findings(self):
        diag = _make_diag({})
        findings = analyze_diagnostics(diag)
        l1_findings = [f for f in findings if f.rule_id.startswith("L1_")]
        assert not l1_findings, f"Healthy system should have no L1 findings, got: {l1_findings}"


class TestL3Rules:
    def test_nat_missing_detected(self):
        diag = _make_diag({"nat_table": "Chain POSTROUTING (policy ACCEPT)"})
        findings = analyze_diagnostics(diag)
        assert any(f.rule_id == "L3_NAT_BROKEN" for f in findings)

    def test_nat_present_no_false_positive(self):
        diag = _make_diag({})  # nat_table has MASQUERADE in base
        findings = analyze_diagnostics(diag)
        assert not any(f.rule_id == "L3_NAT_BROKEN" for f in findings)

    def test_bgp_down_detected(self):
        diag = _make_diag({"telemetry": {"bgp_state": "active"}})
        findings = analyze_diagnostics(diag)
        assert any(f.rule_id == "L3_BGP_DOWN" for f in findings)

    def test_bgp_idle_detected(self):
        diag = _make_diag({"telemetry": {"bgp_state": "idle"}})
        findings = analyze_diagnostics(diag)
        assert any(f.rule_id == "L3_BGP_DOWN" for f in findings)

    def test_missing_default_route(self):
        diag = _make_diag({"routes": {"ns-ce": "10.10.0.0/24 dev eth0 proto kernel"}})
        diag["telemetry"]["route_count"] = 1
        findings = analyze_diagnostics(diag)
        assert any(f.rule_id == "L3_NO_DEFAULT_ROUTE" for f in findings)


class TestL4Rules:
    def test_vpn_blocked_detected(self):
        diag = _make_diag({
            "telemetry": {"vpn_state": "down"},
            "pcap_summary": {"keywords": "UDP 51820 no response"},
        })
        findings = analyze_diagnostics(diag)
        assert any(f.rule_id == "L4_VPN_BLOCKED" for f in findings)

    def test_high_retransmissions(self):
        diag = _make_diag({
            "telemetry": {"packet_loss_percent": 5.0},
            "pcap_summary": {"issues": "TCP Retransmission Dup ACK"},
        })
        findings = analyze_diagnostics(diag)
        assert any(f.rule_id == "L4_HIGH_RETRANSMISSIONS" for f in findings)


class TestL7Rules:
    def test_dns_failure_detected(self):
        diag = _make_diag({
            "pcap_summary": {"issues": "DNS No response query unanswered"},
            "failure_mode": "dns_failure",
        })
        findings = analyze_diagnostics(diag)
        assert any(f.rule_id == "L7_DNS_FAILURE" for f in findings)


class TestFormatOutput:
    def test_empty_findings_produces_healthy_result(self):
        diag = _make_diag({})
        result = format_output(diag, [])
        assert result["confidence"] == 0.0
        assert "healthy" in result["probable_cause"].lower() or "no anomalies" in result["probable_cause"].lower()

    def test_top_finding_becomes_probable_cause(self):
        diag = _make_diag({"telemetry": {"link_state": "down", "packet_loss_percent": 99.9}})
        findings = analyze_diagnostics(diag)
        result = format_output(diag, findings)
        assert result["confidence"] > 0.0
        assert result["osi_layer"] != "N/A"
        assert len(result["evidence"]) > 0

    def test_confidence_sorted(self):
        diag = _make_diag({
            "telemetry": {
                "link_state": "down",
                "packet_loss_percent": 99.9,
                "bgp_state": "idle",
            }
        })
        findings = analyze_diagnostics(diag)
        if len(findings) >= 2:
            for i in range(len(findings) - 1):
                assert findings[i].confidence >= findings[i + 1].confidence
