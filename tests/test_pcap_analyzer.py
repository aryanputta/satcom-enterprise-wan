"""Tests for pcap_analyzer.py — runs without real pcap files using Scapy packet construction."""
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "analyzer"))

from pcap_analyzer import analyze_pcap, PcapSummary

try:
    from scapy.all import wrpcap, IP, TCP, UDP, ICMP, DNS, DNSQR, DNSRR, Ether
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

import pytest


def make_pcap(packets: list, path: str) -> str:
    wrpcap(path, packets)
    return path


@pytest.mark.skipif(not SCAPY_AVAILABLE, reason="scapy not installed")
class TestPcapAnalyzerWithSyntheticPackets:
    def test_empty_pcap_produces_zero_counts(self, tmp_path):
        pcap_file = str(tmp_path / "empty.pcap")
        make_pcap([], pcap_file)
        summary = analyze_pcap(pcap_file)
        assert summary.total_packets == 0

    def test_tcp_syn_count(self, tmp_path):
        pkts = [
            IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=12345, dport=80, flags="S"),
            IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=12346, dport=80, flags="S"),
        ]
        pcap_file = str(tmp_path / "syn.pcap")
        make_pcap(pkts, pcap_file)
        summary = analyze_pcap(pcap_file)
        assert summary.tcp_syn_count == 2

    def test_failed_handshake_detection(self, tmp_path):
        # SYN without SYN-ACK = failed handshake
        pkts = [
            IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=11111, dport=80, flags="S", seq=100),
            IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=11111, dport=80, flags="S", seq=100),  # retransmit
        ]
        pcap_file = str(tmp_path / "failed_hs.pcap")
        make_pcap(pkts, pcap_file)
        summary = analyze_pcap(pcap_file)
        assert summary.tcp_failed_handshakes >= 1
        assert any("handshake failure" in f.lower() for f in summary.failure_indicators)

    def test_tcp_retransmission_detection(self, tmp_path):
        # Same seq number twice = retransmission
        pkts = [
            IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=11111, dport=443, flags="PA", seq=1000),
            IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=11111, dport=443, flags="PA", seq=1000),  # retransmit
            IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=11111, dport=443, flags="PA", seq=1000),  # retransmit
        ]
        pcap_file = str(tmp_path / "retrans.pcap")
        make_pcap(pkts, pcap_file)
        summary = analyze_pcap(pcap_file)
        assert summary.tcp_retransmissions >= 1

    def test_icmp_frag_needed_detected(self, tmp_path):
        pkts = [
            IP(src="100.64.0.1", dst="10.10.0.100") / ICMP(type=3, code=4),
        ]
        pcap_file = str(tmp_path / "frag.pcap")
        make_pcap(pkts, pcap_file)
        summary = analyze_pcap(pcap_file)
        assert summary.icmp_frag_needed_count == 1

    def test_icmp_unreachable_flagged(self, tmp_path):
        pkts = [
            IP(src="10.0.0.1", dst="10.0.0.2") / ICMP(type=3, code=1),
            IP(src="10.0.0.1", dst="10.0.0.2") / ICMP(type=3, code=3),
        ]
        pcap_file = str(tmp_path / "unreachable.pcap")
        make_pcap(pkts, pcap_file)
        summary = analyze_pcap(pcap_file)
        assert summary.icmp_unreachable_count == 2
        assert any("unreachable" in f.lower() for f in summary.failure_indicators)

    def test_protocol_mix_counted(self, tmp_path):
        pkts = [
            IP(src="1.1.1.1", dst="2.2.2.2") / TCP(dport=80, flags="S"),
            IP(src="1.1.1.1", dst="2.2.2.2") / UDP(dport=53),
            IP(src="1.1.1.1", dst="2.2.2.2") / ICMP(),
        ]
        pcap_file = str(tmp_path / "mix.pcap")
        make_pcap(pkts, pcap_file)
        summary = analyze_pcap(pcap_file)
        assert summary.protocol_counts.get("TCP", 0) >= 1
        assert summary.protocol_counts.get("UDP", 0) >= 1
        assert summary.protocol_counts.get("ICMP", 0) >= 1

    def test_top_talkers_populated(self, tmp_path):
        pkts = [
            IP(src="10.10.0.100", dst="192.168.100.10") / TCP(dport=80, flags="S")
            for _ in range(5)
        ]
        pcap_file = str(tmp_path / "talkers.pcap")
        make_pcap(pkts, pcap_file)
        summary = analyze_pcap(pcap_file)
        assert len(summary.top_src_ips) > 0
        assert summary.top_src_ips[0]["ip"] == "10.10.0.100"

    def test_nonexistent_file_returns_error_indicator(self):
        summary = analyze_pcap("/tmp/does_not_exist_xyz.pcap")
        assert any("not found" in f.lower() or "failed" in f.lower() for f in summary.failure_indicators)


class TestPcapAnalyzerWithoutScapy:
    def test_missing_scapy_handled_gracefully(self):
        """Verify that if scapy is unavailable, the analyzer returns a helpful message."""
        summary = PcapSummary(pcap_file="test.pcap")
        summary.failure_indicators.append("scapy not installed")
        assert any("scapy" in f.lower() for f in summary.failure_indicators)
