"""
Packet Capture Analyzer using Scapy.

Analyzes pcap files at each network segment and produces a structured JSON summary
covering: protocol mix, TCP issues, DNS failures, ICMP errors, retransmissions,
handshake failures, and per-flow statistics.

Usage:
  python3 pcap_analyzer.py --pcap captures/baseline/ns-ce_eth1.pcap
  python3 pcap_analyzer.py --dir captures/nat_failure/ --output experiments/nat_failure/pcap_summary.json
"""

from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional

try:
    from scapy.all import rdpcap, TCP, UDP, ICMP, DNS, IP, Ether
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


@dataclass
class FlowKey:
    src_ip: str
    dst_ip: str
    proto: str
    src_port: int = 0
    dst_port: int = 0

    def __hash__(self):
        return hash((self.src_ip, self.dst_ip, self.proto, self.src_port, self.dst_port))

    def __eq__(self, other):
        return asdict(self) == asdict(other)


@dataclass
class PcapSummary:
    pcap_file: str
    total_packets: int = 0
    total_bytes: int = 0
    duration_seconds: float = 0.0

    # Protocol mix
    protocol_counts: dict = field(default_factory=dict)

    # TCP analysis
    tcp_syn_count: int = 0
    tcp_syn_ack_count: int = 0
    tcp_fin_count: int = 0
    tcp_rst_count: int = 0
    tcp_retransmissions: int = 0
    tcp_failed_handshakes: int = 0

    # DNS
    dns_query_count: int = 0
    dns_response_count: int = 0
    dns_nxdomain_count: int = 0
    dns_timeout_count: int = 0
    dns_queried_names: list = field(default_factory=list)

    # ICMP
    icmp_echo_count: int = 0
    icmp_unreachable_count: int = 0
    icmp_frag_needed_count: int = 0
    icmp_time_exceeded_count: int = 0

    # Top talkers
    top_src_ips: list = field(default_factory=list)
    top_dst_ips: list = field(default_factory=list)
    top_dst_ports: list = field(default_factory=list)

    # Failure indicators
    failure_indicators: list = field(default_factory=list)
    packet_loss_estimate_percent: float = 0.0


def analyze_pcap(pcap_path: str | Path) -> PcapSummary:
    """Analyze a single pcap file."""
    path = Path(pcap_path)
    summary = PcapSummary(pcap_file=str(path))

    if not SCAPY_AVAILABLE:
        summary.failure_indicators.append(
            "scapy not installed — install with: pip install scapy"
        )
        return summary

    if not path.exists():
        summary.failure_indicators.append(f"File not found: {path}")
        return summary

    try:
        packets = rdpcap(str(path))
    except Exception as e:
        summary.failure_indicators.append(f"Failed to read pcap: {e}")
        return summary

    if not packets:
        return summary

    # Basic stats
    summary.total_packets = len(packets)
    timestamps = [float(p.time) for p in packets if hasattr(p, "time")]
    if len(timestamps) >= 2:
        summary.duration_seconds = round(timestamps[-1] - timestamps[0], 3)

    proto_counter: Counter = Counter()
    src_ip_counter: Counter = Counter()
    dst_ip_counter: Counter = Counter()
    dst_port_counter: Counter = Counter()

    # Track TCP flows for handshake analysis
    # flow -> (syn_seen, syn_ack_seen)
    tcp_flows: dict = defaultdict(lambda: {"syn": 0, "syn_ack": 0, "seq_nums": set()})
    dns_queries: dict = {}  # txid -> timestamp

    for pkt in packets:
        size = len(pkt)
        summary.total_bytes += size

        if not pkt.haslayer(IP):
            continue

        ip = pkt[IP]
        src_ip_counter[ip.src] += 1
        dst_ip_counter[ip.dst] += 1

        # Protocol classification
        if pkt.haslayer(TCP):
            proto_counter["TCP"] += 1
            tcp = pkt[TCP]
            flags = tcp.flags

            dst_port_counter[tcp.dport] += 1

            flow_key = (ip.src, ip.dst, tcp.sport, tcp.dport)
            rev_key = (ip.dst, ip.src, tcp.dport, tcp.sport)

            # Flag analysis
            if flags & 0x02:  # SYN
                summary.tcp_syn_count += 1
                tcp_flows[flow_key]["syn"] += 1
            if flags & 0x12 == 0x12:  # SYN+ACK
                summary.tcp_syn_ack_count += 1
                tcp_flows[rev_key]["syn_ack"] += 1
            if flags & 0x01:  # FIN
                summary.tcp_fin_count += 1
            if flags & 0x04:  # RST
                summary.tcp_rst_count += 1

            # Naive retransmission detection: duplicate seq numbers in same flow
            seq = tcp.seq
            if seq in tcp_flows[flow_key]["seq_nums"] and seq != 0:
                summary.tcp_retransmissions += 1
            else:
                tcp_flows[flow_key]["seq_nums"].add(seq)

        elif pkt.haslayer(UDP):
            proto_counter["UDP"] += 1
            udp = pkt[UDP]
            dst_port_counter[udp.dport] += 1

            # DNS analysis
            if pkt.haslayer(DNS):
                dns = pkt[DNS]
                if dns.qr == 0:  # query
                    summary.dns_query_count += 1
                    proto_counter["DNS"] += 1
                    if dns.qd:
                        name = dns.qd.qname.decode(errors="ignore").rstrip(".")
                        dns_queries[dns.id] = {"name": name, "time": float(pkt.time)}
                        if name not in summary.dns_queried_names:
                            summary.dns_queried_names.append(name)
                else:  # response
                    summary.dns_response_count += 1
                    if dns.rcode == 3:  # NXDOMAIN
                        summary.dns_nxdomain_count += 1
                    if dns.id in dns_queries:
                        del dns_queries[dns.id]

        elif pkt.haslayer(ICMP):
            proto_counter["ICMP"] += 1
            icmp = pkt[ICMP]
            if icmp.type == 8:
                summary.icmp_echo_count += 1
            elif icmp.type == 3:
                summary.icmp_unreachable_count += 1
                if icmp.code == 4:
                    summary.icmp_frag_needed_count += 1
            elif icmp.type == 11:
                summary.icmp_time_exceeded_count += 1
        else:
            proto_counter["OTHER"] += 1

    # Count unanswered DNS queries as timeouts
    summary.dns_timeout_count = len(dns_queries)

    # Count failed TCP handshakes (SYN without SYN-ACK)
    for flow_key, state in tcp_flows.items():
        if state["syn"] > 0 and state["syn_ack"] == 0:
            summary.tcp_failed_handshakes += 1

    # Packet loss estimate from retransmissions
    if summary.total_packets > 0:
        summary.packet_loss_estimate_percent = round(
            (summary.tcp_retransmissions / max(1, summary.total_packets)) * 100, 2
        )

    # Top talkers
    summary.top_src_ips = [{"ip": ip, "count": cnt}
                           for ip, cnt in src_ip_counter.most_common(5)]
    summary.top_dst_ips = [{"ip": ip, "count": cnt}
                           for ip, cnt in dst_ip_counter.most_common(5)]
    summary.top_dst_ports = [{"port": port, "count": cnt}
                             for port, cnt in dst_port_counter.most_common(10)]
    summary.protocol_counts = dict(proto_counter.most_common())

    # Failure indicator detection
    if summary.tcp_failed_handshakes > 0:
        summary.failure_indicators.append(
            f"TCP handshake failures: {summary.tcp_failed_handshakes} SYNs without SYN-ACK"
        )
    if summary.tcp_retransmissions > 10:
        summary.failure_indicators.append(
            f"High TCP retransmissions: {summary.tcp_retransmissions} — indicates packet loss on path"
        )
    if summary.dns_timeout_count > 0:
        summary.failure_indicators.append(
            f"Unanswered DNS queries: {summary.dns_timeout_count} — possible DNS failure"
        )
    if summary.dns_nxdomain_count > 0:
        summary.failure_indicators.append(
            f"DNS NXDOMAIN responses: {summary.dns_nxdomain_count}"
        )
    if summary.icmp_unreachable_count > 0:
        summary.failure_indicators.append(
            f"ICMP unreachable messages: {summary.icmp_unreachable_count}"
        )
    if summary.icmp_frag_needed_count > 0:
        summary.failure_indicators.append(
            f"ICMP frag-needed (type 3 code 4): {summary.icmp_frag_needed_count} — MTU path discovery active"
        )
    elif summary.tcp_retransmissions > 5 and summary.icmp_frag_needed_count == 0:
        # High retransmissions with no frag-needed = possible MTU black hole
        summary.failure_indicators.append(
            "High retransmissions with NO ICMP frag-needed — possible MTU black hole"
        )
    if summary.tcp_rst_count > summary.tcp_syn_count * 0.3:
        summary.failure_indicators.append(
            f"High RST rate: {summary.tcp_rst_count} RSTs vs {summary.tcp_syn_count} SYNs — firewall or NAT issue"
        )

    return summary


def analyze_directory(pcap_dir: str | Path) -> list[PcapSummary]:
    """Analyze all pcap files in a directory."""
    pcap_dir = Path(pcap_dir)
    summaries = []
    for pcap_file in sorted(pcap_dir.glob("*.pcap")):
        s = analyze_pcap(pcap_file)
        summaries.append(s)
    return summaries


def main() -> None:
    parser = argparse.ArgumentParser(description="SATCOM WAN Packet Capture Analyzer")
    parser.add_argument("--pcap", help="Single pcap file to analyze")
    parser.add_argument("--dir", help="Directory of pcap files to analyze")
    parser.add_argument("--output", help="Write JSON summary to this path")
    args = parser.parse_args()

    summaries: list[PcapSummary] = []

    if args.pcap:
        summaries = [analyze_pcap(args.pcap)]
    elif args.dir:
        summaries = analyze_directory(args.dir)
    else:
        parser.error("Provide --pcap or --dir")

    result = [asdict(s) for s in summaries]
    output_json = json.dumps(result, indent=2, default=str)
    print(output_json)

    if args.output:
        out = Path(args.output)
        out.parent.mkdir(parents=True, exist_ok=True)
        with out.open("w") as f:
            f.write(output_json)
        print(f"\nSummary written to {out}", file=__import__("sys").stderr)


if __name__ == "__main__":
    main()
