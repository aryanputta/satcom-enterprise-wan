"""
Root Cause Analyzer for SATCOM Enterprise WAN.

Ingests:
  - telemetry JSON (from FastAPI or collect_diagnostics.sh)
  - routing table snapshots
  - BGP status
  - VPN status
  - pcap summary (from pcap_analyzer.py)

Outputs:
  - probable_cause
  - osi_layer
  - evidence list
  - recommended_fix
  - confidence score (0.0 - 1.0)

OSI classification: L1 -> L2 -> L3 -> L4 -> L7
Each layer's rules fire independently; highest confidence wins with evidence merging.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path

import yaml
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

RULES_DIR = Path(__file__).parent / "rules"
console = Console()


@dataclass
class Finding:
    rule_id: str
    name: str
    osi_layer: str
    confidence: float
    evidence: list[str] = field(default_factory=list)
    remediation: str = ""

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "name": self.name,
            "osi_layer": self.osi_layer,
            "confidence": round(self.confidence, 3),
            "evidence": self.evidence,
            "remediation": self.remediation.strip(),
        }


def load_rules(layer_file: str) -> list[dict]:
    path = RULES_DIR / layer_file
    if not path.exists():
        return []
    with path.open() as f:
        data = yaml.safe_load(f)
    return data.get("rules", [])


def _val_matches(value, condition) -> bool:
    """Evaluate a rule match condition against an actual value."""
    if isinstance(condition, dict):
        for op, threshold in condition.items():
            if op == "gte" and not (isinstance(value, (int, float)) and value >= threshold):
                return False
            elif op == "lte" and not (isinstance(value, (int, float)) and value <= threshold):
                return False
            elif op == "gt" and not (isinstance(value, (int, float)) and value > threshold):
                return False
            elif op == "lt" and not (isinstance(value, (int, float)) and value < threshold):
                return False
            elif op == "in" and value not in threshold:
                return False
        return True
    # Direct equality
    return value == condition


def _check_pcap_keywords(pcap_summary: dict, keywords: list[str]) -> list[str]:
    """Return which keywords appear in pcap summary fields."""
    text = json.dumps(pcap_summary).lower()
    return [kw for kw in keywords if kw.lower() in text]


def analyze_diagnostics(diag: dict) -> list[Finding]:
    """Run all rule layers against a diagnostics snapshot."""
    telemetry: dict = diag.get("telemetry", {})
    routes: dict = diag.get("routes", {})
    vpn_status: dict = diag.get("vpn_status", {})
    bgp_status: dict = diag.get("bgp_status", {})
    pcap_summary: dict = diag.get("pcap_summary", {})
    nat_table: str = diag.get("nat_table", "")
    iface_status: dict = diag.get("interface_status", {})
    failure_mode: str = diag.get("failure_mode", "unknown")

    findings: list[Finding] = []

    for layer_file in ["layer1_rules.yaml", "layer2_rules.yaml",
                        "layer3_rules.yaml", "layer4_rules.yaml",
                        "layer7_rules.yaml"]:
        rules = load_rules(layer_file)
        for rule in rules:
            match_criteria = rule.get("match", {})
            evidence: list[str] = []
            rule_fires = True
            confidence_mod = 1.0

            for field_name, condition in match_criteria.items():

                # Direct telemetry field match
                if field_name in telemetry:
                    val = telemetry[field_name]
                    if _val_matches(val, condition):
                        evidence.append(f"telemetry.{field_name}={val!r} matches {condition!r}")
                    else:
                        rule_fires = False
                        break

                # Inferred fields
                elif field_name == "nat_masquerade_missing":
                    masq_missing = "MASQUERADE" not in nat_table
                    if masq_missing and condition:
                        evidence.append("NAT MASQUERADE rule absent from iptables nat table")
                    elif not masq_missing and condition:
                        rule_fires = False; break

                elif field_name == "missing_default_route":
                    ce_routes = routes.get("ns-ce", routes.get("ce", ""))
                    has_default = "default" in ce_routes or "0.0.0.0/0" in ce_routes
                    if not has_default and condition:
                        evidence.append("No default route found in CE routing table")
                    elif has_default and condition:
                        rule_fires = False; break

                elif field_name == "interface_down_keywords":
                    iface_text = json.dumps(iface_status)
                    found_kws = [kw for kw in condition if kw in iface_text]
                    if found_kws:
                        evidence.append(f"Interface status contains down indicators: {found_kws}")
                    else:
                        rule_fires = False; break

                elif field_name == "pcap_keywords":
                    found = _check_pcap_keywords(pcap_summary, condition)
                    if found:
                        evidence.append(f"Pcap keywords found: {found}")
                    else:
                        # Soft: don't block rule but reduce confidence
                        confidence_mod *= 0.75

                elif field_name == "large_ping_fail":
                    # Check experiment output files
                    exp_dir = Path("experiments") / failure_mode
                    large_fail = (exp_dir / "ping_large.txt").exists() and \
                        "100% packet loss" in (exp_dir / "ping_large.txt").read_text(errors="ignore") \
                        if (exp_dir / "ping_large.txt").exists() else False
                    if large_fail and condition:
                        evidence.append("Large packet ping test failed (MTU black hole confirmed)")
                    else:
                        confidence_mod *= 0.7

                elif field_name == "small_ping_success":
                    exp_dir = Path("experiments") / failure_mode
                    small_ok = (exp_dir / "ping_small.txt").exists() and \
                        "0% packet loss" in (exp_dir / "ping_small.txt").read_text(errors="ignore") \
                        if (exp_dir / "ping_small.txt").exists() else False
                    if small_ok and condition:
                        evidence.append("Small packet ping succeeds (confirms asymmetric MTU failure)")
                    else:
                        confidence_mod *= 0.7

                # Ignore unknown match fields gracefully
                # (field may be for future extension)

            if rule_fires and evidence:
                final_confidence = rule["confidence"] * confidence_mod
                f = Finding(
                    rule_id=rule["id"],
                    name=rule["name"],
                    osi_layer=rule["osi_layer"],
                    confidence=final_confidence,
                    evidence=evidence,
                    remediation=rule.get("remediation", ""),
                )
                findings.append(f)

    # Sort by confidence descending
    findings.sort(key=lambda x: x.confidence, reverse=True)
    return findings


def format_output(diag: dict, findings: list[Finding]) -> dict:
    """Build final JSON output matching the project spec."""
    incident = diag.get("experiment", "unknown")
    timestamp = diag.get("timestamp", "")

    if not findings:
        return {
            "incident": incident,
            "timestamp": timestamp,
            "probable_cause": "No anomalies detected — system appears healthy",
            "osi_layer": "N/A",
            "evidence": ["All telemetry metrics within normal bounds"],
            "recommended_fix": "None required",
            "confidence": 0.0,
            "all_findings": [],
        }

    top = findings[0]
    return {
        "incident": incident,
        "timestamp": timestamp,
        "probable_cause": top.name,
        "osi_layer": top.osi_layer,
        "evidence": top.evidence,
        "recommended_fix": top.remediation.strip(),
        "confidence": round(top.confidence, 3),
        "all_findings": [f.to_dict() for f in findings],
    }


def print_rich(result: dict) -> None:
    confidence = result["confidence"]
    color = "green" if confidence >= 0.85 else "yellow" if confidence >= 0.6 else "red"

    console.print()
    console.print(Panel(
        f"[bold]Incident:[/bold] {result['incident']}\n"
        f"[bold]Probable Cause:[/bold] {result['probable_cause']}\n"
        f"[bold]OSI Layer:[/bold] {result['osi_layer']}\n"
        f"[bold {color}]Confidence:[/bold {color}] {result['confidence']:.1%}",
        title="[bold blue]Root Cause Analyzer[/bold blue]",
        border_style="blue"
    ))

    if result["evidence"]:
        tbl = Table(title="Evidence", show_header=True, header_style="bold cyan")
        tbl.add_column("#", style="dim", width=3)
        tbl.add_column("Evidence Item")
        for i, ev in enumerate(result["evidence"], 1):
            tbl.add_row(str(i), ev)
        console.print(tbl)

    console.print(Panel(
        result["recommended_fix"] or "No recommendation available.",
        title="[bold green]Recommended Fix[/bold green]",
        border_style="green"
    ))

    if len(result.get("all_findings", [])) > 1:
        console.print("\n[dim]Secondary findings:[/dim]")
        for f in result["all_findings"][1:4]:
            console.print(f"  [{f['osi_layer']}] {f['name']} (confidence: {f['confidence']:.0%})")


def main() -> None:
    parser = argparse.ArgumentParser(description="SATCOM WAN Root Cause Analyzer")
    parser.add_argument("--input", required=True, help="Path to diagnostics.json")
    parser.add_argument("--output", help="Write JSON result to this path")
    parser.add_argument("--json-only", action="store_true", help="Machine-readable output only")
    args = parser.parse_args()

    diag_path = Path(args.input)
    if not diag_path.exists():
        console.print(f"[red]ERROR: {diag_path} not found[/red]")
        sys.exit(1)

    with diag_path.open() as f:
        diag = json.load(f)

    findings = analyze_diagnostics(diag)
    result = format_output(diag, findings)

    if args.json_only:
        print(json.dumps(result, indent=2))
    else:
        print_rich(result)
        print()
        print(json.dumps(result, indent=2))

    if args.output:
        out = Path(args.output)
        out.parent.mkdir(parents=True, exist_ok=True)
        with out.open("w") as f:
            json.dump(result, f, indent=2)
        console.print(f"\n[green]Result written to {out}[/green]")


if __name__ == "__main__":
    main()
