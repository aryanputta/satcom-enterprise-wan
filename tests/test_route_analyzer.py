"""Tests for route_analyzer.py"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "analyzer"))

from route_analyzer import parse_route_table, check_end_to_end_path


SAMPLE_CE_ROUTES = """\
default via 100.64.0.2 dev eth1 proto static
10.10.0.0/24 dev eth0 proto kernel scope link src 10.10.0.1
100.64.0.0/30 dev eth1 proto kernel scope link src 100.64.0.1
192.168.100.0/24 via 100.65.0.2 dev eth1 proto bgp metric 20
"""

SAMPLE_CE_NO_DEFAULT = """\
10.10.0.0/24 dev eth0 proto kernel scope link src 10.10.0.1
100.64.0.0/30 dev eth1 proto kernel scope link src 100.64.0.1
"""

SAMPLE_BGP_ONLY_ROUTES = """\
default via 100.64.0.2 dev eth1 proto bgp
192.168.100.0/24 via 100.65.0.2 dev eth1 proto bgp metric 20
"""


class TestParseRouteTable:
    def test_parses_default_route(self):
        analysis = parse_route_table(SAMPLE_CE_ROUTES, "ns-ce")
        assert analysis.has_default_route
        assert analysis.default_via == "100.64.0.2"

    def test_no_default_route_raises_issue(self):
        analysis = parse_route_table(SAMPLE_CE_NO_DEFAULT, "ns-ce")
        assert not analysis.has_default_route
        assert not analysis.healthy
        assert any("default route" in issue.lower() for issue in analysis.issues)

    def test_bgp_routes_detected(self):
        analysis = parse_route_table(SAMPLE_CE_ROUTES, "ns-ce")
        bgp_routes = [r for r in analysis.routes if r.proto == "bgp"]
        assert len(bgp_routes) == 1
        assert bgp_routes[0].prefix == "192.168.100.0/24"

    def test_route_count(self):
        analysis = parse_route_table(SAMPLE_CE_ROUTES, "ns-ce")
        assert len(analysis.routes) == 4

    def test_empty_table(self):
        analysis = parse_route_table("", "ns-ce")
        assert not analysis.has_default_route
        assert not analysis.healthy

    def test_namespace_stored(self):
        analysis = parse_route_table(SAMPLE_CE_ROUTES, "ns-ce")
        assert analysis.namespace == "ns-ce"


class TestEndToEndPath:
    def _make_tables(self, missing_ns: str | None = None):
        good_routes = """\
default via 10.0.0.1 dev eth0 proto static
192.168.100.0/24 via 10.0.0.2 dev eth0 proto static
"""
        namespaces = ["ns-enterprise", "ns-ce", "ns-satcom", "ns-pop", "ns-cloud", "ns-app"]
        tables = {}
        for ns in namespaces:
            if ns == missing_ns:
                tables[ns] = parse_route_table("", ns)
            else:
                tables[ns] = parse_route_table(good_routes, ns)
        return tables

    def test_complete_path(self):
        tables = self._make_tables()
        result = check_end_to_end_path(tables)
        assert result["complete"]
        assert not result["issues"]

    def test_broken_at_pop(self):
        tables = self._make_tables(missing_ns="ns-pop")
        result = check_end_to_end_path(tables)
        assert not result["complete"]
        assert any("ns-pop" in issue for issue in result["issues"])
