"""Tests for analyzer/bgp_convergence.py"""
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "analyzer"))
sys.path.insert(0, str(Path(__file__).parent.parent / "lab" / "frr"))

from frr_agent import SyntheticFRRAgent, ConvergenceEvent
from bgp_convergence import (
    ConvergenceRecord, ConvergenceBenchmark,
)


class TestConvergenceRecord:
    def _base_record(self, **kwargs) -> ConvergenceRecord:
        t0 = time.time()
        defaults = dict(
            trigger="manual_reset",
            peer_addr="100.65.0.2",
            namespace="ns-ce",
            t_trigger=t0,
        )
        defaults.update(kwargs)
        return ConvergenceRecord(**defaults)

    def test_time_to_established_computed(self):
        t0 = 1000.0
        r = self._base_record(t_trigger=t0, t_established=t0 + 12.5)
        assert r.time_to_established_s == 12.5

    def test_full_convergence_computed(self):
        t0 = 1000.0
        r = self._base_record(t_trigger=t0, t_full_convergence=t0 + 28.3)
        assert r.full_convergence_s == 28.3

    def test_none_when_not_complete(self):
        r = self._base_record()
        assert r.time_to_established_s is None
        assert r.full_convergence_s is None

    def test_to_dict_has_expected_keys(self):
        r = self._base_record()
        d = r.to_dict()
        assert "trigger" in d
        assert "time_to_established_s" in d
        assert "full_convergence_s" in d
        assert "hold_timer_s" in d


class TestConvergenceEvent:
    def test_measure_convergence_complete_sequence(self):
        t0 = 1000.0
        events = [
            ConvergenceEvent("100.65.0.2", "Established", "Idle",    timestamp=t0),
            ConvergenceEvent("100.65.0.2", "Idle",        "Connect", timestamp=t0 + 1),
            ConvergenceEvent("100.65.0.2", "Connect",     "Established", timestamp=t0 + 25),
        ]
        convergence_s = ConvergenceEvent.measure_convergence(events)
        assert convergence_s == 25.0

    def test_measure_convergence_incomplete_returns_none(self):
        t0 = 1000.0
        events = [
            ConvergenceEvent("100.65.0.2", "Established", "Idle", timestamp=t0),
        ]
        assert ConvergenceEvent.measure_convergence(events) is None

    def test_measure_convergence_empty_returns_none(self):
        assert ConvergenceEvent.measure_convergence([]) is None


class TestConvergenceBenchmark:
    def _make_bench(self, state="Established", prefixes=2):
        agent = SyntheticFRRAgent("ns-ce", state=state, prefixes_received=prefixes)
        return ConvergenceBenchmark(
            agent=agent,
            peer_addr="100.65.0.2",
            expected_prefixes=prefixes,
            poll_interval_s=0.01,  # fast poll for tests
            timeout_s=2.0,
        )

    def test_run_returns_record(self):
        bench = self._make_bench()
        record = bench.run(trigger="manual_reset")
        assert isinstance(record, ConvergenceRecord)

    def test_run_records_established(self):
        bench = self._make_bench(state="Established", prefixes=2)
        record = bench.run()
        # Synthetic agent is always established — t_full_convergence should be set
        assert record.t_full_convergence is not None

    def test_run_times_out_when_not_established(self):
        agent = SyntheticFRRAgent("ns-ce", state="Active", prefixes_received=0)
        bench = ConvergenceBenchmark(
            agent=agent, peer_addr="100.65.0.2",
            expected_prefixes=2, poll_interval_s=0.01, timeout_s=0.1,
        )
        record = bench.run()
        # Should complete (timeout), full_convergence will be None
        assert record.t_full_convergence is None

    def test_summary_stats_on_completed(self):
        bench = self._make_bench()
        bench.run_n(3)
        stats = bench.summary_stats()
        assert stats["completed"] == 3
        assert "full_convergence_s" in stats
        assert "mean" in stats["full_convergence_s"]

    def test_to_csv_output(self):
        bench = self._make_bench()
        bench.run()
        csv_text = bench.to_csv()
        assert "trigger" in csv_text
        assert "ns-ce" in csv_text

    def test_run_n_returns_all_records(self):
        bench = self._make_bench()
        records = bench.run_n(3)
        assert len(records) == 3


class TestFRRAgentSynthetic:
    def test_is_available(self):
        agent = SyntheticFRRAgent("ns-ce")
        assert agent.is_available() is True

    def test_get_bgp_summary_established(self):
        agent = SyntheticFRRAgent("ns-ce", state="Established")
        summary = agent.get_bgp_summary()
        assert summary is not None
        assert summary.all_established
        assert summary.local_as == 65001

    def test_get_bgp_summary_non_established(self):
        agent = SyntheticFRRAgent("ns-ce", state="Active")
        summary = agent.get_bgp_summary()
        assert not summary.all_established

    def test_get_bgp_rib_empty_when_down(self):
        agent = SyntheticFRRAgent("ns-ce", state="Active")
        rib = agent.get_bgp_rib()
        assert rib == []

    def test_get_bgp_rib_has_routes_when_established(self):
        agent = SyntheticFRRAgent("ns-ce", state="Established", prefixes_received=1)
        rib = agent.get_bgp_rib()
        assert len(rib) == 1
        assert "192.168.100.0/24" in rib[0].prefix
