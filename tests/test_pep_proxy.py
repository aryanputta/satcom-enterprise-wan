"""Tests for tcp_pep/pep_proxy.py"""
import asyncio
import socket
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "tcp_pep"))

from pep_proxy import (
    PEPProxy, PepStats, _apply_satcom_socket_opts, BDP_BYTES,
    _relay, run_benchmark,
)


class TestBDPConstants:
    def test_bdp_is_large_enough_for_satcom(self):
        # BDP = 140 Mbps × 90ms = 1.575 MB — our buffer must exceed this
        satcom_bdp_bytes = 140 * 1_000_000 * 0.090 / 8
        assert BDP_BYTES >= satcom_bdp_bytes

    def test_bdp_exceeds_default_tcp_window(self):
        default_tcp_window = 64 * 1024
        assert BDP_BYTES > default_tcp_window * 10


class TestSocketOpts:
    def test_apply_opts_does_not_raise(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            _apply_satcom_socket_opts(sock)   # should not raise on any platform
        finally:
            sock.close()

    def test_apply_opts_sets_rcvbuf(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            _apply_satcom_socket_opts(sock)
            # OS may round up to next power of 2; just check it's larger than default
            rcvbuf = sock.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF)
            assert rcvbuf >= 64 * 1024
        finally:
            sock.close()


class TestPepProxyUnit:
    def test_stats_initialized_to_zero(self):
        stats = PepStats(start_time=0)
        assert stats.connections_accepted == 0
        assert stats.bytes_ce_to_pop == 0
        assert stats.active_connections == 0

    def test_stats_to_dict(self):
        stats = PepStats(start_time=0)
        d = stats.to_dict()
        assert "connections_accepted" in d
        assert "bytes_ce_to_pop" in d
        assert isinstance(d["uptime_s"], float)

    def test_proxy_construction(self):
        proxy = PEPProxy(
            listen_host="127.0.0.1",
            listen_port=19081,
            upstream_host="127.0.0.1",
            upstream_port=19082,
        )
        assert proxy.listen_port == 19081
        assert proxy.upstream_port == 19082


class TestPepProxyIntegration:
    """End-to-end proxy relay using real asyncio connections."""

    def _start_echo_server(self) -> tuple[asyncio.AbstractServer, int]:
        """Start a simple TCP echo server on a random port."""
        import asyncio

        async def handle(reader, writer):
            data = await reader.read(4096)
            writer.write(data)
            await writer.drain()
            writer.close()

        async def start():
            server = await asyncio.start_server(handle, "127.0.0.1", 0)
            return server

        loop = asyncio.new_event_loop()
        server = loop.run_until_complete(start())
        port = server.sockets[0].getsockname()[1]
        return server, port, loop

    def test_proxy_relays_data(self):
        import asyncio

        received = []

        async def echo_handler(reader, writer):
            data = await reader.read(4096)
            received.append(data)
            writer.write(data)
            await writer.drain()
            writer.close()

        async def run_test():
            # Start echo backend
            echo_server = await asyncio.start_server(echo_handler, "127.0.0.1", 0)
            echo_port = echo_server.sockets[0].getsockname()[1]

            # Start PEP proxy pointing to echo backend
            proxy = PEPProxy(
                listen_host="127.0.0.1", listen_port=0,
                upstream_host="127.0.0.1", upstream_port=echo_port,
            )
            proxy_server = await asyncio.start_server(
                proxy._handle_connection, "127.0.0.1", 0
            )
            proxy_port = proxy_server.sockets[0].getsockname()[1]

            # Send data through proxy
            reader, writer = await asyncio.open_connection("127.0.0.1", proxy_port)
            writer.write(b"SATCOM_TEST_PAYLOAD")
            await writer.drain()
            response = await asyncio.wait_for(reader.read(64), timeout=2.0)
            writer.close()

            echo_server.close()
            proxy_server.close()

            assert response == b"SATCOM_TEST_PAYLOAD"
            assert len(received) == 1

        asyncio.run(run_test())

    def test_proxy_stats_updated_on_connection(self):
        import asyncio

        async def run_test():
            async def echo(reader, writer):
                data = await reader.read(1024)
                writer.write(data)
                await writer.drain()
                writer.close()

            echo_server = await asyncio.start_server(echo, "127.0.0.1", 0)
            echo_port = echo_server.sockets[0].getsockname()[1]

            proxy = PEPProxy("127.0.0.1", 0, "127.0.0.1", echo_port)
            proxy.stats.start_time = __import__("time").time()
            proxy_server = await asyncio.start_server(
                proxy._handle_connection, "127.0.0.1", 0
            )
            proxy_port = proxy_server.sockets[0].getsockname()[1]

            reader, writer = await asyncio.open_connection("127.0.0.1", proxy_port)
            writer.write(b"x" * 1024)
            await writer.drain()
            await asyncio.wait_for(reader.read(1024), timeout=2.0)
            writer.close()

            # Give proxy a moment to update stats
            await asyncio.sleep(0.05)

            echo_server.close()
            proxy_server.close()

            assert proxy.stats.connections_accepted >= 1
            assert proxy.stats.bytes_ce_to_pop >= 1024

        asyncio.run(run_test())
