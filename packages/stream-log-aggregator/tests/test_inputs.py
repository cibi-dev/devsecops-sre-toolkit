"""Tests for Syslog TCP, UDP, Unix Domain Socket, and File Tail inputs."""

import asyncio
import os
import stat
import tempfile
import pytest
from aggregator import LogEvent
from aggregator.inputs import BaseInput
from aggregator.inputs.file_tail import FileTailInput
from aggregator.inputs.tcp import SyslogTCPInput, UnixSocketInput
from aggregator.inputs.udp import SyslogUDPInput


class DummyInput(BaseInput):
    """Test concrete implementation of BaseInput."""
    async def start(self, target_queue: asyncio.Queue) -> None:
        self._target_queue = target_queue
        self._running = True

    async def stop(self) -> None:
        self._running = False


@pytest.mark.asyncio
class TestInputs:
    """Test suite for input adapters."""

    async def test_base_input_guards(self):
        """Verify BaseInput emit guards when not running or no queue."""
        inp = DummyInput("test-base")
        assert inp.is_running is False
        await inp.emit("Line before start")
        assert inp.metrics["events_received"] == 0

        queue = asyncio.Queue()
        await inp.start(queue)
        assert inp.is_running is True
        await inp.emit("Line after start")
        assert inp.metrics["events_received"] == 1

        ev = await queue.get()
        assert ev.raw == "Line after start"
        await inp.stop()

    async def test_syslog_tcp_input_ingestion(self):
        """Verify TCP Syslog receiver ingests newline-delimited stream."""
        queue: asyncio.Queue[LogEvent] = asyncio.Queue()
        tcp_input = SyslogTCPInput(host="127.0.0.1", port=0)
        await tcp_input.start(queue)
        # Idempotent start
        await tcp_input.start(queue)

        server_port = tcp_input._server.sockets[0].getsockname()[1]

        reader, writer = await asyncio.open_connection("127.0.0.1", server_port)
        writer.write(b"<134>Feb 15 14:00:00 srv1 app: Line 1\n<134>Feb 15 14:00:01 srv1 app: Line 2\n")
        await writer.drain()
        writer.close()
        await writer.wait_closed()

        e1 = await asyncio.wait_for(queue.get(), timeout=1.0)
        e2 = await asyncio.wait_for(queue.get(), timeout=1.0)

        assert "Line 1" in e1.raw
        assert "Line 2" in e2.raw
        assert tcp_input.metrics["events_received"] == 2

        await tcp_input.stop()
        # Idempotent stop
        await tcp_input.stop()

    async def test_syslog_tcp_idle_timeout(self):
        """Verify TCP receiver drops idle connections after idle_timeout."""
        queue: asyncio.Queue[LogEvent] = asyncio.Queue()
        tcp_input = SyslogTCPInput(host="127.0.0.1", port=0, idle_timeout=0.1)
        await tcp_input.start(queue)

        server_port = tcp_input._server.sockets[0].getsockname()[1]
        reader, writer = await asyncio.open_connection("127.0.0.1", server_port)

        # Wait longer than idle_timeout without sending data
        await asyncio.sleep(0.2)
        data = await reader.read()
        assert data == b""

        writer.close()
        await tcp_input.stop()

    async def test_syslog_udp_input_ingestion(self):
        """Verify UDP Syslog receiver ingests datagrams."""
        queue: asyncio.Queue[LogEvent] = asyncio.Queue()
        udp_input = SyslogUDPInput(host="127.0.0.1", port=0)
        await udp_input.start(queue)
        # Idempotent start
        await udp_input.start(queue)

        server_port = udp_input._transport.get_extra_info("sockname")[1]

        loop = asyncio.get_running_loop()
        transport, _ = await loop.create_datagram_endpoint(
            asyncio.DatagramProtocol,
            remote_addr=("127.0.0.1", server_port),
        )
        transport.sendto(b"<165>1 2026-08-27T20:00:00Z host app 12 - UDP Log Message\n")
        transport.close()

        event = await asyncio.wait_for(queue.get(), timeout=1.0)
        assert "UDP Log Message" in event.raw
        assert udp_input.metrics["events_received"] >= 1

        await udp_input.stop()
        # Idempotent stop
        await udp_input.stop()

    async def test_unix_socket_input_ingestion_and_permissions(self):
        """Verify Unix Domain Socket listener and 0o600 file permissions."""
        with tempfile.TemporaryDirectory() as tmpdir:
            sock_path = os.path.join(tmpdir, "syslog.sock")
            queue: asyncio.Queue[LogEvent] = asyncio.Queue()
            unix_input = UnixSocketInput(socket_path=sock_path)
            await unix_input.start(queue)
            # Idempotent start
            await unix_input.start(queue)

            assert os.path.exists(sock_path)
            sock_mode = stat.S_IMODE(os.stat(sock_path).st_mode)
            assert sock_mode == 0o600

            reader, writer = await asyncio.open_unix_connection(sock_path)
            writer.write(b"Unix socket test log\n")
            await writer.drain()
            writer.close()
            await writer.wait_closed()

            event = await asyncio.wait_for(queue.get(), timeout=1.0)
            assert event.raw == "Unix socket test log"
            assert "unix:" in event.source

            await unix_input.stop()
            assert not os.path.exists(sock_path)

    async def test_file_tail_input_live_append_and_rotation(self):
        """Verify FileTailInput captures appended lines and handles logrotate."""
        with tempfile.TemporaryDirectory() as tmpdir:
            log_file = os.path.join(tmpdir, "service.log")
            with open(log_file, "w", encoding="utf-8") as f:
                f.write("Initial line 0\n")

            queue: asyncio.Queue[LogEvent] = asyncio.Queue()
            tail_input = FileTailInput(
                file_path=log_file,
                start_from_beginning=True,
                poll_interval=0.02,
            )
            await tail_input.start(queue)
            # Idempotent start
            await tail_input.start(queue)

            e0 = await asyncio.wait_for(queue.get(), timeout=1.0)
            assert e0.raw == "Initial line 0"

            with open(log_file, "a", encoding="utf-8") as f:
                f.write("Appended line 1\n")

            e1 = await asyncio.wait_for(queue.get(), timeout=1.0)
            assert e1.raw == "Appended line 1"

            # Simulate logrotate (truncate/copytruncate)
            with open(log_file, "w", encoding="utf-8") as f:
                f.write("Truncated line 2\n")

            e2 = await asyncio.wait_for(queue.get(), timeout=1.0)
            assert e2.raw == "Truncated line 2"

            await tail_input.stop()

    async def test_file_tail_missing_file_creation(self):
        """Verify FileTailInput waits for a non-existent file to be created."""
        with tempfile.TemporaryDirectory() as tmpdir:
            log_file = os.path.join(tmpdir, "delayed.log")
            queue: asyncio.Queue[LogEvent] = asyncio.Queue()
            tail_input = FileTailInput(
                file_path=log_file,
                start_from_beginning=True,
                poll_interval=0.02,
            )
            await tail_input.start(queue)

            # Wait briefly while file does not exist
            await asyncio.sleep(0.05)

            # Create file
            with open(log_file, "w", encoding="utf-8") as f:
                f.write("Delayed line\n")

            event = await asyncio.wait_for(queue.get(), timeout=1.0)
            assert event.raw == "Delayed line"

            await tail_input.stop()

    async def test_oversized_payload_truncation(self):
        """Verify input adapter enforces CWE-400 size limit (>64KB)."""
        queue: asyncio.Queue[LogEvent] = asyncio.Queue()
        tcp_input = SyslogTCPInput(host="127.0.0.1", port=0)
        await tcp_input.start(queue)

        huge_payload = "A" * (70 * 1024)
        await tcp_input.emit(huge_payload)

        event = await queue.get()
        assert "[TRUNCATED_OVER_64KB]" in event.raw
        assert tcp_input.metrics["drops"] >= 1

        await tcp_input.stop()
