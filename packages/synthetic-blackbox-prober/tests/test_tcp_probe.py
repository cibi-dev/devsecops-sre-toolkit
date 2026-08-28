"""Tests for TCP connectivity synthetic probe."""

import asyncio
import socket
from unittest.mock import patch
import pytest
from prober.probes.tcp import TCPProbe, TCPProbeResult


@pytest.fixture
async def mock_tcp_server():
    """Spin up a local TCP listener that accepts connections."""
    async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        try:
            await asyncio.sleep(0.01)
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    server = await asyncio.start_server(handle_client, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    yield ("127.0.0.1", port)
    server.close()
    await server.wait_closed()


@pytest.mark.asyncio
async def test_tcp_probe_success(mock_tcp_server):
    """Test successful TCP connection."""
    host, port = mock_tcp_server
    probe = TCPProbe(default_timeout=5.0)
    result = await probe.probe(host=host, port=port)

    assert result.status == "SUCCESS"
    assert result.connected is True
    assert result.is_success is True
    assert result.latency_ms > 0
    assert result.resolved_ip in ("127.0.0.1", "::1")
    assert result.error is None


@pytest.mark.asyncio
async def test_tcp_probe_connection_refused():
    """Test TCP connection to a closed port."""
    s = socket.socket()
    s.bind(("", 0))
    port = s.getsockname()[1]
    s.close()

    probe = TCPProbe(default_timeout=2.0)
    result = await probe.probe(host="127.0.0.1", port=port)

    assert result.status == "CONNECTION_REFUSED"
    assert result.connected is False
    assert result.is_success is False
    assert result.error is not None
    assert "Connection refused" in result.error


@pytest.mark.asyncio
async def test_tcp_probe_timeout():
    """Test TCP connection timeout on unreachable IP (e.g. non-routable test IP 192.0.2.1)."""
    probe = TCPProbe(default_timeout=0.2)
    result = await probe.probe(host="192.0.2.1", port=81, timeout=0.2)

    assert result.status == "TIMEOUT"
    assert result.connected is False
    assert result.is_success is False
    assert "timed out" in str(result.error).lower()


@pytest.mark.asyncio
async def test_tcp_probe_host_resolution_error():
    """Test TCP probe against unresolvable hostname."""
    probe = TCPProbe(default_timeout=2.0)
    result = await probe.probe(host="non-existent-domain-xyz-987654321.invalid", port=80)

    assert result.status == "ERROR"
    assert result.connected is False
    assert result.is_success is False
    assert "failed" in str(result.error).lower()


@pytest.mark.asyncio
async def test_tcp_probe_unexpected_os_error():
    """Test TCP probe handling unexpected socket OS error."""
    probe = TCPProbe(default_timeout=2.0)
    with patch("asyncio.open_connection", side_effect=OSError("Too many open files")):
        result = await probe.probe(host="127.0.0.1", port=80)
        assert result.status == "ERROR"
        assert result.connected is False
        assert "Too many open files" in str(result.error)
