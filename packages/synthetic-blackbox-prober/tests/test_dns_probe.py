"""Tests for DNS resolution synthetic probe."""

import asyncio
import socket
from unittest.mock import MagicMock, patch
import pytest
from prober.probes.dns import DNSProbe, DNSProbeResult


@pytest.mark.asyncio
async def test_dns_probe_localhost():
    """Test DNS probe resolving localhost."""
    probe = DNSProbe(default_timeout=5.0)
    result = await probe.probe(target="localhost", record_type="A")

    assert result.status == "SUCCESS"
    assert result.is_success is True
    assert len(result.resolved_records) > 0
    assert "127.0.0.1" in result.resolved_records
    assert result.latency_ms > 0


@pytest.mark.asyncio
async def test_dns_probe_cname_mock():
    """Test DNS probe querying CNAME with mock addrinfo."""
    loop = asyncio.get_running_loop()
    mock_addrinfo = [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "canonical.example.com", ("93.184.216.34", 0))
    ]
    with patch.object(loop, "getaddrinfo", return_value=mock_addrinfo):
        probe = DNSProbe()
        result = await probe.probe(target="alias.example.com", record_type="CNAME")

        assert result.status == "SUCCESS"
        assert result.canonical_name == "canonical.example.com"
        assert "93.184.216.34" in result.resolved_records


@pytest.mark.asyncio
async def test_dns_probe_nxdomain():
    """Test DNS probe returning NXDOMAIN on gaierror."""
    loop = asyncio.get_running_loop()
    with patch.object(loop, "getaddrinfo", side_effect=socket.gaierror(-2, "Name or service not known")):
        probe = DNSProbe()
        result = await probe.probe(target="non-existent-xyz-987.invalid", record_type="A")

        assert result.status == "NXDOMAIN"
        assert result.is_success is False
        assert len(result.resolved_records) == 0


@pytest.mark.asyncio
async def test_dns_probe_empty_records():
    """Test DNS probe handling empty records."""
    loop = asyncio.get_running_loop()
    with patch.object(loop, "getaddrinfo", return_value=[]):
        probe = DNSProbe()
        result = await probe.probe(target="empty.example.com", record_type="A")

        assert result.status == "NXDOMAIN"
        assert result.is_success is False


@pytest.mark.asyncio
async def test_dns_probe_timeout():
    """Test DNS probe timeout handling."""
    probe = DNSProbe(default_timeout=0.1)
    loop = asyncio.get_running_loop()
    
    async def _mock_slow_dns(*args, **kwargs):
        await asyncio.sleep(0.5)
        return []

    with patch.object(loop, "getaddrinfo", side_effect=_mock_slow_dns):
        result = await probe.probe(target="slow.example.com", record_type="A", timeout=0.1)
        assert result.status == "TIMEOUT"
        assert result.is_success is False
        assert "timed out" in str(result.error).lower()


@pytest.mark.asyncio
async def test_dns_probe_unexpected_error():
    """Test DNS probe handling unexpected runtime exception."""
    loop = asyncio.get_running_loop()
    with patch.object(loop, "getaddrinfo", side_effect=RuntimeError("System DNS daemon down")):
        probe = DNSProbe()
        result = await probe.probe(target="test.example.com", record_type="A")

        assert result.status == "ERROR"
        assert result.is_success is False
        assert "System DNS daemon down" in str(result.error)
