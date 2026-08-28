"""Tests for Asynchronous Probe Scheduler and Concurrency Limiting."""

import asyncio
from unittest.mock import AsyncMock, patch
import pytest
from prober.probes.dns import DNSProbeResult
from prober.probes.http import HTTPProbeResult
from prober.probes.ssl_cert import SSLCertProbeResult
from prober.probes.tcp import TCPProbeResult
from prober.scheduler import ProbeScheduler, ProbeTarget


@pytest.mark.asyncio
async def test_scheduler_execute_targets():
    """Test scheduler delegating to respective probers."""
    scheduler = ProbeScheduler(concurrency_limit=10, default_timeout=5.0)

    # Mock all probers
    scheduler.http_prober.probe = AsyncMock(
        return_value=HTTPProbeResult(url="https://example.com", target_host="example.com", status_code=200, status="SUCCESS")
    )
    scheduler.tcp_prober.probe = AsyncMock(
        return_value=TCPProbeResult(host="127.0.0.1", port=80, connected=True, status="SUCCESS")
    )
    scheduler.ssl_prober.probe = AsyncMock(
        return_value=SSLCertProbeResult(host="example.com", port=443, valid=True, status="SUCCESS")
    )
    scheduler.dns_prober.probe = AsyncMock(
        return_value=DNSProbeResult(target="example.com", record_type="A", resolved_records=["93.184.216.34"], status="SUCCESS")
    )

    t_http = ProbeTarget(name="http_target", probe_type="http", target="https://example.com")
    t_tcp = ProbeTarget(name="tcp_target", probe_type="tcp", target="127.0.0.1", port=80)
    t_ssl = ProbeTarget(name="ssl_target", probe_type="ssl", target="example.com", port=443)
    t_dns = ProbeTarget(name="dns_target", probe_type="dns", target="example.com", record_type="A")

    res_http = await scheduler.execute_target(t_http)
    res_tcp = await scheduler.execute_target(t_tcp)
    res_ssl = await scheduler.execute_target(t_ssl)
    res_dns = await scheduler.execute_target(t_dns)

    assert isinstance(res_http, HTTPProbeResult) and res_http.status == "SUCCESS"
    assert isinstance(res_tcp, TCPProbeResult) and res_tcp.status == "SUCCESS"
    assert isinstance(res_ssl, SSLCertProbeResult) and res_ssl.status == "SUCCESS"
    assert isinstance(res_dns, DNSProbeResult) and res_dns.status == "SUCCESS"


@pytest.mark.asyncio
async def test_scheduler_unknown_probe_type():
    """Test scheduler handling unrecognized probe type."""
    scheduler = ProbeScheduler()
    target = ProbeTarget(name="unknown", probe_type="ftp", target="ftp.example.com")
    result = await scheduler.execute_target(target)

    assert result.status == "ERROR"
    assert "Unknown probe_type" in str(result.error)


@pytest.mark.asyncio
async def test_scheduler_concurrency_limiting():
    """Verify that concurrency is bounded by semaphore (CWE-400)."""
    max_concurrency = 3
    scheduler = ProbeScheduler(concurrency_limit=max_concurrency, default_timeout=5.0)

    active_concurrent = 0
    max_observed_concurrent = 0

    async def _mock_slow_probe(*args, **kwargs):
        nonlocal active_concurrent, max_observed_concurrent
        active_concurrent += 1
        max_observed_concurrent = max(max_observed_concurrent, active_concurrent)
        await asyncio.sleep(0.05)
        active_concurrent -= 1
        return HTTPProbeResult(url="https://test.local", target_host="test.local", status_code=200)

    scheduler.http_prober.probe = _mock_slow_probe

    targets = [
        ProbeTarget(name=f"tgt_{i}", probe_type="http", target=f"https://test{i}.local")
        for i in range(12)
    ]

    results = await scheduler.run_batch(targets)

    assert len(results) == 12
    assert max_observed_concurrent <= max_concurrency


@pytest.mark.asyncio
async def test_scheduler_loop_with_callback():
    """Test periodic loop triggering callback and stopping cleanly."""
    scheduler = ProbeScheduler()
    scheduler.http_prober.probe = AsyncMock(
        return_value=HTTPProbeResult(url="https://loop.test", target_host="loop.test", status_code=200)
    )

    targets = [ProbeTarget(name="loop_t1", probe_type="http", target="https://loop.test", interval_seconds=0.05)]
    received_results = []

    def _callback(target, result):
        received_results.append((target.name, result.status))

    # Run for 2 iterations
    await scheduler.run_loop(targets=targets, callback=_callback, max_iterations=2)

    assert len(received_results) >= 1
    scheduler.stop()
    assert scheduler._running is False
