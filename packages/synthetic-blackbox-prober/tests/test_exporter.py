"""Tests for Prometheus and OpenMetrics exporter module."""

import asyncio
from datetime import datetime, timezone
import httpx
import pytest
from prober.exporter import MetricsCollector, MetricsServer, format_labels
from prober.probes.dns import DNSProbeResult
from prober.probes.http import HTTPProbeResult
from prober.probes.ssl_cert import SSLCertProbeResult
from prober.probes.tcp import TCPProbeResult


def test_format_labels():
    """Test Prometheus label formatting."""
    assert format_labels({}) == ""
    assert format_labels({"target": "example.com", "probe_type": "http"}) == '{probe_type="http",target="example.com"}'


@pytest.mark.asyncio
async def test_metrics_collector_openmetrics_output():
    """Verify standard OpenMetrics formatting for HTTP, TCP, SSL and DNS results."""
    collector = MetricsCollector()

    http_res = HTTPProbeResult(
        url="https://api.example.com/v1",
        target_host="api.example.com",
        status_code=200,
        dns_latency_ms=1.5,
        tcp_latency_ms=10.2,
        tls_latency_ms=15.3,
        ttfb_ms=25.0,
        content_transfer_ms=5.0,
        total_latency_ms=57.0,
        status="SUCCESS",
    )
    await collector.record_result("api_http", http_res)

    tcp_res = TCPProbeResult(
        host="db.example.internal",
        port=5432,
        connected=True,
        latency_ms=4.2,
        status="SUCCESS",
    )
    await collector.record_result("db_tcp", tcp_res)

    ssl_res = SSLCertProbeResult(
        host="api.example.com",
        port=443,
        valid=True,
        not_after=datetime(2026, 12, 31, 23, 59, 59, tzinfo=timezone.utc),
        days_until_expiration=120.5,
        alert_level="OK",
        handshake_latency_ms=12.5,
        status="SUCCESS",
    )
    await collector.record_result("api_ssl", ssl_res)

    dns_res = DNSProbeResult(
        target="auth.example.com",
        record_type="A",
        resolved_records=["1.1.1.1"],
        latency_ms=2.1,
        status="SUCCESS",
    )
    await collector.record_result("auth_dns", dns_res)

    output = collector.generate_openmetrics()

    assert "# HELP probe_success" in output
    assert "# TYPE probe_success gauge" in output
    assert 'probe_success{probe_type="http",target="https://api.example.com/v1"} 1' in output
    assert 'probe_duration_seconds{phase="dns",target="https://api.example.com/v1"} 0.001500' in output
    assert 'probe_duration_seconds{phase="ttfb",target="https://api.example.com/v1"} 0.025000' in output
    assert 'probe_http_status_code{target="https://api.example.com/v1"} 200' in output
    assert 'probe_tcp_connect_time_seconds{port="5432",target="db.example.internal"} 0.004200' in output
    assert 'probe_ssl_days_remaining{target="api.example.com"} 120.50' in output
    assert 'probe_ssl_alert_level_state{level="OK",target="api.example.com"} 1' in output
    assert 'probe_dns_lookup_time_seconds{record_type="A",target="auth.example.com"} 0.002100' in output
    assert "# EOF" in output


@pytest.mark.asyncio
async def test_metrics_server_endpoints():
    """Test HTTP metrics server responding to /metrics, /healthz and 404."""
    collector = MetricsCollector()
    await collector.record_result(
        "t1",
        HTTPProbeResult(url="https://health.local", target_host="health.local", status_code=200),
    )

    server = MetricsServer(collector=collector, host="127.0.0.1", port=0)
    await server.start()
    port = server._server.sockets[0].getsockname()[1]

    async with httpx.AsyncClient(base_url=f"http://127.0.0.1:{port}") as client:
        # /metrics
        resp_m = await client.get("/metrics")
        assert resp_m.status_code == 200
        assert "probe_success" in resp_m.text
        assert "application/openmetrics-text" in resp_m.headers.get("content-type", "")

        # /healthz
        resp_h = await client.get("/healthz")
        assert resp_h.status_code == 200
        assert resp_h.json() == {"status": "ok"}

        # 404
        resp_404 = await client.get("/invalid-path")
        assert resp_404.status_code == 404

    await server.stop()
