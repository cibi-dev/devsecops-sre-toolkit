"""Unit tests for OpenMetrics and Prometheus telemetry registry."""

import pytest

from proxy.metrics import Counter, Gauge, Histogram, MetricsRegistry, _format_labels


def test_format_labels():
    assert _format_labels({}) == ""
    assert _format_labels({"status": "200", "method": "GET"}) == '{method="GET",status="200"}'


def test_counter_metric():
    c = Counter("http_requests", "Total requests", ["method", "status"])
    assert c.get({"method": "GET", "status": "200"}) == 0.0

    c.inc(1.0, {"method": "GET", "status": "200"})
    c.inc(2.0, {"method": "GET", "status": "200"})
    assert c.get({"method": "GET", "status": "200"}) == 3.0

    with pytest.raises(ValueError):
        c.inc(-1.0)

    lines = c.export()
    assert any("# TYPE http_requests counter" in l for l in lines)
    assert any('http_requests{method="GET",status="200"} 3.0' in l for l in lines)


def test_gauge_metric():
    g = Gauge("active_connections", "Active conns", ["upstream"])
    g.set(5.0, {"upstream": "node1"})
    assert g.get({"upstream": "node1"}) == 5.0

    g.inc(2.0, {"upstream": "node1"})
    assert g.get({"upstream": "node1"}) == 7.0

    g.dec(3.0, {"upstream": "node1"})
    assert g.get({"upstream": "node1"}) == 4.0

    lines = g.export()
    assert any("# TYPE active_connections gauge" in l for l in lines)
    assert any('active_connections{upstream="node1"} 4.0' in l for l in lines)


def test_histogram_metric():
    h = Histogram("request_latency", "Latency seconds", ["route"], buckets=[0.1, 0.5, 1.0])
    h.observe(0.05, {"route": "/api"})
    h.observe(0.4, {"route": "/api"})
    h.observe(0.8, {"route": "/api"})
    h.observe(2.0, {"route": "/api"})

    lines = h.export()
    assert any("# TYPE request_latency histogram" in l for l in lines)
    assert any('request_latency_bucket{le="0.1",route="/api"} 1' in l for l in lines)
    assert any('request_latency_bucket{le="0.5",route="/api"} 2' in l for l in lines)
    assert any('request_latency_bucket{le="1.0",route="/api"} 3' in l for l in lines)
    assert any('request_latency_bucket{le="+Inf",route="/api"} 4' in l for l in lines)
    assert any('request_latency_count{route="/api"} 4' in l for l in lines)


def test_metrics_registry_export():
    reg = MetricsRegistry()
    reg.http_requests_total.inc(1.0, {"method": "GET", "status": "200", "upstream": "srv1"})
    reg.http_active_connections.set(2.0, {"upstream": "srv1"})
    reg.http_request_duration_seconds.observe(0.02, {"method": "GET", "status": "200"})

    body, media_type = reg.generate_response()
    assert "application/openmetrics-text" in media_type
    assert "# EOF" in body
    assert "proxy_http_requests_total" in body
    assert "proxy_http_active_connections" in body
    assert "proxy_http_request_duration_seconds" in body
