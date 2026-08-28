"""Unit and integration tests for async Reverse Proxy server."""

import asyncio
import json
import secrets
import pytest
import httpx
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.testclient import TestClient

from proxy.circuit_breaker import CircuitBreakerConfig
from proxy.metrics import MetricsRegistry
from proxy.server import ProxyConfig, ProxyServer, sanitize_headers_for_logging


def test_sanitize_headers_for_logging():
    raw = {
        "host": "localhost",
        "authorization": f"Bearer mock_{secrets.token_hex(8)}",
        "x-api-key": f"mock_key_{secrets.token_hex(8)}",
        "content-type": "application/json",
        "cookie": f"session_id={secrets.token_hex(8)}",
    }
    sanitized = sanitize_headers_for_logging(raw)
    assert sanitized["host"] == "localhost"
    assert sanitized["content-type"] == "application/json"
    assert sanitized["authorization"] == "[REDACTED]"
    assert sanitized["x-api-key"] == "[REDACTED]"
    assert sanitized["cookie"] == "[REDACTED]"


@pytest.mark.asyncio
async def test_health_endpoints():
    cfg = ProxyConfig(upstreams=["http://10.0.0.1:8080"])
    proxy = ProxyServer(cfg)

    # Test via TestClient
    with TestClient(proxy.app) as client:
        resp = client.get("/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "healthy"
        assert data["healthy_nodes"] == 1
        assert "Strict-Transport-Security" in resp.headers
        assert "Content-Security-Policy" in resp.headers

        resp_z = client.get("/healthz")
        assert resp_z.status_code == 200


@pytest.mark.asyncio
async def test_metrics_endpoint():
    cfg = ProxyConfig(upstreams=["http://10.0.0.1:8080"])
    proxy = ProxyServer(cfg)

    with TestClient(proxy.app) as client:
        resp = client.get("/metrics")
        assert resp.status_code == 200
        assert "proxy_http_requests_total" in resp.text
        assert "proxy_upstream_health_status" in resp.text
        assert "Strict-Transport-Security" in resp.headers


@pytest.mark.asyncio
async def test_security_headers_injected():
    cfg = ProxyConfig(enable_security_headers=True)
    proxy = ProxyServer(cfg)

    with TestClient(proxy.app) as client:
        resp = client.get("/health")
        assert resp.headers["Strict-Transport-Security"] == "max-age=31536000; includeSubDomains; preload"
        assert resp.headers["X-Content-Type-Options"] == "nosniff"
        assert resp.headers["X-Frame-Options"] == "DENY"
        assert resp.headers["Content-Security-Policy"] == "default-src 'self'"
        assert resp.headers["Referrer-Policy"] == "strict-origin-when-cross-origin"


@pytest.mark.asyncio
async def test_rate_limiting_429():
    cfg = ProxyConfig(
        upstreams=["http://10.0.0.1:8080"],
        rate_limit_rate=1.0,
        rate_limit_capacity=1.0,
    )
    proxy = ProxyServer(cfg)

    # Mock HTTP client
    mock_transport = httpx.MockTransport(lambda req: httpx.Response(200, json={"ok": True}))
    proxy._http_client = httpx.AsyncClient(transport=mock_transport)

    with TestClient(proxy.app) as client:
        # First request allowed
        r1 = client.get("/api/data")
        assert r1.status_code == 200
        assert "X-RateLimit-Limit" in r1.headers

        # Second request rejected with 429
        r2 = client.get("/api/data")
        assert r2.status_code == 429
        assert "Retry-After" in r2.headers
        assert r2.json()["error"] == "Too Many Requests"


@pytest.mark.asyncio
async def test_payload_too_large_413_header():
    cfg = ProxyConfig(max_body_size=1024)
    proxy = ProxyServer(cfg)

    with TestClient(proxy.app) as client:
        large_headers = {"Content-Length": "2048"}
        resp = client.post("/upload", headers=large_headers, content=b"x" * 10)
        assert resp.status_code == 413
        assert "Payload Too Large" in resp.json()["error"]


@pytest.mark.asyncio
async def test_payload_too_large_413_stream():
    cfg = ProxyConfig(max_body_size=100)
    proxy = ProxyServer(cfg)

    with TestClient(proxy.app) as client:
        resp = client.post("/upload", content=b"a" * 200)
        assert resp.status_code == 413
        assert "Payload Too Large" in resp.json()["error"]


@pytest.mark.asyncio
async def test_upstream_proxy_success_and_headers():
    cfg = ProxyConfig(upstreams=["http://upstream-srv:8080"])
    proxy = ProxyServer(cfg)

    def handler(req: httpx.Request) -> httpx.Response:
        assert req.headers["x-forwarded-proto"] == "http"
        assert "x-request-id" in req.headers
        return httpx.Response(200, json={"result": "ok", "path": str(req.url)})

    proxy._http_client = httpx.AsyncClient(transport=httpx.MockTransport(handler))

    with TestClient(proxy.app) as client:
        resp = client.get("/api/v1/resource?query=test")
        assert resp.status_code == 200
        assert resp.json()["result"] == "ok"


@pytest.mark.asyncio
async def test_upstream_timeout_504():
    cfg = ProxyConfig(upstreams=["http://slow-upstream:8080"], upstream_timeout=0.05)
    proxy = ProxyServer(cfg)

    async def slow_handler(req: httpx.Request) -> httpx.Response:
        await asyncio.sleep(0.2)
        return httpx.Response(200, json={"ok": True})

    proxy._http_client = httpx.AsyncClient(transport=httpx.MockTransport(slow_handler))

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=proxy.app), base_url="http://test") as ac:
        resp = await ac.get("/slow-endpoint")
        assert resp.status_code == 504
        assert resp.json()["error"] == "Gateway Timeout"


@pytest.mark.asyncio
async def test_upstream_connect_error_502():
    cfg = ProxyConfig(upstreams=["http://dead-upstream:8080"])
    proxy = ProxyServer(cfg)

    def broken_handler(req: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("Connection refused")

    proxy._http_client = httpx.AsyncClient(transport=httpx.MockTransport(broken_handler))

    with TestClient(proxy.app) as client:
        resp = client.get("/dead-endpoint")
        assert resp.status_code == 502
        assert "Bad Gateway" in resp.json()["error"]


@pytest.mark.asyncio
async def test_no_healthy_upstream_503():
    cfg = ProxyConfig(upstreams=[])
    proxy = ProxyServer(cfg)

    with TestClient(proxy.app) as client:
        resp = client.get("/any-endpoint")
        assert resp.status_code == 503
        assert "No healthy upstream nodes" in resp.json()["error"]


@pytest.mark.asyncio
async def test_circuit_breaker_open_503():
    cfg = ProxyConfig(upstreams=["http://failing-upstream:8080"])
    proxy = ProxyServer(cfg)
    node = proxy.balancer.nodes[0]
    node.circuit_breaker.trip()

    with TestClient(proxy.app) as client:
        resp = client.get("/test-cb")
        assert resp.status_code == 503
        assert "circuit breaker is OPEN" in resp.json()["error"]
        assert "Retry-After" in resp.headers


@pytest.mark.asyncio
async def test_server_lifespan_startup_shutdown():
    cfg = ProxyConfig(health_check_interval=0.1)
    proxy = ProxyServer(cfg)

    await proxy.startup()
    assert proxy._http_client is not None
    await proxy.shutdown()
    assert proxy._http_client is None
