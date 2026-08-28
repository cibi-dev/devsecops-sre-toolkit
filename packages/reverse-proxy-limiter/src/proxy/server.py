"""
Enterprise Async ASGI Reverse Proxy Server.

Features:
- Async I/O HTTP/1.1 forwarding with connection pooling
- High-throughput direct ASGI 3.0 pipeline
- Concurrency limiting semaphores & explicit upstream timeouts (CWE-400)
- Immediate hard cutoff for payloads > 10MB (CWE-400)
- Canonical security header injection (HSTS, CSP, X-Frame-Options, X-Content-Type-Options)
- Sensitive credential sanitization in logs and diagnostics (CWE-209)
- Integrated Round-Robin/Least-Connections load balancing with Circuit Breaker failover
- Prometheus/OpenMetrics /metrics and /health endpoints
"""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
import json
import logging
import re
import secrets
import time
from typing import Any, AsyncGenerator, Dict, List, Optional, Set, Tuple

import httpx
from pydantic import BaseModel, Field

from proxy.balancer import BalancerStrategy, LoadBalancer, NoHealthyUpstreamError, UpstreamNode
from proxy.circuit_breaker import CircuitBreakerConfig, CircuitBreakerOpenError, CircuitState
from proxy.limiter import RateLimiterConfig, RateLimiterManager
from proxy.metrics import MetricsRegistry, metrics_registry

logger = logging.getLogger("proxy.server")

HOP_BY_HOP_HEADERS: Set[str] = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
    "host",
}

SENSITIVE_HEADER_PATTERNS = re.compile(
    r"^(authorization|x-api-key|api-key|cookie|set-cookie|token|secret)$",
    re.IGNORECASE,
)

CANONICAL_SECURITY_HEADERS: List[Tuple[bytes, bytes]] = [
    (b"strict-transport-security", b"max-age=31536000; includeSubDomains; preload"),
    (b"x-content-type-options", b"nosniff"),
    (b"x-frame-options", b"DENY"),
    (b"content-security-policy", b"default-src 'self'"),
    (b"referrer-policy", b"strict-origin-when-cross-origin"),
    (b"permissions-policy", b"geolocation=(), camera=(), microphone=()"),
    (b"x-permitted-cross-domain-policies", b"none"),
]


def sanitize_headers_for_logging(headers: Dict[str, str]) -> Dict[str, str]:
    """Redacts sensitive headers to prevent secret leaks in logs (CWE-209)."""
    sanitized = {}
    for k, v in headers.items():
        if SENSITIVE_HEADER_PATTERNS.match(k):
            sanitized[k] = "[REDACTED]"
        else:
            sanitized[k] = v
    return sanitized


class ProxyConfig(BaseModel):
    """Configuration for Enterprise Reverse Proxy Server."""
    upstreams: List[str] = Field(default_factory=lambda: ["http://127.0.0.1:8080"])
    balancer_strategy: str = Field(default="round_robin")
    rate_limit_rate: float = Field(default=100.0, gt=0.0)
    rate_limit_capacity: float = Field(default=200.0, gt=0.0)
    rate_limit_strategy: str = Field(default="token_bucket")
    circuit_failure_threshold: int = Field(default=5, ge=1)
    circuit_cooldown: float = Field(default=10.0, gt=0.0)
    max_body_size: int = Field(default=10 * 1024 * 1024, ge=1, description="Max payload size in bytes (CWE-400)")
    upstream_timeout: float = Field(default=5.0, gt=0.0, description="Upstream timeout in seconds (CWE-400)")
    max_concurrency: int = Field(default=5000, ge=1, description="Max concurrent in-flight requests (CWE-400)")
    enable_security_headers: bool = Field(default=True)
    health_check_interval: float = Field(default=10.0, ge=0.0)

    model_config = {"extra": "forbid"}


class ProxyServer:
    """Enterprise Async Reverse Proxy Application (ASGI 3.0 Compliant)."""

    def __init__(
        self,
        config: Optional[ProxyConfig] = None,
        registry: Optional[MetricsRegistry] = None,
    ) -> None:
        self.config = config or ProxyConfig()
        self.metrics = registry or metrics_registry

        # Circuit breaker settings
        self.circuit_config = CircuitBreakerConfig(
            failure_threshold=self.config.circuit_failure_threshold,
            recovery_time=self.config.circuit_cooldown,
        )

        # Load balancer
        self.balancer = LoadBalancer(
            strategy=self.config.balancer_strategy,
            circuit_config=self.circuit_config,
        )
        for url in self.config.upstreams:
            self.balancer.add_node(url)

        # Rate Limiter
        self.limiter = RateLimiterManager(
            default_rate=self.config.rate_limit_rate,
            default_capacity=self.config.rate_limit_capacity,
            strategy=self.config.rate_limit_strategy,
        )

        # Concurrency control semaphore (CWE-400)
        self.concurrency_semaphore = asyncio.Semaphore(self.config.max_concurrency)

        # HTTP client pool for upstream requests
        self._http_client: Optional[httpx.AsyncClient] = None
        self.app = self

    async def get_http_client(self) -> httpx.AsyncClient:
        """Get or initialize persistent HTTP client pool."""
        if self._http_client is None or self._http_client.is_closed:
            limits = httpx.Limits(
                max_connections=self.config.max_concurrency,
                max_keepalive_connections=1000,
                keepalive_expiry=60.0,
            )
            self._http_client = httpx.AsyncClient(
                limits=limits,
                timeout=httpx.Timeout(self.config.upstream_timeout),
                follow_redirects=False,
            )
        return self._http_client

    async def startup(self) -> None:
        """Initialize server dependencies."""
        await self.get_http_client()
        if self.config.health_check_interval > 0:
            self.balancer.start_background_health_checks(interval=self.config.health_check_interval)

    async def shutdown(self) -> None:
        """Gracefully release resources."""
        self.balancer.stop_background_health_checks()
        if self._http_client is not None and not self._http_client.is_closed:
            await self._http_client.aclose()
            self._http_client = None

    def _build_response_headers(
        self,
        base_headers: Optional[List[Tuple[bytes, bytes]]] = None,
        content_type: bytes = b"application/json",
        extra_headers: Optional[Dict[str, str]] = None,
    ) -> List[Tuple[bytes, bytes]]:
        """Construct raw ASGI response headers with injected security headers."""
        headers: List[Tuple[bytes, bytes]] = list(base_headers or [])
        if content_type and not any(k.lower() == b"content-type" for k, _ in headers):
            headers.append((b"content-type", content_type))

        if self.config.enable_security_headers:
            existing = {k.lower() for k, _ in headers}
            for k, v in CANONICAL_SECURITY_HEADERS:
                if k not in existing:
                    headers.append((k, v))

        if extra_headers:
            for k_str, v_str in extra_headers.items():
                headers.append((k_str.lower().encode("latin-1"), v_str.encode("latin-1")))

        return headers

    async def _send_json_response(
        self,
        send: Any,
        status: int,
        payload: Dict[str, Any],
        extra_headers: Optional[Dict[str, str]] = None,
    ) -> None:
        """Send JSON response conforming to ASGI 3.0."""
        body = json.dumps(payload).encode("utf-8")
        headers = self._build_response_headers(
            base_headers=[(b"content-length", str(len(body)).encode("ascii"))],
            content_type=b"application/json",
            extra_headers=extra_headers,
        )
        await send({"type": "http.response.start", "status": status, "headers": headers})
        await send({"type": "http.response.body", "body": body})

    async def handle_health_asgi(self, scope: Any, receive: Any, send: Any) -> None:
        """Proxy health check endpoint with upstream status."""
        nodes_status = [node.to_dict() for node in self.balancer.nodes]
        healthy_count = len(self.balancer.get_healthy_nodes())
        is_healthy = healthy_count > 0 or len(self.balancer.nodes) == 0

        status_code = 200 if is_healthy else 503
        data = {
            "status": "healthy" if is_healthy else "degraded",
            "healthy_nodes": healthy_count,
            "total_nodes": len(self.balancer.nodes),
            "upstreams": nodes_status,
        }
        await self._send_json_response(send, status_code, data)

    async def handle_metrics_asgi(self, scope: Any, receive: Any, send: Any) -> None:
        """Prometheus / OpenMetrics compliant telemetry endpoint."""
        for node in self.balancer.nodes:
            self.metrics.upstream_health_status.set(
                1.0 if node.is_available() else 0.0,
                labels={"upstream": node.url},
            )
            cb_val = 0.0
            if node.circuit_breaker.current_state == CircuitState.HALF_OPEN:
                cb_val = 1.0
            elif node.circuit_breaker.current_state == CircuitState.OPEN:
                cb_val = 2.0
            self.metrics.circuit_breaker_state.set(
                cb_val,
                labels={"upstream": node.url, "state": node.circuit_breaker.current_state.value},
            )

        body_str, content_type = self.metrics.generate_response()
        body_bytes = body_str.encode("utf-8")
        headers = self._build_response_headers(
            base_headers=[(b"content-length", str(len(body_bytes)).encode("ascii"))],
            content_type=content_type.encode("latin-1"),
        )
        await send({"type": "http.response.start", "status": 200, "headers": headers})
        await send({"type": "http.response.body", "body": body_bytes})

    async def handle_proxy_asgi(self, scope: Any, receive: Any, send: Any) -> None:
        """High-Performance Reverse Proxy Core Dispatcher."""
        start_time = time.monotonic()
        method = scope.get("method", "GET")
        raw_headers = scope.get("headers", [])
        headers_dict = {
            k.decode("latin-1").lower(): v.decode("latin-1") for k, v in raw_headers
        }
        client_tuple = scope.get("client")
        client_host = client_tuple[0] if client_tuple else "127.0.0.1"

        # 1. Concurrency Limiter (CWE-400)
        try:
            if self.concurrency_semaphore.locked() and self.concurrency_semaphore._value <= 0:
                await self._send_json_response(
                    send, 503, {"error": "Too Many Concurrent Requests", "code": 503}
                )
                return
        except Exception:
            pass

        async with self.concurrency_semaphore:
            # 2. Hard Content-Length check (CWE-400: DoS via large payload)
            content_length_str = headers_dict.get("content-length")
            if content_length_str:
                try:
                    content_length = int(content_length_str)
                    if content_length > self.config.max_body_size:
                        await self._send_json_response(
                            send,
                            413,
                            {
                                "error": f"Payload Too Large. Max allowed is {self.config.max_body_size} bytes",
                                "code": 413,
                            },
                        )
                        return
                except ValueError:
                    pass

            # 3. Rate Limiter Check (Token Bucket / Sliding Window)
            rate_result = self.limiter.check(headers_dict, client_host)
            if not rate_result.allowed:
                self.metrics.rate_limit_exceeded_total.inc(labels={"key_type": rate_result.key_type})
                await self._send_json_response(
                    send,
                    429,
                    {
                        "error": "Too Many Requests",
                        "code": 429,
                        "retry_after": round(rate_result.retry_after, 2),
                    },
                    extra_headers=rate_result.headers,
                )
                return

            # 4. Load Balancer Node Selection & Circuit Breaker Check
            try:
                node = self.balancer.select_node(client_key=rate_result.key)
            except NoHealthyUpstreamError:
                self.metrics.http_requests_total.inc(
                    labels={"method": method, "status": "503", "upstream": "none"}
                )
                await self._send_json_response(
                    send,
                    503,
                    {"error": "Service Unavailable: No healthy upstream nodes", "code": 503},
                )
                return

            try:
                node.circuit_breaker.allow_request()
            except CircuitBreakerOpenError as cb_err:
                self.metrics.http_requests_total.inc(
                    labels={"method": method, "status": "503", "upstream": node.url}
                )
                await self._send_json_response(
                    send,
                    503,
                    {
                        "error": "Service Unavailable: Upstream circuit breaker is OPEN",
                        "code": 503,
                        "retry_after": round(cb_err.retry_after, 2),
                    },
                    extra_headers={"Retry-After": str(max(1, int(cb_err.retry_after)))},
                )
                return

            # 5. Read Request Body with hard byte limit (CWE-400)
            body_chunks = []
            total_bytes = 0
            while True:
                message = await receive()
                chunk = message.get("body", b"")
                if chunk:
                    total_bytes += len(chunk)
                    if total_bytes > self.config.max_body_size:
                        await self._send_json_response(
                            send,
                            413,
                            {
                                "error": f"Payload Too Large. Max allowed is {self.config.max_body_size} bytes",
                                "code": 413,
                            },
                        )
                        return
                    body_chunks.append(chunk)
                if not message.get("more_body", False):
                    break

            req_body = b"".join(body_chunks)
            if req_body:
                self.metrics.payload_bytes_total.inc(len(req_body), labels={"direction": "request"})

            # 6. Prepare Forwarded Headers (filter hop-by-hop)
            forward_headers = {
                k: v for k, v in headers_dict.items() if k not in HOP_BY_HOP_HEADERS
            }
            prior_xff = forward_headers.get("x-forwarded-for")
            forward_headers["x-forwarded-for"] = (
                f"{prior_xff}, {client_host}" if prior_xff else client_host
            )
            forward_headers["x-forwarded-proto"] = scope.get("scheme", "http")
            forward_headers["x-forwarded-host"] = headers_dict.get("host", "localhost")
            if "x-request-id" not in forward_headers:
                forward_headers["x-request-id"] = secrets.token_hex(16)

            # Target URL
            path = scope.get("path", "/")
            qs = scope.get("query_string", b"").decode("latin-1")
            target_url = f"{node.url}{path}?{qs}" if qs else f"{node.url}{path}"

            # 7. Forward Request to Upstream
            client = await self.get_http_client()
            status_code = 500
            self.metrics.http_active_connections.inc(labels={"upstream": node.url})
            node.active_connections += 1

            try:
                async with asyncio.timeout(self.config.upstream_timeout):
                    upstream_resp = await client.request(
                        method=method,
                        url=target_url,
                        headers=forward_headers,
                        content=req_body,
                    )

                elapsed_seconds = time.monotonic() - start_time
                status_code = upstream_resp.status_code

                if status_code < 500:
                    node.record_success(elapsed_seconds * 1000.0)
                else:
                    node.record_failure()

                # Response headers
                out_headers = [
                    (k.encode("latin-1"), v.encode("latin-1"))
                    for k, v in upstream_resp.headers.items()
                    if k.lower() not in HOP_BY_HOP_HEADERS
                ]
                final_headers = self._build_response_headers(
                    base_headers=out_headers,
                    content_type=b"",
                    extra_headers=rate_result.headers,
                )

                content_bytes = upstream_resp.content
                if content_bytes:
                    self.metrics.payload_bytes_total.inc(
                        len(content_bytes), labels={"direction": "response"}
                    )

                await send({"type": "http.response.start", "status": status_code, "headers": final_headers})
                await send({"type": "http.response.body", "body": content_bytes})

            except (asyncio.TimeoutError, httpx.TimeoutException):
                node.record_failure()
                status_code = 504
                await self._send_json_response(
                    send,
                    504,
                    {
                        "error": "Gateway Timeout",
                        "code": 504,
                        "upstream": node.url,
                        "timeout_seconds": self.config.upstream_timeout,
                    },
                )

            except (httpx.ConnectError, httpx.NetworkError, httpx.RequestError) as net_err:
                node.record_failure(net_err)
                status_code = 502
                await self._send_json_response(
                    send,
                    502,
                    {
                        "error": "Bad Gateway: Upstream connection failed",
                        "code": 502,
                        "upstream": node.url,
                    },
                )

            except Exception as unhandled_err:
                node.record_failure(unhandled_err)
                status_code = 500
                logger.error("Unhandled proxy exception: %s", type(unhandled_err).__name__)
                await self._send_json_response(
                    send,
                    500,
                    {"error": "Internal Server Error", "code": 500},
                )

            finally:
                node.active_connections = max(0, node.active_connections - 1)
                self.metrics.http_active_connections.dec(labels={"upstream": node.url})
                elapsed = time.monotonic() - start_time
                self.metrics.http_requests_total.inc(
                    labels={"method": method, "status": str(status_code), "upstream": node.url}
                )
                self.metrics.http_request_duration_seconds.observe(
                    elapsed, labels={"method": method, "status": str(status_code)}
                )

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        """ASGI 3.0 standard interface entrypoint."""
        scope_type = scope.get("type")

        if scope_type == "http":
            path = scope.get("path", "")
            if path in ("/health", "/healthz"):
                await self.handle_health_asgi(scope, receive, send)
            elif path == "/metrics":
                await self.handle_metrics_asgi(scope, receive, send)
            else:
                await self.handle_proxy_asgi(scope, receive, send)

        elif scope_type == "lifespan":
            while True:
                message = await receive()
                msg_type = message.get("type")
                if msg_type == "lifespan.startup":
                    try:
                        await self.startup()
                        await send({"type": "lifespan.startup.complete"})
                    except Exception as err:
                        await send({"type": "lifespan.startup.failed", "message": str(err)})
                elif msg_type == "lifespan.shutdown":
                    try:
                        await self.shutdown()
                        await send({"type": "lifespan.shutdown.complete"})
                    except Exception as err:
                        await send({"type": "lifespan.shutdown.failed", "message": str(err)})
                    break
