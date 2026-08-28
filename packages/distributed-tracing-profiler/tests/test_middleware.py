"""Unit tests for ASGI and WSGI distributed tracing middlewares and @traced decorator."""

from __future__ import annotations

from typing import Any

import pytest
from tracing.middleware import (
    TracingASGIMiddleware,
    TracingWSGIMiddleware,
    traced,
)
from tracing.profiler import SpanProfiler
from tracing.span import SpanKind, SpanStatus, Tracer


@pytest.mark.asyncio
async def test_asgi_middleware_successful_request() -> None:
    profiler = SpanProfiler()
    sent_messages: list[dict[str, Any]] = []

    async def dummy_app(scope: dict[str, Any], receive: Any, send: Any) -> None:
        await send({
            "type": "http.response.start",
            "status": 200,
            "headers": [(b"content-type", b"application/json")],
        })
        await send({"type": "http.response.body", "body": b'{"status": "ok"}'})

    middleware = TracingASGIMiddleware(dummy_app, profiler=profiler)

    scope = {
        "type": "http",
        "method": "GET",
        "path": "/api/v1/users",
        "scheme": "https",
        "client": ("127.0.0.1", 54321),
        "headers": [
            (b"traceparent", b"00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"),
            (b"user-agent", b"pytest-client"),
            (b"authorization", b"Bearer super_secret_token"),
        ],
    }

    async def receive() -> dict[str, Any]:
        return {"type": "http.request"}

    async def send(message: dict[str, Any]) -> None:
        sent_messages.append(message)

    await middleware(scope, receive, send)

    # Verify response headers contain traceparent
    start_msg = next(m for m in sent_messages if m["type"] == "http.response.start")
    header_dict = {k.decode("latin1"): v.decode("latin1") for k, v in start_msg["headers"]}
    assert "traceparent" in header_dict
    assert header_dict["traceparent"].startswith("00-4bf92f3577b34da6a3ce929d0e0e4736-")

    # Verify span was recorded in profiler
    metrics = profiler.get_metrics("HTTP GET /api/v1/users")
    assert metrics.count == 1


@pytest.mark.asyncio
async def test_asgi_middleware_500_error() -> None:
    profiler = SpanProfiler()

    async def error_app(scope: dict[str, Any], receive: Any, send: Any) -> None:
        await send({"type": "http.response.start", "status": 500, "headers": []})
        await send({"type": "http.response.body", "body": b"Server Error"})

    middleware = TracingASGIMiddleware(error_app, profiler=profiler)

    scope = {
        "type": "http",
        "method": "POST",
        "path": "/api/v1/checkout",
        "headers": [],
    }

    async def dummy_recv() -> dict[str, Any]:
        return {"type": "http.request"}

    async def dummy_send(msg: dict[str, Any]) -> None:
        pass

    await middleware(scope, dummy_recv, dummy_send)
    slowest = profiler.get_slowest_spans(limit=1)
    assert len(slowest) == 1
    assert slowest[0]["status"]["code"] == "ERROR"


@pytest.mark.asyncio
async def test_asgi_middleware_exception_handling() -> None:
    profiler = SpanProfiler()

    async def crashing_app(scope: dict[str, Any], receive: Any, send: Any) -> None:
        raise ValueError("App crash")

    middleware = TracingASGIMiddleware(crashing_app, profiler=profiler)

    scope = {
        "type": "http",
        "method": "GET",
        "path": "/api/crash",
        "headers": [],
    }

    async def dummy_recv() -> dict[str, Any]:
        return {"type": "http.request"}

    async def dummy_send(msg: dict[str, Any]) -> None:
        pass

    with pytest.raises(ValueError, match="App crash"):
        await middleware(scope, dummy_recv, dummy_send)

    slowest = profiler.get_slowest_spans(limit=1)
    assert len(slowest) == 1
    assert slowest[0]["status"]["code"] == "ERROR"


@pytest.mark.asyncio
async def test_asgi_middleware_non_http_scope() -> None:
    called = False

    async def lifespan_app(scope: dict[str, Any], receive: Any, send: Any) -> None:
        nonlocal called
        called = True

    async def dummy_recv() -> dict[str, Any]:
        return {}

    async def dummy_send(msg: dict[str, Any]) -> None:
        pass

    middleware = TracingASGIMiddleware(lifespan_app)
    await middleware({"type": "lifespan"}, dummy_recv, dummy_send)
    assert called


def test_wsgi_middleware() -> None:
    profiler = SpanProfiler()

    def dummy_wsgi_app(environ: dict[str, Any], start_response: Any) -> list[bytes]:
        start_response("200 OK", [("Content-Type", "text/plain")])
        return [b"Hello WSGI"]

    middleware = TracingWSGIMiddleware(dummy_wsgi_app, profiler=profiler)

    environ = {
        "REQUEST_METHOD": "GET",
        "PATH_INFO": "/wsgi/test",
        "HTTP_TRACEPARENT": "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
        "HTTP_AUTHORIZATION": "Bearer token",
    }

    response_headers: list[tuple[str, str]] = []

    def start_response(status: str, headers: list[tuple[str, str]], exc_info: Any = None) -> None:
        nonlocal response_headers
        response_headers = list(headers)

    res = middleware(environ, start_response)
    assert res == [b"Hello WSGI"]

    header_dict = dict(response_headers)
    assert "traceparent" in header_dict
    assert header_dict["traceparent"].startswith("00-4bf92f3577b34da6a3ce929d0e0e4736-")
    assert profiler.get_metrics("HTTP GET /wsgi/test").count == 1


def test_traced_decorator_sync() -> None:
    ended_spans = []
    custom_tracer = Tracer(on_span_end=ended_spans.append)

    @traced(name="custom_sync_fn", kind=SpanKind.INTERNAL, tracer=custom_tracer)
    def compute(a: int, b: int) -> int:
        return a + b

    result = compute(10, 20)
    assert result == 30
    assert len(ended_spans) == 1
    assert ended_spans[0].name == "custom_sync_fn"
    assert ended_spans[0].status == SpanStatus.OK


@pytest.mark.asyncio
async def test_traced_decorator_async() -> None:
    ended_spans = []
    custom_tracer = Tracer(on_span_end=ended_spans.append)

    @traced(name="custom_async_fn", tracer=custom_tracer)
    async def fetch_data() -> str:
        return "data_async"

    result = await fetch_data()
    assert result == "data_async"
    assert len(ended_spans) == 1
    assert ended_spans[0].name == "custom_async_fn"
    assert ended_spans[0].status == SpanStatus.OK
