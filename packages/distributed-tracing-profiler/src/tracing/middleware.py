"""Async & WSGI middleware for distributed tracing across HTTP frameworks.

Provides seamless ASGI / WSGI request instrumentation conforming to W3C TraceContext.
Propagates async contextvars across coroutines and injects trace headers downstream.

DevSecOps Guardrails:
- CWE-209: Sanitizes all HTTP request headers (Authorization, Cookie, etc.)
- CWE-400: Non-blocking async interception with zero memory leakage
"""

from __future__ import annotations

import functools
import inspect
from collections.abc import Callable, Mapping
from typing import Any

from tracing.context import (
    SpanContext,
    extract_context,
    inject_context,
)
from tracing.profiler import SpanProfiler
from tracing.span import SpanKind, SpanStatus, Tracer, sanitize_attributes


class TracingASGIMiddleware:
    """Standard ASGI 3.0 middleware for distributed tracing."""

    def __init__(
        self,
        app: Any,
        tracer: Tracer | None = None,
        profiler: SpanProfiler | None = None,
        service_name: str = "http-service",
    ) -> None:
        self.app = app
        self.profiler = profiler
        self.tracer = tracer or Tracer(
            name=service_name,
            on_span_end=self.profiler.record_span if self.profiler else None,
        )

    async def __call__(
        self,
        scope: dict[str, Any],
        receive: Callable[..., Any],
        send: Callable[..., Any],
    ) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        # Extract headers and context
        raw_headers = scope.get("headers", [])
        parent_context = extract_context(raw_headers)

        method = scope.get("method", "GET").upper()
        path = scope.get("path", "/")
        span_name = f"HTTP {method} {path}"

        # Populate standard HTTP attributes
        client = scope.get("client")
        client_ip = client[0] if client and len(client) > 0 else "unknown"

        attributes: dict[str, Any] = {
            "http.method": method,
            "http.target": path,
            "http.scheme": scope.get("scheme", "http"),
            "http.client_ip": client_ip,
        }

        # Extract useful headers (sanitized)
        for h_name, h_val in raw_headers:
            decoded_name = (
                h_name.decode("latin1") if isinstance(h_name, bytes) else str(h_name)
            ).lower()
            decoded_val = (
                h_val.decode("latin1") if isinstance(h_val, bytes) else str(h_val)
            )
            if decoded_name == "user-agent":
                attributes["http.user_agent"] = decoded_val
            elif decoded_name == "host":
                attributes["http.host"] = decoded_val

        sanitized_attrs = sanitize_attributes(attributes)

        span = self.tracer.start_span(
            name=span_name,
            parent=parent_context,
            kind=SpanKind.SERVER,
            attributes=sanitized_attrs,
        )

        response_status_code: int | None = None

        async def send_wrapper(message: dict[str, Any]) -> None:
            nonlocal response_status_code
            if message.get("type") == "http.response.start":
                status = message.get("status", 200)
                response_status_code = status
                span.set_attribute("http.status_code", status)
                if status >= 500:
                    span.set_status(SpanStatus.ERROR, f"HTTP Status {status}")
                elif status < 400 and span.status == SpanStatus.UNSET:
                    span.set_status(SpanStatus.OK)

                # Inject traceparent into response headers
                headers = list(message.get("headers", []))
                carrier: dict[str, str] = {}
                inject_context(span.context, carrier)

                for k, v in carrier.items():
                    headers.append((k.encode("latin1"), v.encode("latin1")))
                message["headers"] = headers

            await send(message)

        with span:
            try:
                await self.app(scope, receive, send_wrapper)
            except BaseException as exc:
                span.record_exception(exc, escaped=True)
                raise


class TracingWSGIMiddleware:
    """Standard WSGI middleware for distributed tracing."""

    def __init__(
        self,
        app: Any,
        tracer: Tracer | None = None,
        profiler: SpanProfiler | None = None,
        service_name: str = "wsgi-service",
    ) -> None:
        self.app = app
        self.profiler = profiler
        self.tracer = tracer or Tracer(
            name=service_name,
            on_span_end=self.profiler.record_span if self.profiler else None,
        )

    def __call__(
        self,
        environ: dict[str, Any],
        start_response: Callable[..., Any],
    ) -> Any:
        headers_dict: dict[str, str] = {}
        for k, v in environ.items():
            if k == "HTTP_TRACEPARENT":
                headers_dict["traceparent"] = str(v)
            elif k == "HTTP_TRACESTATE":
                headers_dict["tracestate"] = str(v)
            elif k.startswith("HTTP_"):
                header_name = k[5:].replace("_", "-").lower()
                headers_dict[header_name] = str(v)

        parent_context = extract_context(headers_dict)
        method = environ.get("REQUEST_METHOD", "GET").upper()
        path = environ.get("PATH_INFO", "/")
        span_name = f"HTTP {method} {path}"

        attributes = sanitize_attributes({
            "http.method": method,
            "http.target": path,
            "http.client_ip": environ.get("REMOTE_ADDR", "unknown"),
        })

        span = self.tracer.start_span(
            name=span_name,
            parent=parent_context,
            kind=SpanKind.SERVER,
            attributes=attributes,
        )

        def start_response_wrapper(
            status: str, response_headers: list[tuple[str, str]], exc_info: Any = None
        ) -> Any:
            try:
                code_str = status.split(" ", 1)[0]
                code = int(code_str)
                span.set_attribute("http.status_code", code)
                if code >= 500:
                    span.set_status(SpanStatus.ERROR, status)
                elif code < 400:
                    span.set_status(SpanStatus.OK)
            except Exception:
                pass

            carrier: dict[str, str] = {}
            inject_context(span.context, carrier)
            for k, v in carrier.items():
                response_headers.append((k, v))

            return start_response(status, response_headers, exc_info)

        with span:
            try:
                return self.app(environ, start_response_wrapper)
            except BaseException as exc:
                span.record_exception(exc, escaped=True)
                raise


def traced(
    name: str | None = None,
    kind: SpanKind = SpanKind.INTERNAL,
    tracer: Tracer | None = None,
    attributes: Mapping[str, Any] | None = None,
) -> Callable[..., Any]:
    """Decorator to automatically trace synchronous or asynchronous functions."""

    def decorator(fn: Callable[..., Any]) -> Callable[..., Any]:
        span_name = name or fn.__qualname__
        active_tracer = tracer or Tracer()

        if inspect.iscoroutinefunction(fn):

            @functools.wraps(fn)
            async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
                span = active_tracer.start_span(
                    name=span_name, kind=kind, attributes=attributes
                )
                with span:
                    return await fn(*args, **kwargs)

            return async_wrapper
        else:

            @functools.wraps(fn)
            def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
                span = active_tracer.start_span(
                    name=span_name, kind=kind, attributes=attributes
                )
                with span:
                    return fn(*args, **kwargs)

            return sync_wrapper

    return decorator
