"""Span model, lifecycle management, and sanitization.

Implements high-resolution microsecond timing, parent/child hierarchy,
event logging, and strict attribute sanitization.

DevSecOps Guardrails:
- CWE-209: Sensitive attribute redaction ([REDACTED]) for auth tokens, passwords, and PII.
- CWE-400: Hard limits on span attributes (<=128) and events (<=128) to prevent memory saturation.
"""

from __future__ import annotations

import contextvars
import enum
import re
import time
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass, field
from types import TracebackType
from typing import TYPE_CHECKING, Any

from tracing.context import (
    SpanContext,
    detach_span,
    get_current_span,
    set_current_span,
)

if TYPE_CHECKING:
    from tracing.sampler import Sampler

# Security Limits (CWE-400)
MAX_SPAN_ATTRIBUTES = 128
MAX_SPAN_EVENTS = 128
MAX_STRING_LENGTH = 4096

# Sensitive Key Patterns (CWE-209)
SENSITIVE_KEYS = {
    "authorization",
    "auth",
    "token",
    "access_token",
    "refresh_token",
    "id_token",
    "secret",
    "password",
    "passwd",
    "api_key",
    "apikey",
    "x-api-key",
    "private_key",
    "cookie",
    "set-cookie",
    "bearer",
    "credit_card",
    "card_number",
    "cvv",
    "ssn",
}

SENSITIVE_VALUE_REGEX = re.compile(
    r"(?i)(?:bearer\s+[a-zA-Z0-9_\-\.=]+|ghp_[a-zA-Z0-9]{20,}|eyJ[a-zA-Z0-9_\-]+\.eyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+)"
)


def is_sensitive_key(key: str) -> bool:
    """Check whether a key name indicates sensitive credential or PII data."""
    clean_key = key.strip().lower().replace("-", "_").replace(".", "_")
    return clean_key in SENSITIVE_KEYS or any(
        sub in clean_key for sub in ("token", "secret", "password", "apikey", "auth")
    )


def sanitize_value(key: str, value: Any) -> Any:
    """Sanitize attribute value, replacing secrets or PII with [REDACTED]."""
    if is_sensitive_key(key):
        return "[REDACTED]"

    if isinstance(value, str):
        if len(value) > MAX_STRING_LENGTH:
            value = value[:MAX_STRING_LENGTH] + "...[TRUNCATED]"
        if SENSITIVE_VALUE_REGEX.search(value):
            return SENSITIVE_VALUE_REGEX.sub("[REDACTED]", value)
        return value

    if isinstance(value, Mapping):
        return {
            k: sanitize_value(str(k), v)
            for i, (k, v) in enumerate(value.items())
            if i < MAX_SPAN_ATTRIBUTES
        }

    if isinstance(value, (list, tuple, set)):
        return [
            sanitize_value(key, item)
            for i, item in enumerate(value)
            if i < MAX_SPAN_ATTRIBUTES
        ]

    return value


def sanitize_attributes(attributes: Mapping[str, Any]) -> dict[str, Any]:
    """Sanitize an entire dictionary of attributes."""
    sanitized: dict[str, Any] = {}
    for i, (k, v) in enumerate(attributes.items()):
        if i >= MAX_SPAN_ATTRIBUTES:
            break
        k_str = str(k)
        sanitized[k_str] = sanitize_value(k_str, v)
    return sanitized


class SpanKind(enum.Enum):
    """Span kinds aligning with OpenTelemetry specifications."""

    INTERNAL = "INTERNAL"
    SERVER = "SERVER"
    CLIENT = "CLIENT"
    PRODUCER = "PRODUCER"
    CONSUMER = "CONSUMER"


class SpanStatus(enum.Enum):
    """Span execution status."""

    UNSET = "UNSET"
    OK = "OK"
    ERROR = "ERROR"


@dataclass(slots=True)
class SpanEvent:
    """Timestamped event attached to a span."""

    name: str
    timestamp_ns: int
    attributes: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "timestamp_ns": self.timestamp_ns,
            "attributes": self.attributes,
        }


class Span:
    """Represents a single timed operation within a distributed trace."""

    __slots__ = (
        "name",
        "context",
        "parent_span_id",
        "kind",
        "start_time_ns",
        "start_time_perf_ns",
        "end_time_ns",
        "end_time_perf_ns",
        "status",
        "status_message",
        "attributes",
        "events",
        "_on_end_callbacks",
        "_context_token",
    )

    def __init__(
        self,
        name: str,
        context: SpanContext,
        parent_span_id: str | None = None,
        kind: SpanKind = SpanKind.INTERNAL,
        attributes: Mapping[str, Any] | None = None,
        start_time_ns: int | None = None,
        on_end_callbacks: list[Callable[[Span], None]] | None = None,
    ) -> None:
        self.name = name
        self.context = context
        self.parent_span_id = parent_span_id
        self.kind = kind
        self.start_time_ns = start_time_ns or time.time_ns()
        self.start_time_perf_ns = time.perf_counter_ns()
        self.end_time_ns: int | None = None
        self.end_time_perf_ns: int | None = None
        self.status = SpanStatus.UNSET
        self.status_message: str | None = None
        self.attributes: dict[str, Any] = (
            sanitize_attributes(attributes) if attributes else {}
        )
        self.events: list[SpanEvent] = []
        self._on_end_callbacks: list[Callable[[Span], None]] = (
            list(on_end_callbacks) if on_end_callbacks else []
        )
        self._context_token: contextvars.Token[Span | None] | None = None

    @property
    def trace_id(self) -> str:
        return self.context.trace_id

    @property
    def span_id(self) -> str:
        return self.context.span_id

    @property
    def is_sampled(self) -> bool:
        return self.context.is_sampled

    @property
    def is_ended(self) -> bool:
        return self.end_time_ns is not None

    @property
    def duration_ns(self) -> int | None:
        """Calculate duration in nanoseconds using high-resolution perf_counter."""
        if self.end_time_perf_ns is None:
            return None
        return max(0, self.end_time_perf_ns - self.start_time_perf_ns)

    @property
    def duration_us(self) -> float | None:
        """Calculate duration in microseconds."""
        dur = self.duration_ns
        return (dur / 1_000.0) if dur is not None else None

    @property
    def duration_ms(self) -> float | None:
        """Calculate duration in milliseconds."""
        dur = self.duration_ns
        return (dur / 1_000_000.0) if dur is not None else None

    def set_attribute(self, key: str, value: Any) -> Span:
        """Set a sanitized attribute on the span (bounded to MAX_SPAN_ATTRIBUTES)."""
        if self.is_ended:
            return self
        if len(self.attributes) < MAX_SPAN_ATTRIBUTES or key in self.attributes:
            self.attributes[str(key)] = sanitize_value(str(key), value)
        return self

    def set_attributes(self, attributes: Mapping[str, Any]) -> Span:
        """Set multiple sanitized attributes on the span."""
        if self.is_ended:
            return self
        for k, v in attributes.items():
            self.set_attribute(k, v)
        return self

    def add_event(
        self,
        name: str,
        attributes: Mapping[str, Any] | None = None,
        timestamp_ns: int | None = None,
    ) -> Span:
        """Add a timestamped event to the span (bounded to MAX_SPAN_EVENTS)."""
        if self.is_ended:
            return self
        if len(self.events) < MAX_SPAN_EVENTS:
            evt = SpanEvent(
                name=name,
                timestamp_ns=timestamp_ns or time.time_ns(),
                attributes=sanitize_attributes(attributes or {}),
            )
            self.events.append(evt)
        return self

    def record_exception(
        self,
        exception: BaseException,
        attributes: Mapping[str, Any] | None = None,
        escaped: bool = False,
    ) -> Span:
        """Record an exception event and mark span status as ERROR."""
        exc_attrs = {
            "exception.type": exception.__class__.__name__,
            "exception.message": sanitize_value("message", str(exception)),
            "exception.escaped": escaped,
        }
        if attributes:
            exc_attrs.update(sanitize_attributes(attributes))
        self.add_event(name="exception", attributes=exc_attrs)
        self.set_status(SpanStatus.ERROR, str(exception))
        return self

    def set_status(self, status: SpanStatus, message: str | None = None) -> Span:
        """Set the span status and optional status message."""
        if self.is_ended:
            return self
        self.status = status
        self.status_message = (
            sanitize_value("status_message", message) if message else None
        )
        return self

    def end(self, end_time_ns: int | None = None) -> Span:
        """End span recording, calculate duration, and notify callbacks."""
        if self.is_ended:
            return self
        self.end_time_perf_ns = time.perf_counter_ns()
        self.end_time_ns = end_time_ns or time.time_ns()

        for callback in self._on_end_callbacks:
            try:
                callback(self)
            except Exception:
                pass
        return self

    def to_dict(self) -> dict[str, Any]:
        """Serialize span to standard dictionary format."""
        return {
            "name": self.name,
            "context": {
                "trace_id": self.context.trace_id,
                "span_id": self.context.span_id,
                "trace_flags": self.context.trace_flags,
                "tracestate": self.context.tracestate,
            },
            "parent_span_id": self.parent_span_id,
            "kind": self.kind.value,
            "start_time_ns": self.start_time_ns,
            "end_time_ns": self.end_time_ns,
            "duration_ms": self.duration_ms,
            "status": {
                "code": self.status.value,
                "message": self.status_message,
            },
            "attributes": self.attributes,
            "events": [e.to_dict() for e in self.events],
        }

    def __enter__(self) -> Span:
        self._context_token = set_current_span(self)
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> bool | None:
        try:
            if exc_val is not None:
                self.record_exception(exc_val, escaped=True)
            elif self.status == SpanStatus.UNSET:
                self.status = SpanStatus.OK
            self.end()
        finally:
            if self._context_token is not None:
                detach_span(self._context_token)
                self._context_token = None
        return None

    async def __aenter__(self) -> Span:
        self._context_token = set_current_span(self)
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> bool | None:
        try:
            if exc_val is not None:
                self.record_exception(exc_val, escaped=True)
            elif self.status == SpanStatus.UNSET:
                self.status = SpanStatus.OK
            self.end()
        finally:
            if self._context_token is not None:
                detach_span(self._context_token)
                self._context_token = None
        return None


class Tracer:
    """Tracer interface for creating and managing spans."""

    def __init__(
        self,
        name: str = "distributed-tracing-profiler",
        sampler: Sampler | None = None,
        on_span_end: Callable[[Span], None] | None = None,
    ) -> None:
        self.name = name
        self.sampler = sampler
        self._on_span_end = on_span_end

    def start_span(
        self,
        name: str,
        parent: SpanContext | Span | None = None,
        kind: SpanKind = SpanKind.INTERNAL,
        attributes: Mapping[str, Any] | None = None,
        start_time_ns: int | None = None,
    ) -> Span:
        """Create and start a new Span, linking to parent context if provided or active."""
        parent_ctx: SpanContext | None = None
        parent_span_id: str | None = None

        if isinstance(parent, Span):
            parent_ctx = parent.context
            parent_span_id = parent.span_id
        elif isinstance(parent, SpanContext):
            parent_ctx = parent
            parent_span_id = parent.span_id
        else:
            current = get_current_span()
            if current:
                parent_ctx = current.context
                parent_span_id = current.span_id

        # Determine sampling
        is_sampled = True
        tracestate: str | None = None

        if self.sampler is not None:
            temp_trace_id = parent_ctx.trace_id if parent_ctx else "0" * 32
            decision = self.sampler.should_sample(
                parent_context=parent_ctx,
                trace_id=temp_trace_id,
                span_name=name,
                span_kind=kind,
                attributes=attributes or {},
            )
            is_sampled = decision.is_sampled
            tracestate = decision.tracestate
        elif parent_ctx is not None:
            is_sampled = parent_ctx.is_sampled
            tracestate = parent_ctx.tracestate

        # Create SpanContext
        if parent_ctx:
            ctx = parent_ctx.create_child(
                is_sampled=is_sampled, tracestate=tracestate
            )
        else:
            ctx = SpanContext.create_root(
                is_sampled=is_sampled, tracestate=tracestate
            )

        callbacks: list[Callable[[Span], None]] = []
        if self._on_span_end:
            callbacks.append(self._on_span_end)

        span = Span(
            name=name,
            context=ctx,
            parent_span_id=parent_span_id,
            kind=kind,
            attributes=attributes,
            start_time_ns=start_time_ns,
            on_end_callbacks=callbacks,
        )
        return span

    def start_as_current_span(
        self,
        name: str,
        parent: SpanContext | Span | None = None,
        kind: SpanKind = SpanKind.INTERNAL,
        attributes: Mapping[str, Any] | None = None,
        start_time_ns: int | None = None,
    ) -> Span:
        """Start a span that can be used directly as a context manager."""
        return self.start_span(
            name=name,
            parent=parent,
            kind=kind,
            attributes=attributes,
            start_time_ns=start_time_ns,
        )
