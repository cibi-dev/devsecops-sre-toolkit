"""Unit tests for Span model, lifecycle, and Tracer."""

from __future__ import annotations

import time

import pytest
from tracing.context import (
    SpanContext,
    get_current_span,
)
from tracing.sampler import AlwaysOnSampler
from tracing.span import (
    MAX_SPAN_ATTRIBUTES,
    MAX_SPAN_EVENTS,
    Span,
    SpanKind,
    SpanStatus,
    Tracer,
    sanitize_attributes,
    sanitize_value,
)


def test_span_initialization_and_properties() -> None:
    ctx = SpanContext.create_root()
    span = Span(
        name="test_operation",
        context=ctx,
        parent_span_id="parent1234567890",
        kind=SpanKind.SERVER,
        attributes={"http.method": "GET", "custom.tag": 42},
    )

    assert span.name == "test_operation"
    assert span.trace_id == ctx.trace_id
    assert span.span_id == ctx.span_id
    assert span.parent_span_id == "parent1234567890"
    assert span.kind == SpanKind.SERVER
    assert span.status == SpanStatus.UNSET
    assert span.status_message is None
    assert span.attributes["http.method"] == "GET"
    assert span.attributes["custom.tag"] == 42
    assert not span.is_ended
    assert span.duration_ms is None


def test_span_lifecycle_and_timing() -> None:
    ctx = SpanContext.create_root()
    span = Span("timed_op", ctx)

    time.sleep(0.005)  # 5ms
    span.set_status(SpanStatus.OK)
    span.end()

    assert span.is_ended
    assert span.duration_ns is not None
    assert span.duration_ns > 0
    assert span.duration_us is not None
    assert span.duration_ms is not None
    assert span.duration_ms >= 4.0  # Approx 5ms
    assert span.status == SpanStatus.OK

    # Calling end() again should be a no-op
    first_end = span.end_time_ns
    span.end()
    assert span.end_time_ns == first_end


def test_span_attributes_mutation() -> None:
    ctx = SpanContext.create_root()
    span = Span("attr_op", ctx)

    span.set_attribute("key1", "val1")
    span.set_attributes({"key2": 2, "key3": True})

    assert span.attributes["key1"] == "val1"
    assert span.attributes["key2"] == 2
    assert span.attributes["key3"] is True

    span.end()
    # Cannot modify after ended
    span.set_attribute("key4", "val4")
    assert "key4" not in span.attributes
    span.set_attributes({"key5": "val5"})
    assert "key5" not in span.attributes
    span.add_event("event_after_end")
    assert len(span.events) == 0
    span.set_status(SpanStatus.ERROR, "too late")
    assert span.status != SpanStatus.ERROR


def test_span_events() -> None:
    ctx = SpanContext.create_root()
    span = Span("event_op", ctx)

    span.add_event("cache_miss", {"cache.key": "user_100"})
    span.add_event("db_fallback")

    assert len(span.events) == 2
    assert span.events[0].name == "cache_miss"
    assert span.events[0].attributes["cache.key"] == "user_100"
    assert span.events[1].name == "db_fallback"


def test_span_record_exception() -> None:
    ctx = SpanContext.create_root()
    span = Span("error_op", ctx)

    exc = ValueError("Database connection failed")
    span.record_exception(exc)

    assert span.status == SpanStatus.ERROR
    assert span.status_message == "Database connection failed"
    assert len(span.events) == 1
    assert span.events[0].name == "exception"
    assert span.events[0].attributes["exception.type"] == "ValueError"
    assert span.events[0].attributes["exception.message"] == "Database connection failed"


def test_span_sync_context_manager() -> None:
    ctx = SpanContext.create_root()
    span = Span("ctx_op", ctx)

    assert get_current_span() is None
    with span:
        assert get_current_span() is span
    assert get_current_span() is None
    assert span.is_ended
    assert span.status == SpanStatus.OK


def test_span_sync_context_manager_exception() -> None:
    ctx = SpanContext.create_root()
    span = Span("ctx_exc_op", ctx)

    with pytest.raises(RuntimeError, match="Kaboom"):
        with span:
            raise RuntimeError("Kaboom")

    assert span.is_ended
    assert span.status == SpanStatus.ERROR
    assert get_current_span() is None


@pytest.mark.asyncio
async def test_span_async_context_manager() -> None:
    ctx = SpanContext.create_root()
    span = Span("async_ctx_op", ctx)

    assert get_current_span() is None
    async with span:
        assert get_current_span() is span
    assert get_current_span() is None
    assert span.is_ended
    assert span.status == SpanStatus.OK


@pytest.mark.asyncio
async def test_span_async_context_manager_exception() -> None:
    ctx = SpanContext.create_root()
    span = Span("async_ctx_exc_op", ctx)

    with pytest.raises(RuntimeError, match="Async Kaboom"):
        async with span:
            raise RuntimeError("Async Kaboom")

    assert span.is_ended
    assert span.status == SpanStatus.ERROR
    assert get_current_span() is None


def test_tracer_parent_child_hierarchy() -> None:
    tracer = Tracer(name="test_tracer", sampler=AlwaysOnSampler())

    parent = tracer.start_span("parent_span")
    with parent:
        child = tracer.start_span("child_span")
        with child:
            assert child.trace_id == parent.trace_id
            assert child.parent_span_id == parent.span_id
            assert child.span_id != parent.span_id

    assert parent.is_ended
    assert child.is_ended


def test_tracer_start_as_current_span() -> None:
    tracer = Tracer(name="current_tracer")
    span = tracer.start_as_current_span("current_op")
    with span:
        assert get_current_span() is span
    assert span.is_ended


def test_tracer_callbacks_and_error_handling() -> None:
    ended_spans: list[Span] = []

    def faulty_callback(s: Span) -> None:
        raise RuntimeError("Callback crash")

    tracer = Tracer(name="cb_tracer", on_span_end=ended_spans.append)
    span = tracer.start_span("op1")
    span._on_end_callbacks.append(faulty_callback)
    # Should not raise even if a callback fails
    span.end()

    assert len(ended_spans) == 1
    assert ended_spans[0] is span


def test_span_to_dict() -> None:
    ctx = SpanContext.create_root()
    span = Span("dict_op", ctx, attributes={"env": "prod"})
    span.add_event("ev1")
    span.end()

    d = span.to_dict()
    assert d["name"] == "dict_op"
    assert d["context"]["trace_id"] == ctx.trace_id
    assert d["attributes"]["env"] == "prod"
    assert len(d["events"]) == 1
    assert d["status"]["code"] == "UNSET"


def test_span_bounded_attributes_and_events() -> None:
    ctx = SpanContext.create_root()
    span = Span("overflow_op", ctx)

    # Insert 200 attributes
    for i in range(200):
        span.set_attribute(f"attr_{i}", i)

    # Insert 200 events
    for i in range(200):
        span.add_event(f"evt_{i}")

    assert len(span.attributes) <= MAX_SPAN_ATTRIBUTES
    assert len(span.events) <= MAX_SPAN_EVENTS


def test_sanitize_nested_structures() -> None:
    nested = {
        "dict_field": {"auth_key": "secret", "safe": "ok"},
        "list_field": ["safe", "ghp_123456789012345678901234567890"],
        "long_str": "a" * 5000,
    }
    sanitized = sanitize_attributes(nested)
    assert sanitized["dict_field"]["auth_key"] == "[REDACTED]"
    assert sanitized["dict_field"]["safe"] == "ok"
    assert "[REDACTED]" in sanitized["list_field"][1]
    assert "...[TRUNCATED]" in sanitized["long_str"]
