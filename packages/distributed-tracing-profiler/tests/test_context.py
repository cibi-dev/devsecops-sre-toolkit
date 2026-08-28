"""Unit tests for W3C TraceContext parsing, validation, and async context propagation."""

from __future__ import annotations

import asyncio

import pytest
from tracing.context import (
    SpanContext,
    detach_span,
    extract_context,
    generate_span_id,
    generate_trace_id,
    get_current_span,
    inject_context,
    parse_traceparent,
    set_current_span,
    use_span,
    validate_span_id,
    validate_trace_id,
    validate_tracestate,
)
from tracing.span import Span


def test_generate_trace_and_span_ids() -> None:
    trace_id = generate_trace_id()
    span_id = generate_span_id()

    assert len(trace_id) == 32
    assert validate_trace_id(trace_id)
    assert len(span_id) == 16
    assert validate_span_id(span_id)


def test_validate_trace_and_span_ids_invalid() -> None:
    assert not validate_trace_id("0" * 32)
    assert not validate_trace_id("invalid_hex_characters_length32!")
    assert not validate_trace_id("12345")  # Too short
    assert not validate_trace_id("")
    assert not validate_trace_id(123)  # type: ignore[arg-type]

    assert not validate_span_id("0" * 16)
    assert not validate_span_id("invalid_hex_16!")
    assert not validate_span_id("12345")  # Too short
    assert not validate_span_id("")
    assert not validate_span_id(123)  # type: ignore[arg-type]


def test_parse_valid_traceparent() -> None:
    header = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
    parsed = parse_traceparent(header)
    assert parsed is not None
    version, trace_id, parent_id, flags = parsed

    assert version == "00"
    assert trace_id == "4bf92f3577b34da6a3ce929d0e0e4736"
    assert parent_id == "00f067aa0ba902b7"
    assert flags == 1


def test_parse_invalid_traceparents() -> None:
    # Too short
    assert parse_traceparent("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7") is None
    # Version ff is forbidden
    assert (
        parse_traceparent("ff-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")
        is None
    )
    # All zeros trace_id
    assert (
        parse_traceparent(f"00-{'0'*32}-00f067aa0ba902b7-01")
        is None
    )
    # All zeros parent_id
    assert (
        parse_traceparent(f"00-4bf92f3577b34da6a3ce929d0e0e4736-{'0'*16}-01")
        is None
    )
    # Version 00 with extra fields
    assert (
        parse_traceparent(
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01-extra"
        )
        is None
    )
    # Non-string
    assert parse_traceparent(12345) is None  # type: ignore[arg-type]
    # Invalid regex match
    assert parse_traceparent("not-a-valid-traceparent-format-at-all-55-chars-padded-------") is None


def test_parse_future_version_traceparent() -> None:
    header = "01-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01-future-field"
    parsed = parse_traceparent(header)
    assert parsed is not None
    version, trace_id, parent_id, flags = parsed
    assert version == "01"
    assert trace_id == "4bf92f3577b34da6a3ce929d0e0e4736"
    assert parent_id == "00f067aa0ba902b7"
    assert flags == 1


def test_validate_tracestate() -> None:
    assert validate_tracestate("rojo=1,congo=2")
    assert validate_tracestate("vendor1@system=opaqueValue,vendor2=val2")
    assert validate_tracestate("")  # Empty is valid
    assert validate_tracestate("   ")  # Whitespace only is valid (stripped to empty)

    # Invalid cases
    assert not validate_tracestate("invalid_no_equal_sign")
    assert not validate_tracestate("key=" + "a" * 300)  # Value too long
    assert not validate_tracestate("a" * 600)  # Total too long
    assert not validate_tracestate(123)  # type: ignore[arg-type]
    assert not validate_tracestate("key=val, ,key2=val2")  # Empty member
    assert not validate_tracestate("INVALID_UPPER_KEY=val")  # Upper key invalid
    assert not validate_tracestate("key=val with space at end ")  # Space at end
    assert not validate_tracestate("key= space_at_start")  # Space at start

    # Too many members (>32)
    too_many = ",".join(f"k{i}=v{i}" for i in range(35))
    assert not validate_tracestate(too_many)


def test_span_context_model() -> None:
    ctx = SpanContext.create_root(is_sampled=True, tracestate="congo=4")
    assert ctx.is_sampled
    assert ctx.trace_flags == 1
    assert ctx.tracestate == "congo=4"
    assert not ctx.is_remote
    assert ctx.traceparent.startswith("00-")

    child_ctx = ctx.create_child(is_sampled=False)
    assert child_ctx.trace_id == ctx.trace_id
    assert child_ctx.span_id != ctx.span_id
    assert not child_ctx.is_sampled
    assert child_ctx.trace_flags == 0
    assert child_ctx.tracestate == "congo=4"

    child_ctx2 = ctx.create_child(tracestate="custom=1")
    assert child_ctx2.tracestate == "custom=1"
    assert child_ctx2.is_sampled == ctx.is_sampled


def test_span_context_validation_errors() -> None:
    with pytest.raises(ValueError, match="Invalid trace_id"):
        SpanContext(trace_id="0" * 32, span_id="1" * 16)

    with pytest.raises(ValueError, match="Invalid span_id"):
        SpanContext(trace_id="1" * 32, span_id="0" * 16)

    with pytest.raises(ValueError, match="Invalid trace_flags"):
        SpanContext(trace_id="1" * 32, span_id="1" * 16, trace_flags=300)

    with pytest.raises(ValueError, match="Invalid tracestate"):
        SpanContext(trace_id="1" * 32, span_id="1" * 16, tracestate="bad_tracestate")


def test_extract_and_inject_context() -> None:
    carrier: dict[str, str] = {
        "TraceParent": "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
        "TraceState": "rojo=1,congo=2",
    }
    extracted = extract_context(carrier)
    assert extracted is not None
    assert extracted.trace_id == "4bf92f3577b34da6a3ce929d0e0e4736"
    assert extracted.span_id == "00f067aa0ba902b7"
    assert extracted.is_sampled
    assert extracted.tracestate == "rojo=1,congo=2"
    assert extracted.is_remote

    # Injection
    out_carrier: dict[str, str] = {}
    inject_context(extracted, out_carrier)
    assert "traceparent" in out_carrier
    assert out_carrier["traceparent"] == extracted.traceparent
    assert out_carrier["tracestate"] == "rojo=1,congo=2"


def test_extract_context_bytes_headers() -> None:
    headers = [
        (b"traceparent", b"00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-00"),
        (b"tracestate", b"foo=bar"),
    ]
    extracted = extract_context(headers)
    assert extracted is not None
    assert extracted.trace_id == "4bf92f3577b34da6a3ce929d0e0e4736"
    assert not extracted.is_sampled
    assert extracted.tracestate == "foo=bar"


def test_extract_context_empty_or_invalid() -> None:
    assert extract_context({}) is None
    assert extract_context(None) is None  # type: ignore[arg-type]
    assert extract_context({"other": "header"}) is None
    assert extract_context({"traceparent": "invalid"}) is None


def test_set_and_detach_span() -> None:
    ctx = SpanContext.create_root()
    span = Span("manual_span", ctx)

    token = set_current_span(span)
    assert get_current_span() is span

    detach_span(token)
    assert get_current_span() is None


@pytest.mark.asyncio
async def test_async_contextvars_propagation() -> None:
    ctx = SpanContext.create_root()
    span = Span("test_async_span", ctx)

    assert get_current_span() is None

    with use_span(span):
        assert get_current_span() is span

        async def subtask(task_id: int) -> Span | None:
            await asyncio.sleep(0.001)
            return get_current_span()

        tasks = [asyncio.create_task(subtask(i)) for i in range(5)]
        results = await asyncio.gather(*tasks)

        for res in results:
            assert res is span

    assert get_current_span() is None
