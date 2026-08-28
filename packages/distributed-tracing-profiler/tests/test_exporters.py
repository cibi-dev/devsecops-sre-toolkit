"""Unit tests for OpenTelemetry JSON, Jaeger JSON, and ASCII Waterfall Exporters."""

from __future__ import annotations

import io
import json
from typing import Any

from tracing.context import SpanContext
from tracing.exporters.console import (
    ASCIIWaterfallExporter,
    ConsoleSpanExporter,
    _format_duration,
)
from tracing.exporters.otel_json import OTelJSONExporter, _format_otel_value
from tracing.span import Span, SpanKind, SpanStatus


def test_otel_value_formatting() -> None:
    assert _format_otel_value(True) == {"boolValue": True}
    assert _format_otel_value(123) == {"intValue": 123}
    assert _format_otel_value(12.34) == {"doubleValue": 12.34}
    assert _format_otel_value(["a", 1]) == {
        "arrayValue": {
            "values": [{"stringValue": "a"}, {"intValue": 1}]
        }
    }
    assert _format_otel_value({"k": "v"}) == {
        "kvlistValue": {
            "values": [{"key": "k", "value": {"stringValue": "v"}}]
        }
    }


def test_otel_json_exporter_otlp_format() -> None:
    ctx = SpanContext.create_root()
    parent = Span(
        "parent_op",
        ctx,
        kind=SpanKind.SERVER,
        attributes={"http.status": 200, "is_admin": True, "float_score": 9.5},
    )
    parent.add_event("event1", {"detail": "info"})
    parent.set_status(SpanStatus.OK)
    parent.end()

    child_ctx = ctx.create_child()
    child = Span("child_op", child_ctx, parent_span_id=parent.span_id, kind=SpanKind.CLIENT)
    child.set_status(SpanStatus.ERROR, "timeout")
    child.end()

    exporter = OTelJSONExporter(service_name="test-service", service_version="1.2.3")
    otlp = exporter.format_otlp_json([parent, child])

    assert "resourceSpans" in otlp
    assert len(otlp["resourceSpans"]) == 1
    res = otlp["resourceSpans"][0]

    # Verify resource attributes
    res_attrs = {a["key"]: a["value"]["stringValue"] for a in res["resource"]["attributes"]}
    assert res_attrs["service.name"] == "test-service"
    assert res_attrs["service.version"] == "1.2.3"

    spans = res["scopeSpans"][0]["spans"]
    assert len(spans) == 2

    # Verify parent span
    p_span = spans[0]
    assert p_span["name"] == "parent_op"
    assert p_span["kind"] == 2  # SERVER
    assert p_span["status"]["code"] == 1  # OK
    assert len(p_span["events"]) == 1

    # Verify child span
    c_span = spans[1]
    assert c_span["name"] == "child_op"
    assert c_span["parentSpanId"] == parent.span_id
    assert c_span["status"]["code"] == 2  # ERROR
    assert c_span["status"]["message"] == "timeout"


def test_otel_json_exporter_jaeger_format() -> None:
    ctx = SpanContext.create_root()
    parent = Span("gateway", ctx)
    parent.end()

    child = Span(
        "db_query",
        ctx.create_child(),
        parent_span_id=parent.span_id,
        kind=SpanKind.CLIENT,
        attributes={"db.system": "postgresql"},
    )
    child.add_event("connected", {"host": "10.0.0.1"})
    child.set_status(SpanStatus.ERROR, "conn reset")
    child.end()

    exporter = OTelJSONExporter(service_name="db-service")
    jaeger = exporter.format_jaeger_json([parent, child])

    assert "data" in jaeger
    data = jaeger["data"][0]
    assert data["traceID"] == ctx.trace_id
    assert len(data["spans"]) == 2

    # Child should have CHILD_OF reference and error tag
    c = data["spans"][1]
    assert len(c["references"]) == 1
    assert c["references"][0]["spanID"] == parent.span_id
    error_tags = [t for t in c["tags"] if t["key"] == "error"]
    assert len(error_tags) == 1
    assert error_tags[0]["value"] is True


def test_otel_exporter_to_file(tmp_path: Any) -> None:
    ctx = SpanContext.create_root()
    span = Span("file_op", ctx)
    span.end()

    exporter = OTelJSONExporter()
    out_file = str(tmp_path / "traces.json")
    exporter.export_to_file([span], out_file, format_type="otlp")

    with open(out_file, encoding="utf-8") as f:
        loaded = json.load(f)
        assert "resourceSpans" in loaded

    jaeger_out_file = str(tmp_path / "jaeger.json")
    exporter.export_to_file([span], jaeger_out_file, format_type="jaeger")

    with open(jaeger_out_file, encoding="utf-8") as f:
        jaeger_loaded = json.load(f)
        assert "data" in jaeger_loaded


def test_ascii_waterfall_rendering() -> None:
    ctx = SpanContext.create_root()

    root = Span("root", ctx, start_time_ns=1_000_000_000)
    root.end_time_ns = 1_050_000_000  # 50ms
    root.end_time_perf_ns = root.start_time_perf_ns + 50_000_000
    root.status = SpanStatus.OK

    child1 = Span("child1", ctx.create_child(), parent_span_id=root.span_id, start_time_ns=1_010_000_000)
    child1.end_time_ns = 1_030_000_000  # 20ms
    child1.end_time_perf_ns = child1.start_time_perf_ns + 20_000_000
    child1.status = SpanStatus.OK

    child2 = Span("child2", ctx.create_child(), parent_span_id=root.span_id, start_time_ns=1_030_000_000)
    child2.end_time_ns = 1_045_000_000  # 15ms
    child2.end_time_perf_ns = child2.start_time_perf_ns + 15_000_000
    child2.status = SpanStatus.ERROR

    exporter = ASCIIWaterfallExporter(bar_width=20)
    text = exporter.render_cascade([root, child1, child2])

    assert f"TRACE: {ctx.trace_id}" in text
    assert "root" in text
    assert "child1" in text
    assert "child2" in text
    assert "🟢 OK" in text
    assert "🔴 ERROR" in text


def test_ascii_waterfall_empty() -> None:
    exporter = ASCIIWaterfallExporter()
    assert exporter.render_cascade([]) == "No spans to display."


def test_console_span_exporter() -> None:
    stream = io.StringIO()
    console_exp = ConsoleSpanExporter(stream=stream)

    ctx = SpanContext.create_root()
    span = Span("console_op", ctx)
    span.end()

    console_exp.export([span])
    output = stream.getvalue()
    assert "console_op" in output


def test_format_duration_helpers() -> None:
    assert _format_duration(None) == "0.00ms"
    assert _format_duration(0.0005) == "500.0ns"
    assert _format_duration(0.45) == "450.00µs"
    assert _format_duration(12.345) == "12.35ms"
    assert _format_duration(2500.0) == "2.50s"
