"""OpenTelemetry OTLP JSON and Jaeger-compatible trace exporter.

Produces standard, schema-compliant JSON payloads consumable by OpenTelemetry Collector,
Jaeger, Datadog, or Grafana Tempo.

DevSecOps Guardrails:
- CWE-502: Safe standard JSON serialization without dynamic evaluation or pickle.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING, Any

from tracing.span import SpanKind, SpanStatus

if TYPE_CHECKING:
    from tracing.span import Span

# OpenTelemetry SpanKind mapping
OTEL_SPAN_KIND_MAP = {
    SpanKind.INTERNAL: 1,
    SpanKind.SERVER: 2,
    SpanKind.CLIENT: 3,
    SpanKind.PRODUCER: 4,
    SpanKind.CONSUMER: 5,
}

# OpenTelemetry StatusCode mapping
OTEL_STATUS_CODE_MAP = {
    SpanStatus.UNSET: 0,
    SpanStatus.OK: 1,
    SpanStatus.ERROR: 2,
}


def _format_otel_value(value: Any) -> dict[str, Any]:
    """Convert a Python value to OpenTelemetry AnyValue dictionary."""
    if isinstance(value, bool):
        return {"boolValue": value}
    elif isinstance(value, int):
        return {"intValue": value}
    elif isinstance(value, float):
        return {"doubleValue": value}
    elif isinstance(value, (list, tuple)):
        return {
            "arrayValue": {
                "values": [_format_otel_value(item) for item in value]
            }
        }
    elif isinstance(value, Mapping):
        return {
            "kvlistValue": {
                "values": [
                    {"key": str(k), "value": _format_otel_value(v)}
                    for k, v in value.items()
                ]
            }
        }
    else:
        return {"stringValue": str(value)}


def _format_otel_attributes(attributes: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Format attribute dictionary into OpenTelemetry key-value list."""
    return [
        {"key": str(k), "value": _format_otel_value(v)}
        for k, v in attributes.items()
    ]


class OTelJSONExporter:
    """Exports trace spans to OpenTelemetry and Jaeger JSON formats."""

    def __init__(
        self,
        service_name: str = "distributed-tracing-profiler",
        service_version: str = "0.1.0",
    ) -> None:
        self.service_name = service_name
        self.service_version = service_version

    def format_otlp_json(self, spans: Sequence[Span]) -> dict[str, Any]:
        """Convert spans to standard OpenTelemetry OTLP JSON schema."""
        otel_spans: list[dict[str, Any]] = []

        for span in spans:
            end_ns = span.end_time_ns or span.start_time_ns
            kind_num = OTEL_SPAN_KIND_MAP.get(span.kind, 1)
            status_code = OTEL_STATUS_CODE_MAP.get(span.status, 0)

            otel_events: list[dict[str, Any]] = []
            for evt in span.events:
                otel_events.append({
                    "timeUnixNano": str(evt.timestamp_ns),
                    "name": evt.name,
                    "attributes": _format_otel_attributes(evt.attributes),
                })

            span_dict: dict[str, Any] = {
                "traceId": span.trace_id,
                "spanId": span.span_id,
                "name": span.name,
                "kind": kind_num,
                "startTimeUnixNano": str(span.start_time_ns),
                "endTimeUnixNano": str(end_ns),
                "attributes": _format_otel_attributes(span.attributes),
                "events": otel_events,
                "status": {
                    "code": status_code,
                    "message": span.status_message or "",
                },
            }

            if span.parent_span_id:
                span_dict["parentSpanId"] = span.parent_span_id

            otel_spans.append(span_dict)

        return {
            "resourceSpans": [
                {
                    "resource": {
                        "attributes": [
                            {
                                "key": "service.name",
                                "value": {"stringValue": self.service_name},
                            },
                            {
                                "key": "service.version",
                                "value": {"stringValue": self.service_version},
                            },
                        ]
                    },
                    "scopeSpans": [
                        {
                            "scope": {
                                "name": "distributed-tracing-profiler",
                                "version": self.service_version,
                            },
                            "spans": otel_spans,
                        }
                    ],
                }
            ]
        }

    def format_jaeger_json(self, spans: Sequence[Span]) -> dict[str, Any]:
        """Convert spans to Jaeger JSON trace format."""
        jaeger_spans: list[dict[str, Any]] = []
        process_id = "p1"

        for span in spans:
            start_us = span.start_time_ns // 1_000
            dur_us = int((span.duration_us or 0.0))

            tags: list[dict[str, Any]] = [
                {"key": k, "type": "string", "value": str(v)}
                for k, v in span.attributes.items()
            ]
            tags.append({
                "key": "span.kind",
                "type": "string",
                "value": span.kind.value.lower(),
            })

            if span.status == SpanStatus.ERROR:
                tags.append({"key": "error", "type": "bool", "value": True})

            references: list[dict[str, str]] = []
            if span.parent_span_id:
                references.append({
                    "refType": "CHILD_OF",
                    "traceID": span.trace_id,
                    "spanID": span.parent_span_id,
                })

            logs: list[dict[str, Any]] = []
            for evt in span.events:
                logs.append({
                    "timestamp": evt.timestamp_ns // 1_000,
                    "fields": [
                        {"key": "event", "type": "string", "value": evt.name},
                        *[
                            {"key": k, "type": "string", "value": str(v)}
                            for k, v in evt.attributes.items()
                        ],
                    ],
                })

            jaeger_spans.append({
                "traceID": span.trace_id,
                "spanID": span.span_id,
                "operationName": span.name,
                "references": references,
                "startTime": start_us,
                "duration": dur_us,
                "tags": tags,
                "logs": logs,
                "processID": process_id,
            })

        trace_id = spans[0].trace_id if spans else "0" * 32

        return {
            "data": [
                {
                    "traceID": trace_id,
                    "spans": jaeger_spans,
                    "processes": {
                        process_id: {
                            "serviceName": self.service_name,
                            "tags": [
                                {
                                    "key": "version",
                                    "type": "string",
                                    "value": self.service_version,
                                }
                            ],
                        }
                    },
                }
            ],
            "total": len(jaeger_spans),
            "limit": 0,
            "offset": 0,
            "errors": None,
        }

    def export_to_json_string(
        self, spans: Sequence[Span], format_type: str = "otlp", indent: int = 2
    ) -> str:
        """Serialize spans to a formatted JSON string."""
        if format_type.lower() == "jaeger":
            data = self.format_jaeger_json(spans)
        else:
            data = self.format_otlp_json(spans)
        return json.dumps(data, indent=indent)

    def export_to_file(
        self,
        spans: Sequence[Span],
        filepath: str,
        format_type: str = "otlp",
        indent: int = 2,
    ) -> None:
        """Safely write JSON spans to file."""
        content = self.export_to_json_string(
            spans, format_type=format_type, indent=indent
        )
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(content)
