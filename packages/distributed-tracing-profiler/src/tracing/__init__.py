"""Distributed Tracing Profiler.

Enterprise-grade pure-Python distributed tracing SDK, W3C TraceContext propagator,
and high-precision latency profiler.
"""

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
from tracing.exporters.console import ASCIIWaterfallExporter, ConsoleSpanExporter
from tracing.exporters.otel_json import OTelJSONExporter
from tracing.middleware import TracingASGIMiddleware, TracingWSGIMiddleware, traced
from tracing.profiler import (
    LatencyMetrics,
    OverheadBenchmark,
    PercentileCalculator,
    SpanProfiler,
)
from tracing.sampler import (
    AlwaysOffSampler,
    AlwaysOnSampler,
    ParentBasedSampler,
    RateLimitingSampler,
    RatioBasedSampler,
    Sampler,
    SamplingDecision,
)
from tracing.span import (
    Span,
    SpanEvent,
    SpanKind,
    SpanStatus,
    Tracer,
    sanitize_attributes,
    sanitize_value,
)

__version__ = "0.1.0"

__all__ = [
    # Context & W3C
    "SpanContext",
    "generate_trace_id",
    "generate_span_id",
    "validate_trace_id",
    "validate_span_id",
    "validate_tracestate",
    "parse_traceparent",
    "extract_context",
    "inject_context",
    "get_current_span",
    "set_current_span",
    "detach_span",
    "use_span",
    # Span & Tracer
    "Span",
    "SpanEvent",
    "SpanKind",
    "SpanStatus",
    "Tracer",
    "sanitize_attributes",
    "sanitize_value",
    # Samplers
    "Sampler",
    "AlwaysOnSampler",
    "AlwaysOffSampler",
    "RatioBasedSampler",
    "RateLimitingSampler",
    "ParentBasedSampler",
    "SamplingDecision",
    # Profiler
    "LatencyMetrics",
    "PercentileCalculator",
    "SpanProfiler",
    "OverheadBenchmark",
    # Middleware
    "TracingASGIMiddleware",
    "TracingWSGIMiddleware",
    "traced",
    # Exporters
    "OTelJSONExporter",
    "ConsoleSpanExporter",
    "ASCIIWaterfallExporter",
    "__version__",
]
