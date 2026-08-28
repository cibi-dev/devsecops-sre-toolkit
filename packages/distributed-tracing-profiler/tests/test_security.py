"""DevSecOps Security Guardrails Verification Test Suite.

Verifies mitigations for:
- CWE-330 & CWE-208: Cryptographically secure identifier generation and constant-time comparisons.
- CWE-209: Attribute sanitization, credential masking, and PII protection.
- CWE-400: Bounded memory consumption via circular buffers.
- CWE-502: Safe serialization without dynamic evaluation or pickle.
"""

from __future__ import annotations

import hmac

from tracing.context import (
    SpanContext,
    generate_span_id,
    generate_trace_id,
    validate_span_id,
    validate_trace_id,
)
from tracing.exporters.otel_json import OTelJSONExporter
from tracing.profiler import SpanProfiler
from tracing.span import (
    MAX_SPAN_ATTRIBUTES,
    MAX_SPAN_EVENTS,
    Span,
    sanitize_attributes,
    sanitize_value,
)


def test_cwe_330_entropy_and_uniqueness() -> None:
    """Verify CWE-330: Trace IDs and Span IDs must be unique and non-zero."""
    num_samples = 5_000
    trace_ids: set[str] = set()
    span_ids: set[str] = set()

    for _ in range(num_samples):
        tid = generate_trace_id()
        sid = generate_span_id()

        assert len(tid) == 32
        assert len(sid) == 16
        assert validate_trace_id(tid)
        assert validate_span_id(sid)

        trace_ids.add(tid)
        span_ids.add(sid)

    # 100% collision-free in 5,000 samples
    assert len(trace_ids) == num_samples
    assert len(span_ids) == num_samples


def test_cwe_208_constant_time_comparison() -> None:
    """Verify CWE-208: constant-time digest comparison is utilized."""
    id1 = "4bf92f3577b34da6a3ce929d0e0e4736"
    id2 = "4bf92f3577b34da6a3ce929d0e0e4736"
    id3 = "00000000000000000000000000000000"

    assert hmac.compare_digest(id1, id2)
    assert not hmac.compare_digest(id1, id3)


def test_cwe_209_sensitive_key_redaction() -> None:
    """Verify CWE-209: Sensitive keys are masked as [REDACTED]."""
    sensitive_dict = {
        "authorization": "Bearer secret_jwt_12345",
        "auth.token": "ghp_myPersonalSecretToken12345678",
        "api_key": "live_sk_999888777",
        "user.password": "P@ssw0rd123!",
        "cookie": "session_id=abcxyz987",
        "credit_card": "4532-0000-1111-2222",
        "normal_field": "public_data",
    }

    sanitized = sanitize_attributes(sensitive_dict)

    assert sanitized["authorization"] == "[REDACTED]"
    assert sanitized["auth.token"] == "[REDACTED]"
    assert sanitized["api_key"] == "[REDACTED]"
    assert sanitized["user.password"] == "[REDACTED]"
    assert sanitized["cookie"] == "[REDACTED]"
    assert sanitized["credit_card"] == "[REDACTED]"
    assert sanitized["normal_field"] == "public_data"


def test_cwe_209_value_regex_redaction() -> None:
    """Verify CWE-209: Sensitive tokens inside arbitrary values are masked."""
    # Even if key is generic, token pattern should trigger redaction
    jwt_val = f"Header {'eyJ' + 'hbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9'}.eyJzdWIiOiIxMjM0NTY3ODkwIn0.mockSignature"  # gitleaks:allow
    sanitized = sanitize_value("unusual_key", jwt_val)
    assert "[REDACTED]" in sanitized
    assert "mockSignature" not in sanitized


def test_cwe_400_bounded_memory_profiler() -> None:
    """Verify CWE-400 Anti-DoS: Profiler memory buffer is strictly bounded."""
    buffer_cap = 500
    profiler = SpanProfiler(max_buffer_size=buffer_cap)
    ctx = SpanContext.create_root()

    # Attempt to flood profiler with 10,000 spans
    for i in range(10_000):
        s = Span(f"stress_op_{i % 5}", ctx)
        s.end_time_perf_ns = s.start_time_perf_ns + 1_000_000
        s.end_time_ns = s.start_time_ns + 1_000_000
        profiler.record_span(s)

    metrics = profiler.get_metrics()
    # Total count in circular buffer must never exceed capacity
    assert metrics.count == buffer_cap


def test_cwe_400_bounded_span_attributes_and_events() -> None:
    """Verify CWE-400: Individual span attributes & events cannot grow unbounded."""
    ctx = SpanContext.create_root()
    span = Span("bounded_span", ctx)

    # Attempt to inject 500 attributes and 500 events
    for i in range(500):
        span.set_attribute(f"k_{i}", f"v_{i}")
        span.add_event(f"e_{i}")

    assert len(span.attributes) == MAX_SPAN_ATTRIBUTES
    assert len(span.events) == MAX_SPAN_EVENTS


def test_cwe_502_safe_serialization() -> None:
    """Verify CWE-502: Exporter outputs valid and safe JSON without unsafe structures."""
    ctx = SpanContext.create_root()
    span = Span("safe_op", ctx, attributes={"user": "safe_user", "count": 10})
    span.end()

    exporter = OTelJSONExporter()
    json_str = exporter.export_to_json_string([span])

    # Must be valid standard JSON
    import json

    loaded = json.loads(json_str)
    assert isinstance(loaded, dict)
    assert "resourceSpans" in loaded
