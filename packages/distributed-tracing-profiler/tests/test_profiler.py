"""Unit tests for PercentileCalculator, LatencyMetrics, and SpanProfiler."""

from __future__ import annotations

import pytest
from tracing.context import SpanContext
from tracing.profiler import (
    LatencyMetrics,
    OverheadBenchmark,
    PercentileCalculator,
    SpanProfiler,
)
from tracing.span import Span


def test_percentile_calculator_empty_and_single() -> None:
    empty_m = PercentileCalculator.compute_metrics([])
    assert empty_m.count == 0
    assert empty_m.min_ms == 0.0
    assert empty_m.p50_ms == 0.0

    single_m = PercentileCalculator.compute_metrics([42.5])
    assert single_m.count == 1
    assert single_m.min_ms == 42.5
    assert single_m.max_ms == 42.5
    assert single_m.mean_ms == 42.5
    assert single_m.p50_ms == 42.5
    assert single_m.p99_ms == 42.5
    assert single_m.stddev_ms == 0.0


def test_percentile_calculator_exact_distribution() -> None:
    # 1 to 100
    values = [float(i) for i in range(1, 101)]
    metrics = PercentileCalculator.compute_metrics(values)

    assert metrics.count == 100
    assert metrics.min_ms == 1.0
    assert metrics.max_ms == 100.0
    assert metrics.mean_ms == 50.5
    # Linear interpolation for 1..100: p50 should be 50.5
    assert pytest.approx(metrics.p50_ms, 0.1) == 50.5
    assert pytest.approx(metrics.p90_ms, 0.1) == 90.1
    assert pytest.approx(metrics.p95_ms, 0.1) == 95.05
    assert pytest.approx(metrics.p99_ms, 0.1) == 99.01


def test_span_profiler_recording() -> None:
    profiler = SpanProfiler(max_buffer_size=100)
    ctx = SpanContext.create_root()

    # Record 10 spans of operation A
    for i in range(10):
        s = Span("op_a", ctx)
        s.end_time_perf_ns = s.start_time_perf_ns + (i + 1) * 1_000_000  # (i+1) ms
        s.end_time_ns = s.start_time_ns + (i + 1) * 1_000_000
        profiler.record_span(s)

    # Record 5 spans of operation B
    for i in range(5):
        s = Span("op_b", ctx)
        s.end_time_perf_ns = s.start_time_perf_ns + 10_000_000  # 10 ms
        s.end_time_ns = s.start_time_ns + 10_000_000
        profiler.record_span(s)

    metrics_a = profiler.get_metrics("op_a")
    assert metrics_a.count == 10
    assert metrics_a.min_ms == 1.0
    assert metrics_a.max_ms == 10.0

    metrics_b = profiler.get_metrics("op_b")
    assert metrics_b.count == 5
    assert metrics_b.min_ms == 10.0
    assert metrics_b.max_ms == 10.0

    all_metrics = profiler.get_metrics()
    assert all_metrics.count == 15

    dict_metrics = profiler.get_all_metrics()
    assert "op_a" in dict_metrics
    assert "op_b" in dict_metrics

    slowest = profiler.get_slowest_spans(limit=3)
    assert len(slowest) == 3
    assert slowest[0]["duration_ms"] == 10.0


def test_span_profiler_clear() -> None:
    profiler = SpanProfiler()
    ctx = SpanContext.create_root()
    s = Span("test", ctx)
    s.end_time_perf_ns = s.start_time_perf_ns + 1_000_000
    s.end_time_ns = s.start_time_ns + 1_000_000
    profiler.record_span(s)

    assert profiler.get_metrics().count == 1
    profiler.clear()
    assert profiler.get_metrics().count == 0


def test_span_profiler_buffer_eviction() -> None:
    # Small buffer of 10 items
    profiler = SpanProfiler(max_buffer_size=10)
    ctx = SpanContext.create_root()

    for i in range(25):
        s = Span("evict_test", ctx)
        s.end_time_perf_ns = s.start_time_perf_ns + (i + 1) * 1_000_000
        s.end_time_ns = s.start_time_ns + (i + 1) * 1_000_000
        profiler.record_span(s)

    # Capacity should not exceed 10
    assert profiler.get_metrics().count == 10


def test_overhead_benchmark() -> None:
    res = OverheadBenchmark.measure_span_overhead(iterations=100)
    assert res["iterations"] == 100.0
    assert res["avg_overhead_us"] < 1000.0  # Must be strictly under 1ms
    assert res["ops_per_second"] > 0
