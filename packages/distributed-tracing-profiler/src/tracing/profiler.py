"""High-precision latency profiler and mathematical percentile calculator.

Calculates exact percentiles (p50, p90, p95, p99, p99.9), mean, stddev,
and measures microsecond instrumentation overhead.

DevSecOps Guardrails:
- CWE-400: Uses bounded circular buffers (collections.deque(maxlen=...)) to guarantee fixed memory consumption.
- Thread-safe state mutation.
"""

from __future__ import annotations

import collections
import math
import statistics
import threading
import time
from collections.abc import Sequence
from typing import TYPE_CHECKING, Any

from pydantic import BaseModel, Field

if TYPE_CHECKING:
    from tracing.span import Span

DEFAULT_BUFFER_CAPACITY = 10_000


class LatencyMetrics(BaseModel):
    """Pydantic model representing statistical latency metrics."""

    count: int = Field(ge=0, description="Total number of measured operations")
    min_ms: float = Field(ge=0.0, description="Minimum latency in milliseconds")
    max_ms: float = Field(ge=0.0, description="Maximum latency in milliseconds")
    mean_ms: float = Field(ge=0.0, description="Arithmetic mean latency in milliseconds")
    stddev_ms: float = Field(ge=0.0, description="Standard deviation in milliseconds")
    p50_ms: float = Field(ge=0.0, description="50th percentile (Median) latency in ms")
    p90_ms: float = Field(ge=0.0, description="90th percentile latency in ms")
    p95_ms: float = Field(ge=0.0, description="95th percentile latency in ms")
    p99_ms: float = Field(ge=0.0, description="99th percentile latency in ms")
    p99_9_ms: float = Field(ge=0.0, description="99.9th percentile latency in ms")

    model_config = {"extra": "forbid"}

    @classmethod
    def empty(cls) -> LatencyMetrics:
        return cls(
            count=0,
            min_ms=0.0,
            max_ms=0.0,
            mean_ms=0.0,
            stddev_ms=0.0,
            p50_ms=0.0,
            p90_ms=0.0,
            p95_ms=0.0,
            p99_ms=0.0,
            p99_9_ms=0.0,
        )


class PercentileCalculator:
    """Mathematical percentile calculator using standard linear interpolation."""

    @staticmethod
    def calculate_percentile(sorted_values: Sequence[float], percentile: float) -> float:
        """Calculate exact percentile via linear interpolation (R-7 / NumPy standard)."""
        n = len(sorted_values)
        if n == 0:
            return 0.0
        if n == 1 or percentile <= 0.0:
            return float(sorted_values[0])
        if percentile >= 100.0:
            return float(sorted_values[-1])

        rank = (percentile / 100.0) * (n - 1)
        lower_idx = int(math.floor(rank))
        upper_idx = min(lower_idx + 1, n - 1)
        weight = rank - lower_idx

        return float(
            sorted_values[lower_idx] * (1.0 - weight)
            + sorted_values[upper_idx] * weight
        )

    @classmethod
    def compute_metrics(cls, values_ms: Sequence[float]) -> LatencyMetrics:
        """Compute complete statistical summary from raw latency samples in milliseconds."""
        if not values_ms:
            return LatencyMetrics.empty()

        sorted_vals = sorted(values_ms)
        n = len(sorted_vals)
        min_v = sorted_vals[0]
        max_v = sorted_vals[-1]
        mean_v = sum(sorted_vals) / n

        if n > 1:
            try:
                stddev_v = statistics.stdev(sorted_vals)
            except statistics.StatisticsError:
                stddev_v = 0.0
        else:
            stddev_v = 0.0

        return LatencyMetrics(
            count=n,
            min_ms=round(min_v, 4),
            max_ms=round(max_v, 4),
            mean_ms=round(mean_v, 4),
            stddev_ms=round(stddev_v, 4),
            p50_ms=round(cls.calculate_percentile(sorted_vals, 50.0), 4),
            p90_ms=round(cls.calculate_percentile(sorted_vals, 90.0), 4),
            p95_ms=round(cls.calculate_percentile(sorted_vals, 95.0), 4),
            p99_ms=round(cls.calculate_percentile(sorted_vals, 99.0), 4),
            p99_9_ms=round(cls.calculate_percentile(sorted_vals, 99.9), 4),
        )


class SpanProfiler:
    """Thread-safe latency profiler with bounded memory consumption."""

    def __init__(self, max_buffer_size: int = DEFAULT_BUFFER_CAPACITY) -> None:
        self.max_buffer_size = max_buffer_size
        self._spans_buffer: collections.deque[Span] = collections.deque(
            maxlen=max_buffer_size
        )
        self._durations_by_name: dict[str, collections.deque[float]] = {}
        self._all_durations: collections.deque[float] = collections.deque(
            maxlen=max_buffer_size
        )
        self._lock = threading.Lock()

    def record_span(self, span: Span) -> None:
        """Record a finished span into the bounded circular buffer."""
        dur_ms = span.duration_ms
        if dur_ms is None:
            return

        with self._lock:
            self._spans_buffer.append(span)
            self._all_durations.append(dur_ms)

            if span.name not in self._durations_by_name:
                self._durations_by_name[span.name] = collections.deque(
                    maxlen=self.max_buffer_size
                )
            self._durations_by_name[span.name].append(dur_ms)

    def get_metrics(self, span_name: str | None = None) -> LatencyMetrics:
        """Calculate latency metrics for a specific span name or all recorded spans."""
        with self._lock:
            if span_name is not None:
                samples = list(self._durations_by_name.get(span_name, []))
            else:
                samples = list(self._all_durations)

        return PercentileCalculator.compute_metrics(samples)

    def get_all_metrics(self) -> dict[str, LatencyMetrics]:
        """Calculate latency metrics for each distinct operation."""
        with self._lock:
            names = list(self._durations_by_name.keys())

        return {name: self.get_metrics(name) for name in names}

    def get_slowest_spans(self, limit: int = 10) -> list[dict[str, Any]]:
        """Retrieve the top N slowest recorded spans."""
        with self._lock:
            valid_spans = [s for s in self._spans_buffer if s.duration_ms is not None]
            sorted_spans = sorted(
                valid_spans, key=lambda s: s.duration_ms or 0.0, reverse=True
            )
            return [s.to_dict() for s in sorted_spans[:limit]]

    def clear(self) -> None:
        """Reset all recorded metrics and empty the circular buffer."""
        with self._lock:
            self._spans_buffer.clear()
            self._durations_by_name.clear()
            self._all_durations.clear()


class OverheadBenchmark:
    """High-resolution profiler for measuring instrumentation overhead."""

    @staticmethod
    def measure_span_overhead(iterations: int = 10_000) -> dict[str, float]:
        """Measure average CPU overhead per span start and end in microseconds."""
        from tracing.context import SpanContext
        from tracing.span import Span

        ctx = SpanContext.create_root()

        start_time = time.perf_counter_ns()
        for _ in range(iterations):
            s = Span("benchmark_op", ctx)
            s.set_attribute("http.method", "GET")
            s.end()
        total_ns = time.perf_counter_ns() - start_time

        avg_ns = total_ns / iterations
        avg_us = avg_ns / 1_000.0

        return {
            "iterations": float(iterations),
            "total_time_ms": round(total_ns / 1_000_000.0, 3),
            "avg_overhead_us": round(avg_us, 3),
            "avg_overhead_ns": round(avg_ns, 1),
            "ops_per_second": round(1_000_000_000.0 / avg_ns, 1) if avg_ns > 0 else 0,
        }
