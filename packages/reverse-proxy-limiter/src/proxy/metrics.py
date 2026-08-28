"""
Prometheus and OpenMetrics Compliant Metrics Registry.

High-performance pure-Python implementation of Counters, Gauges, and Histograms
for reverse proxy monitoring with zero external C-dependencies.
"""

from __future__ import annotations

from enum import Enum
import threading
import time
from typing import Dict, List, Optional, Sequence, Tuple


class MetricType(str, Enum):
    COUNTER = "counter"
    GAUGE = "gauge"
    HISTOGRAM = "histogram"


def _format_labels(labels: Dict[str, str]) -> str:
    """Format dictionary labels into OpenMetrics key=value string."""
    if not labels:
        return ""
    pairs = [f'{k}="{v}"' for k, v in sorted(labels.items())]
    return "{" + ",".join(pairs) + "}"


class Counter:
    """Thread-safe cumulative monotonic metric counter."""

    def __init__(self, name: str, help_text: str, label_names: Optional[Sequence[str]] = None) -> None:
        self.name = name
        self.help_text = help_text
        self.label_names = tuple(label_names or ())
        self._values: Dict[Tuple[Tuple[str, str], ...], float] = {}
        self._lock = threading.Lock()

    def _get_key(self, labels: Dict[str, str]) -> Tuple[Tuple[str, str], ...]:
        return tuple((k, str(labels.get(k, ""))) for k in self.label_names)

    def inc(self, amount: float = 1.0, labels: Optional[Dict[str, str]] = None) -> None:
        """Increment counter value by amount (must be non-negative)."""
        if amount < 0:
            raise ValueError("Counter increments must be non-negative")
        key = self._get_key(labels or {})
        with self._lock:
            self._values[key] = self._values.get(key, 0.0) + amount

    def get(self, labels: Optional[Dict[str, str]] = None) -> float:
        """Retrieve current value for label set."""
        key = self._get_key(labels or {})
        with self._lock:
            return self._values.get(key, 0.0)

    def export(self) -> List[str]:
        """Format metric into OpenMetrics lines."""
        lines = [
            f"# HELP {self.name} {self.help_text}",
            f"# TYPE {self.name} counter",
        ]
        with self._lock:
            if not self._values:
                lines.append(f"{self.name} 0.0")
            for key, val in sorted(self._values.items()):
                lbl_dict = dict(key)
                lines.append(f"{self.name}{_format_labels(lbl_dict)} {val}")
        return lines


class Gauge:
    """Thread-safe instantaneous value metric."""

    def __init__(self, name: str, help_text: str, label_names: Optional[Sequence[str]] = None) -> None:
        self.name = name
        self.help_text = help_text
        self.label_names = tuple(label_names or ())
        self._values: Dict[Tuple[Tuple[str, str], ...], float] = {}
        self._lock = threading.Lock()

    def _get_key(self, labels: Dict[str, str]) -> Tuple[Tuple[str, str], ...]:
        return tuple((k, str(labels.get(k, ""))) for k in self.label_names)

    def set(self, value: float, labels: Optional[Dict[str, str]] = None) -> None:
        """Set gauge to an exact value."""
        key = self._get_key(labels or {})
        with self._lock:
            self._values[key] = float(value)

    def inc(self, amount: float = 1.0, labels: Optional[Dict[str, str]] = None) -> None:
        """Increment gauge value."""
        key = self._get_key(labels or {})
        with self._lock:
            self._values[key] = self._values.get(key, 0.0) + amount

    def dec(self, amount: float = 1.0, labels: Optional[Dict[str, str]] = None) -> None:
        """Decrement gauge value."""
        key = self._get_key(labels or {})
        with self._lock:
            self._values[key] = self._values.get(key, 0.0) - amount

    def get(self, labels: Optional[Dict[str, str]] = None) -> float:
        """Retrieve current value."""
        key = self._get_key(labels or {})
        with self._lock:
            return self._values.get(key, 0.0)

    def export(self) -> List[str]:
        """Format metric into OpenMetrics lines."""
        lines = [
            f"# HELP {self.name} {self.help_text}",
            f"# TYPE {self.name} gauge",
        ]
        with self._lock:
            if not self._values:
                lines.append(f"{self.name} 0.0")
            for key, val in sorted(self._values.items()):
                lbl_dict = dict(key)
                lines.append(f"{self.name}{_format_labels(lbl_dict)} {val}")
        return lines


class Histogram:
    """Thread-safe statistical distribution tracker with predefined buckets."""

    DEFAULT_BUCKETS: Tuple[float, ...] = (
        0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0
    )

    def __init__(
        self,
        name: str,
        help_text: str,
        label_names: Optional[Sequence[str]] = None,
        buckets: Optional[Sequence[float]] = None,
    ) -> None:
        self.name = name
        self.help_text = help_text
        self.label_names = tuple(label_names or ())
        b_list = sorted(list(buckets if buckets is not None else self.DEFAULT_BUCKETS))
        self.buckets = tuple(b_list)
        # key -> (bucket_counts: Dict[float, int], sum: float, count: int)
        self._data: Dict[Tuple[Tuple[str, str], ...], Tuple[Dict[float, int], float, int]] = {}
        self._lock = threading.Lock()

    def _get_key(self, labels: Dict[str, str]) -> Tuple[Tuple[str, str], ...]:
        return tuple((k, str(labels.get(k, ""))) for k in self.label_names)

    def observe(self, value: float, labels: Optional[Dict[str, str]] = None) -> None:
        """Observe a sample value."""
        val = float(value)
        key = self._get_key(labels or {})
        with self._lock:
            if key not in self._data:
                b_counts = {b: 0 for b in self.buckets}
                total_sum = 0.0
                total_count = 0
            else:
                b_counts, total_sum, total_count = self._data[key]
                b_counts = dict(b_counts)

            for b in self.buckets:
                if val <= b:
                    b_counts[b] += 1

            total_sum += val
            total_count += 1
            self._data[key] = (b_counts, total_sum, total_count)

    def export(self) -> List[str]:
        """Format metric into OpenMetrics histogram lines."""
        lines = [
            f"# HELP {self.name} {self.help_text}",
            f"# TYPE {self.name} histogram",
        ]
        with self._lock:
            if not self._data:
                for b in self.buckets:
                    lines.append(f'{self.name}_bucket{{le="{b}"}} 0')
                lines.append(f'{self.name}_bucket{{le="+Inf"}} 0')
                lines.append(f"{self.name}_sum 0.0")
                lines.append(f"{self.name}_count 0")
            for key, (b_counts, total_sum, total_count) in sorted(self._data.items()):
                base_labels = dict(key)
                for b in self.buckets:
                    lbls = dict(base_labels)
                    lbls["le"] = str(b)
                    lines.append(f"{self.name}_bucket{_format_labels(lbls)} {b_counts.get(b, 0)}")
                # +Inf bucket equals total_count
                inf_lbls = dict(base_labels)
                inf_lbls["le"] = "+Inf"
                lines.append(f"{self.name}_bucket{_format_labels(inf_lbls)} {total_count}")
                lines.append(f"{self.name}_sum{_format_labels(base_labels)} {total_sum}")
                lines.append(f"{self.name}_count{_format_labels(base_labels)} {total_count}")
        return lines


class MetricsRegistry:
    """Central registry and exporter for OpenMetrics/Prometheus telemetry."""

    def __init__(self) -> None:
        self._counters: Dict[str, Counter] = {}
        self._gauges: Dict[str, Gauge] = {}
        self._histograms: Dict[str, Histogram] = {}
        self._lock = threading.Lock()

        # Initialize canonical proxy metrics
        self.http_requests_total = self.register_counter(
            "proxy_http_requests_total",
            "Total number of HTTP requests processed by the reverse proxy",
            label_names=["method", "status", "upstream"],
        )
        self.http_request_duration_seconds = self.register_histogram(
            "proxy_http_request_duration_seconds",
            "HTTP request latency in seconds",
            label_names=["method", "status"],
        )
        self.http_active_connections = self.register_gauge(
            "proxy_http_active_connections",
            "Current number of active client connections",
            label_names=["upstream"],
        )
        self.upstream_health_status = self.register_gauge(
            "proxy_upstream_health_status",
            "Health status of upstream nodes (1=healthy, 0=unhealthy)",
            label_names=["upstream"],
        )
        self.rate_limit_exceeded_total = self.register_counter(
            "proxy_rate_limit_exceeded_total",
            "Total number of rate limit rejections (429)",
            label_names=["key_type"],
        )
        self.circuit_breaker_state = self.register_gauge(
            "proxy_circuit_breaker_state",
            "Circuit breaker state value (0=CLOSED, 1=HALF_OPEN, 2=OPEN)",
            label_names=["upstream", "state"],
        )
        self.payload_bytes_total = self.register_counter(
            "proxy_payload_bytes_total",
            "Total bytes transferred across proxy",
            label_names=["direction"],
        )

    def register_counter(self, name: str, help_text: str, label_names: Optional[Sequence[str]] = None) -> Counter:
        with self._lock:
            if name in self._counters:
                return self._counters[name]
            c = Counter(name, help_text, label_names)
            self._counters[name] = c
            return c

    def register_gauge(self, name: str, help_text: str, label_names: Optional[Sequence[str]] = None) -> Gauge:
        with self._lock:
            if name in self._gauges:
                return self._gauges[name]
            g = Gauge(name, help_text, label_names)
            self._gauges[name] = g
            return g

    def register_histogram(
        self,
        name: str,
        help_text: str,
        label_names: Optional[Sequence[str]] = None,
        buckets: Optional[Sequence[float]] = None,
    ) -> Histogram:
        with self._lock:
            if name in self._histograms:
                return self._histograms[name]
            h = Histogram(name, help_text, label_names, buckets)
            self._histograms[name] = h
            return h

    def export(self) -> str:
        """Export all registered metrics in OpenMetrics text format."""
        all_lines: List[str] = []
        with self._lock:
            for c in self._counters.values():
                all_lines.extend(c.export())
            for g in self._gauges.values():
                all_lines.extend(g.export())
            for h in self._histograms.values():
                all_lines.extend(h.export())
        all_lines.append("# EOF")
        return "\n".join(all_lines) + "\n"

    def generate_response(self) -> Tuple[str, str]:
        """Return metric text body and OpenMetrics content type."""
        return self.export(), "application/openmetrics-text; version=1.0.0; charset=utf-8"


# Global singleton registry
metrics_registry = MetricsRegistry()
