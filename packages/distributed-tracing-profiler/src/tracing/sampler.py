"""Deterministic and adaptive trace samplers.

Provides sampling strategies conforming to distributed tracing standards:
- AlwaysOnSampler: 100% trace capture
- AlwaysOffSampler: 0% trace capture (disabled)
- RatioBasedSampler: Deterministic trace_id hashing for consistent distributed sampling
- RateLimitingSampler: Token-bucket adaptive rate limiter with thread-safety
- ParentBasedSampler: Inherits upstream sampling decisions

DevSecOps Guardrails:
- Thread-safe locks on mutable rate limiter state
- CWE-400 Anti-DoS: Prevents trace storage explosion through controlled sampling rates
"""

from __future__ import annotations

import abc
import math
import threading
import time
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from tracing.context import SpanContext
    from tracing.span import SpanKind

MAX_INT64 = 0xFFFFFFFFFFFFFFFF


@dataclass(frozen=True, slots=True)
class SamplingDecision:
    """Immutable result of a sampling decision."""

    is_sampled: bool
    attributes: dict[str, Any] = field(default_factory=dict)
    tracestate: str | None = None


class Sampler(abc.ABC):
    """Abstract base class for all trace sampling strategies."""

    @abc.abstractmethod
    def should_sample(
        self,
        parent_context: SpanContext | None,
        trace_id: str,
        span_name: str,
        span_kind: SpanKind | None = None,
        attributes: Mapping[str, Any] | None = None,
    ) -> SamplingDecision:
        """Evaluate whether a trace should be sampled."""
        raise NotImplementedError

    @abc.abstractmethod
    def get_description(self) -> str:
        """Return a human-readable description of the sampler."""
        raise NotImplementedError

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__}: {self.get_description()}>"


class AlwaysOnSampler(Sampler):
    """Always samples every trace (100% sampling rate)."""

    def should_sample(
        self,
        parent_context: SpanContext | None,
        trace_id: str,
        span_name: str,
        span_kind: SpanKind | None = None,
        attributes: Mapping[str, Any] | None = None,
    ) -> SamplingDecision:
        return SamplingDecision(
            is_sampled=True,
            attributes={"sampler.type": "AlwaysOnSampler"},
            tracestate=parent_context.tracestate if parent_context else None,
        )

    def get_description(self) -> str:
        return "AlwaysOnSampler"


class AlwaysOffSampler(Sampler):
    """Never samples any trace (0% sampling rate)."""

    def should_sample(
        self,
        parent_context: SpanContext | None,
        trace_id: str,
        span_name: str,
        span_kind: SpanKind | None = None,
        attributes: Mapping[str, Any] | None = None,
    ) -> SamplingDecision:
        return SamplingDecision(
            is_sampled=False,
            attributes={"sampler.type": "AlwaysOffSampler"},
            tracestate=parent_context.tracestate if parent_context else None,
        )

    def get_description(self) -> str:
        return "AlwaysOffSampler"


class RatioBasedSampler(Sampler):
    """Deterministic ratio-based sampler using trace_id hashing.

    Guarantees that all downstream services in a distributed trace will make
    the exact same sampling decision for the same trace_id.
    """

    def __init__(self, ratio: float) -> None:
        if not (0.0 <= ratio <= 1.0):
            raise ValueError(f"Sampling ratio must be between 0.0 and 1.0, got {ratio}")
        self.ratio = ratio
        # Threshold calculation based on 64-bit integer space
        self._id_upper_bound = int(ratio * MAX_INT64)

    def should_sample(
        self,
        parent_context: SpanContext | None,
        trace_id: str,
        span_name: str,
        span_kind: SpanKind | None = None,
        attributes: Mapping[str, Any] | None = None,
    ) -> SamplingDecision:
        if self.ratio <= 0.0:
            return SamplingDecision(
                is_sampled=False,
                attributes={"sampler.type": "RatioBasedSampler", "sampler.ratio": 0.0},
                tracestate=parent_context.tracestate if parent_context else None,
            )
        if self.ratio >= 1.0:
            return SamplingDecision(
                is_sampled=True,
                attributes={"sampler.type": "RatioBasedSampler", "sampler.ratio": 1.0},
                tracestate=parent_context.tracestate if parent_context else None,
            )

        # Extract last 16 hex chars (8 bytes) of trace_id for deterministic hashing
        try:
            sample_part = trace_id[-16:] if len(trace_id) >= 16 else trace_id
            trace_int = int(sample_part, 16)
        except (ValueError, TypeError):
            trace_int = 0

        is_sampled = trace_int < self._id_upper_bound
        return SamplingDecision(
            is_sampled=is_sampled,
            attributes={
                "sampler.type": "RatioBasedSampler",
                "sampler.ratio": self.ratio,
            },
            tracestate=parent_context.tracestate if parent_context else None,
        )

    def get_description(self) -> str:
        return f"RatioBasedSampler{{ratio={self.ratio:.4f}}}"


class RateLimitingSampler(Sampler):
    """Adaptive token-bucket rate limiter.

    Limits traces to a fixed maximum rate per second with support for bursts.
    Thread-safe implementation.
    """

    def __init__(
        self, max_traces_per_second: float, burst_size: int | None = None
    ) -> None:
        if max_traces_per_second <= 0:
            raise ValueError(
                f"max_traces_per_second must be positive, got {max_traces_per_second}"
            )
        self.rate = max_traces_per_second
        self.capacity = float(
            burst_size if burst_size is not None else max(1, int(math.ceil(max_traces_per_second)))
        )
        self._tokens = self.capacity
        self._last_update = time.monotonic()
        self._lock = threading.Lock()

    def should_sample(
        self,
        parent_context: SpanContext | None,
        trace_id: str,
        span_name: str,
        span_kind: SpanKind | None = None,
        attributes: Mapping[str, Any] | None = None,
    ) -> SamplingDecision:
        with self._lock:
            now = time.monotonic()
            elapsed = now - self._last_update
            self._last_update = now

            # Replenish tokens
            self._tokens = min(self.capacity, self._tokens + elapsed * self.rate)

            if self._tokens >= 1.0:
                self._tokens -= 1.0
                is_sampled = True
            else:
                is_sampled = False

        return SamplingDecision(
            is_sampled=is_sampled,
            attributes={
                "sampler.type": "RateLimitingSampler",
                "sampler.rate_limit": self.rate,
            },
            tracestate=parent_context.tracestate if parent_context else None,
        )

    def get_description(self) -> str:
        return f"RateLimitingSampler{{rate={self.rate}/s, capacity={self.capacity}}}"


class ParentBasedSampler(Sampler):
    """Sampler that respects upstream parent sampling decisions.

    If parent exists, adheres to its is_sampled flag.
    If no parent exists (root span), delegates to root_sampler.
    """

    def __init__(self, root_sampler: Sampler | None = None) -> None:
        self.root_sampler = root_sampler or AlwaysOnSampler()

    def should_sample(
        self,
        parent_context: SpanContext | None,
        trace_id: str,
        span_name: str,
        span_kind: SpanKind | None = None,
        attributes: Mapping[str, Any] | None = None,
    ) -> SamplingDecision:
        if parent_context is not None:
            return SamplingDecision(
                is_sampled=parent_context.is_sampled,
                attributes={"sampler.type": "ParentBasedSampler(Inherited)"},
                tracestate=parent_context.tracestate,
            )

        return self.root_sampler.should_sample(
            parent_context=None,
            trace_id=trace_id,
            span_name=span_name,
            span_kind=span_kind,
            attributes=attributes,
        )

    def get_description(self) -> str:
        return f"ParentBasedSampler{{root={self.root_sampler.get_description()}}}"
