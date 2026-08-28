"""Unit tests for sampling strategies."""

from __future__ import annotations

import time

import pytest
from tracing.context import SpanContext
from tracing.sampler import (
    AlwaysOffSampler,
    AlwaysOnSampler,
    ParentBasedSampler,
    RateLimitingSampler,
    RatioBasedSampler,
)
from tracing.span import SpanKind


def test_always_on_sampler() -> None:
    sampler = AlwaysOnSampler()
    decision = sampler.should_sample(
        parent_context=None,
        trace_id="4bf92f3577b34da6a3ce929d0e0e4736",
        span_name="op",
        span_kind=SpanKind.SERVER,
    )
    assert decision.is_sampled
    assert "AlwaysOnSampler" in sampler.get_description()
    assert "AlwaysOnSampler" in repr(sampler)


def test_always_off_sampler() -> None:
    sampler = AlwaysOffSampler()
    decision = sampler.should_sample(
        parent_context=None,
        trace_id="4bf92f3577b34da6a3ce929d0e0e4736",
        span_name="op",
        span_kind=SpanKind.SERVER,
    )
    assert not decision.is_sampled
    assert "AlwaysOffSampler" in sampler.get_description()


def test_ratio_based_sampler_boundaries() -> None:
    # 0% ratio
    sampler_0 = RatioBasedSampler(0.0)
    assert not sampler_0.should_sample(
        None, "4bf92f3577b34da6a3ce929d0e0e4736", "op"
    ).is_sampled

    # 100% ratio
    sampler_1 = RatioBasedSampler(1.0)
    assert sampler_1.should_sample(
        None, "4bf92f3577b34da6a3ce929d0e0e4736", "op"
    ).is_sampled

    # Invalid ratios
    with pytest.raises(ValueError, match="Sampling ratio must be between"):
        RatioBasedSampler(-0.1)

    with pytest.raises(ValueError, match="Sampling ratio must be between"):
        RatioBasedSampler(1.5)


def test_ratio_based_sampler_deterministic() -> None:
    sampler = RatioBasedSampler(0.5)
    tid = "4bf92f3577b34da6a3ce929d0e0e4736"

    decision1 = sampler.should_sample(None, tid, "op1")
    decision2 = sampler.should_sample(None, tid, "op2")

    # Same trace ID must always yield the exact same decision
    assert decision1.is_sampled == decision2.is_sampled


def test_rate_limiting_sampler() -> None:
    sampler = RateLimitingSampler(max_traces_per_second=10.0, burst_size=2)

    # Initial burst of 2 tokens allowed
    d1 = sampler.should_sample(None, "tid1", "op")
    d2 = sampler.should_sample(None, "tid2", "op")
    assert d1.is_sampled
    assert d2.is_sampled

    # Third immediate request should be rate limited
    d3 = sampler.should_sample(None, "tid3", "op")
    assert not d3.is_sampled

    # Wait for token replenishment (150ms -> 1.5 tokens at 10/s)
    time.sleep(0.15)
    d4 = sampler.should_sample(None, "tid4", "op")
    assert d4.is_sampled


def test_rate_limiting_sampler_invalid() -> None:
    with pytest.raises(ValueError, match="max_traces_per_second must be positive"):
        RateLimitingSampler(0)


def test_parent_based_sampler() -> None:
    root_sampler = RatioBasedSampler(0.0)  # Would reject root
    sampler = ParentBasedSampler(root_sampler=root_sampler)

    # No parent: falls back to root_sampler (rejected)
    decision_root = sampler.should_sample(None, "tid1", "op")
    assert not decision_root.is_sampled

    # Parent is sampled: should inherit sampled=True
    parent_ctx_sampled = SpanContext.create_root(is_sampled=True)
    decision_parent_sampled = sampler.should_sample(parent_ctx_sampled, "tid2", "op")
    assert decision_parent_sampled.is_sampled

    # Parent is NOT sampled: should inherit sampled=False
    parent_ctx_unsampled = SpanContext.create_root(is_sampled=False)
    decision_parent_unsampled = sampler.should_sample(
        parent_ctx_unsampled, "tid3", "op"
    )
    assert not decision_parent_unsampled.is_sampled
