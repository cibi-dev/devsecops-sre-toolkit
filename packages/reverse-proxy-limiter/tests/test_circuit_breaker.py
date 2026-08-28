"""Unit tests for 3-state Circuit Breaker (CLOSED / OPEN / HALF_OPEN)."""

import asyncio
import time
import pytest
from pydantic import ValidationError

from proxy.circuit_breaker import (
    CircuitBreaker,
    CircuitBreakerConfig,
    CircuitBreakerError,
    CircuitBreakerOpenError,
    CircuitState,
)


def test_circuit_breaker_initial_state():
    cb = CircuitBreaker("test-cb", CircuitBreakerConfig(failure_threshold=3, recovery_time=1.0))
    assert cb.current_state == CircuitState.CLOSED
    assert cb.allow_request() is True
    status = cb.get_status()
    assert status["state"] == "CLOSED"
    assert status["failure_count"] == 0


def test_circuit_breaker_transitions_to_open():
    cb = CircuitBreaker("test-cb", CircuitBreakerConfig(failure_threshold=3, recovery_time=2.0))
    
    cb.record_failure()
    assert cb.current_state == CircuitState.CLOSED
    cb.record_failure()
    assert cb.current_state == CircuitState.CLOSED
    cb.record_failure()  # 3rd failure trips threshold
    assert cb.current_state == CircuitState.OPEN

    with pytest.raises(CircuitBreakerOpenError) as exc_info:
        cb.allow_request()
    assert "is OPEN" in str(exc_info.value)
    assert exc_info.value.retry_after > 0


def test_circuit_breaker_cooldown_to_half_open():
    cb = CircuitBreaker(
        "test-cb",
        CircuitBreakerConfig(failure_threshold=2, recovery_time=0.1, half_open_max_calls=2),
    )
    cb.record_failure()
    cb.record_failure()
    assert cb.current_state == CircuitState.OPEN

    time.sleep(0.12)
    # State should evaluate to HALF_OPEN
    assert cb.current_state == CircuitState.HALF_OPEN
    assert cb.allow_request() is True
    assert cb.allow_request() is True
    # 3rd request in HALF_OPEN exceeds half_open_max_calls
    with pytest.raises(CircuitBreakerOpenError):
        cb.allow_request()


def test_circuit_breaker_half_open_success_recovery():
    cb = CircuitBreaker(
        "test-cb",
        CircuitBreakerConfig(
            failure_threshold=2,
            recovery_time=0.05,
            half_open_max_calls=3,
            success_threshold=2,
        ),
    )
    cb.record_failure()
    cb.record_failure()
    assert cb.current_state == CircuitState.OPEN

    time.sleep(0.06)
    assert cb.current_state == CircuitState.HALF_OPEN

    cb.record_success()
    assert cb.current_state == CircuitState.HALF_OPEN
    cb.record_success()  # Reaches success_threshold of 2
    assert cb.current_state == CircuitState.CLOSED
    assert cb.allow_request() is True


def test_circuit_breaker_half_open_failure_reopens():
    cb = CircuitBreaker(
        "test-cb",
        CircuitBreakerConfig(failure_threshold=2, recovery_time=0.05),
    )
    cb.record_failure()
    cb.record_failure()
    assert cb.current_state == CircuitState.OPEN

    time.sleep(0.06)
    assert cb.current_state == CircuitState.HALF_OPEN

    cb.record_failure()  # Any failure in HALF_OPEN immediately reopens
    assert cb.current_state == CircuitState.OPEN


def test_circuit_breaker_manual_trip_and_reset():
    cb = CircuitBreaker("manual-cb")
    assert cb.current_state == CircuitState.CLOSED
    cb.trip()
    assert cb.current_state == CircuitState.OPEN
    cb.reset()
    assert cb.current_state == CircuitState.CLOSED
    assert cb.allow_request() is True


def test_circuit_breaker_callback():
    state_changes = []

    def on_change(old_state: CircuitState, new_state: CircuitState):
        state_changes.append((old_state, new_state))

    cb = CircuitBreaker(
        "callback-cb",
        CircuitBreakerConfig(failure_threshold=1, recovery_time=0.05),
        on_state_change=on_change,
    )
    cb.record_failure()
    assert len(state_changes) == 1
    assert state_changes[0] == (CircuitState.CLOSED, CircuitState.OPEN)


@pytest.mark.asyncio
async def test_circuit_breaker_async_context_manager():
    cb = CircuitBreaker("async-cb", CircuitBreakerConfig(failure_threshold=2))

    async with cb:
        pass  # Success recorded
    assert cb.current_state == CircuitState.CLOSED

    with pytest.raises(RuntimeError):
        async with cb:
            raise RuntimeError("Upstream failed")

    assert cb._failure_count == 1


def test_circuit_breaker_config_validation():
    with pytest.raises(ValidationError):
        CircuitBreakerConfig(failure_threshold=0)

    with pytest.raises(ValidationError):
        CircuitBreakerConfig(recovery_time=-1.0)

    with pytest.raises(ValidationError):
        CircuitBreakerConfig(extra_field="invalid")  # extra='forbid'
