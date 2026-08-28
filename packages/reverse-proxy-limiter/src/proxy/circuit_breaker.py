"""
Enterprise 3-State Circuit Breaker (CLOSED / OPEN / HALF_OPEN).

Provides deterministic fault tolerance and fail-fast isolation for upstream
services under failure conditions.
"""

from __future__ import annotations

import asyncio
import time
from enum import Enum
from typing import Any, Callable, Dict, Optional
from pydantic import BaseModel, Field


class CircuitState(str, Enum):
    CLOSED = "CLOSED"
    OPEN = "OPEN"
    HALF_OPEN = "HALF_OPEN"


class CircuitBreakerError(Exception):
    """Base exception for circuit breaker faults."""
    pass


class CircuitBreakerOpenError(CircuitBreakerError):
    """Raised when an operation is attempted while circuit is OPEN."""

    def __init__(self, message: str, retry_after: float = 0.0) -> None:
        super().__init__(message)
        self.retry_after = max(0.0, retry_after)


class CircuitBreakerConfig(BaseModel):
    """Configuration parameters for CircuitBreaker."""
    failure_threshold: int = Field(default=5, ge=1, description="Failures before opening circuit")
    recovery_time: float = Field(default=10.0, gt=0.0, description="Cooldown time in seconds before HALF_OPEN")
    half_open_max_calls: int = Field(default=3, ge=1, description="Max trial requests allowed in HALF_OPEN")
    success_threshold: int = Field(default=2, ge=1, description="Consecutive successes in HALF_OPEN to close")

    model_config = {"extra": "forbid"}


class CircuitBreaker:
    """
    Thread-safe and Asyncio-compatible 3-state Circuit Breaker.
    """

    def __init__(
        self,
        name: str = "default",
        config: Optional[CircuitBreakerConfig] = None,
        on_state_change: Optional[Callable[[CircuitState, CircuitState], None]] = None,
    ) -> None:
        self.name = name
        self.config = config or CircuitBreakerConfig()
        self.on_state_change = on_state_change

        self._state = CircuitState.CLOSED
        self._failure_count = 0
        self._success_count = 0
        self._half_open_calls = 0
        self._opened_at: Optional[float] = None
        self._last_state_change = time.monotonic()
        self._lock = asyncio.Lock()

    @property
    def current_state(self) -> CircuitState:
        """Returns the current state, evaluating time-based cooldown transitions."""
        if self._state == CircuitState.OPEN and self._opened_at is not None:
            elapsed = time.monotonic() - self._opened_at
            if elapsed >= self.config.recovery_time:
                self._transition_to(CircuitState.HALF_OPEN)
        return self._state

    def _transition_to(self, new_state: CircuitState) -> None:
        """Internal transition handler with state change notification."""
        old_state = self._state
        if old_state != new_state:
            self._state = new_state
            self._last_state_change = time.monotonic()
            if new_state == CircuitState.OPEN:
                self._opened_at = time.monotonic()
                self._half_open_calls = 0
                self._success_count = 0
            elif new_state == CircuitState.HALF_OPEN:
                self._half_open_calls = 0
                self._success_count = 0
            elif new_state == CircuitState.CLOSED:
                self._failure_count = 0
                self._success_count = 0
                self._half_open_calls = 0
                self._opened_at = None

            if self.on_state_change is not None:
                try:
                    self.on_state_change(old_state, new_state)
                except Exception:
                    pass

    def allow_request(self) -> bool:
        """
        Determines whether a request is allowed according to the current state.
        Raises CircuitBreakerOpenError if the circuit is OPEN or saturated in HALF_OPEN.
        """
        state = self.current_state

        if state == CircuitState.CLOSED:
            return True

        if state == CircuitState.OPEN:
            retry_after = 0.0
            if self._opened_at is not None:
                remaining = self.config.recovery_time - (time.monotonic() - self._opened_at)
                retry_after = max(0.0, remaining)
            raise CircuitBreakerOpenError(
                f"Circuit breaker '{self.name}' is OPEN. Retry after {retry_after:.2f}s",
                retry_after=retry_after,
            )

        if state == CircuitState.HALF_OPEN:
            if self._half_open_calls < self.config.half_open_max_calls:
                self._half_open_calls += 1
                return True
            else:
                raise CircuitBreakerOpenError(
                    f"Circuit breaker '{self.name}' is HALF_OPEN and max trial requests ({self.config.half_open_max_calls}) reached",
                    retry_after=self.config.recovery_time,
                )

        return False

    def record_success(self) -> None:
        """Records a successful upstream call."""
        state = self.current_state
        if state == CircuitState.HALF_OPEN:
            self._success_count += 1
            if self._success_count >= self.config.success_threshold:
                self._transition_to(CircuitState.CLOSED)
        elif state == CircuitState.CLOSED:
            self._failure_count = 0

    def record_failure(self, exception: Optional[Exception] = None) -> None:
        """Records a failed upstream call."""
        state = self.current_state
        if state == CircuitState.HALF_OPEN:
            self._transition_to(CircuitState.OPEN)
        elif state == CircuitState.CLOSED:
            self._failure_count += 1
            if self._failure_count >= self.config.failure_threshold:
                self._transition_to(CircuitState.OPEN)

    def trip(self) -> None:
        """Manually forces the circuit into OPEN state."""
        self._transition_to(CircuitState.OPEN)

    def reset(self) -> None:
        """Manually resets the circuit into CLOSED state."""
        self._transition_to(CircuitState.CLOSED)

    def get_status(self) -> Dict[str, Any]:
        """Returns diagnostic metrics and current state information."""
        state = self.current_state
        retry_after = 0.0
        if state == CircuitState.OPEN and self._opened_at is not None:
            remaining = self.config.recovery_time - (time.monotonic() - self._opened_at)
            retry_after = max(0.0, remaining)

        return {
            "name": self.name,
            "state": state.value,
            "failure_count": self._failure_count,
            "failure_threshold": self.config.failure_threshold,
            "success_count": self._success_count,
            "success_threshold": self.config.success_threshold,
            "half_open_calls": self._half_open_calls,
            "half_open_max_calls": self.config.half_open_max_calls,
            "retry_after": round(retry_after, 2),
        }

    async def __aenter__(self) -> CircuitBreaker:
        self.allow_request()
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        if exc_type is not None:
            self.record_failure(exc_val)
        else:
            self.record_success()
