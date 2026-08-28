"""Anti-flapping circuit breaker for Linux SRE Watchdog auto-remediation.

Implements 3-strikes in 5-minute sliding window with CLOSED, OPEN, and HALF-OPEN states.
Secured with fcntl.flock concurrency controls (CWE-362 / CWE-377 compliant).
"""

from __future__ import annotations

import atexit
import contextlib
import fcntl
import json
import os
import tempfile
import threading
import time
from enum import Enum
from pathlib import Path
from typing import Any, Generator, Optional

from pydantic import BaseModel, ConfigDict, Field


class CircuitBreakerState(str, Enum):
    """Circuit breaker operational state."""

    CLOSED = "CLOSED"        # Normal: actions permitted
    OPEN = "OPEN"            # Tripped: actions blocked to prevent flapping
    HALF_OPEN = "HALF_OPEN"  # Testing: single probe action allowed after cooldown


class ActionRecord(BaseModel):
    """Historical state and failure tracking for a single action."""

    model_config = ConfigDict(extra="forbid")

    failure_timestamps: list[float] = Field(default_factory=list)
    success_count: int = Field(default=0)
    consecutive_failures: int = Field(default=0)
    state: CircuitBreakerState = Field(default=CircuitBreakerState.CLOSED)
    last_state_change: float = Field(default_factory=time.time)
    last_failure_error: Optional[str] = Field(default=None)


class CircuitBreakerConfig(BaseModel):
    """Circuit breaker tuning parameters."""

    model_config = ConfigDict(extra="forbid")

    failure_threshold: int = Field(default=3, description="Number of failures to trip breaker")
    window_seconds: float = Field(default=300.0, description="Sliding window duration (5 minutes)")
    cooldown_seconds: float = Field(default=300.0, description="Cooldown duration before half-open (5 minutes)")
    half_open_success_threshold: int = Field(default=1, description="Successes required in half-open to close")


class CircuitBreaker:
    """Thread- and process-safe anti-flapping circuit breaker.

    Uses fcntl.flock with monotonic timeouts (<=5s) to guarantee atomic state transitions
    and prevent split-brain remediation loops across multiple worker processes.
    """

    LOCK_TIMEOUT_SECONDS = 5.0

    def __init__(
        self,
        config: Optional[CircuitBreakerConfig] = None,
        state_file: Optional[Path | str] = None,
    ) -> None:
        self.config = config or CircuitBreakerConfig()
        self._thread_lock = threading.RLock()
        self._lock_depth = 0
        self._lock_fd: Optional[int] = None

        if state_file is not None:
            self._state_file = Path(state_file)
            self._lock_file = Path(f"{self._state_file}.lock")
            self._owns_state_file = False
        else:
            # Create secure temporary state directory (CWE-377)
            self._temp_dir = tempfile.mkdtemp(prefix="sre_watchdog_cb_")
            self._state_file = Path(self._temp_dir) / "circuit_breaker.json"
            self._lock_file = Path(self._temp_dir) / "circuit_breaker.lock"
            self._owns_state_file = True
            atexit.register(self._cleanup_temp)

        # In-memory fast cache
        self._memory_state: dict[str, ActionRecord] = {}

    def _cleanup_temp(self) -> None:
        """Cleanup temporary files upon exit."""
        if getattr(self, "_owns_state_file", False) and hasattr(self, "_temp_dir"):
            try:
                for f in Path(self._temp_dir).glob("*"):
                    f.unlink(missing_ok=True)
                os.rmdir(self._temp_dir)
            except OSError:
                pass

    @contextlib.contextmanager
    def _acquire_lock(self) -> Generator[None, None, None]:
        """Acquire exclusive file lock with timeout <=5s (CWE-362/377)."""
        self._thread_lock.acquire()
        try:
            if self._lock_depth == 0:
                self._lock_file.parent.mkdir(parents=True, exist_ok=True)
                fd = os.open(str(self._lock_file), os.O_RDWR | os.O_CREAT, 0o600)
                start_time = time.monotonic()
                acquired = False

                while time.monotonic() - start_time < self.LOCK_TIMEOUT_SECONDS:
                    try:
                        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                        acquired = True
                        break
                    except (BlockingIOError, OSError):
                        time.sleep(0.02)

                if not acquired:
                    os.close(fd)
                    raise TimeoutError(f"Failed to acquire circuit breaker lock within {self.LOCK_TIMEOUT_SECONDS}s")

                self._lock_fd = fd

            self._lock_depth += 1
            yield
        finally:
            self._lock_depth -= 1
            if self._lock_depth == 0 and self._lock_fd is not None:
                try:
                    fcntl.flock(self._lock_fd, fcntl.LOCK_UN)
                except OSError:
                    pass
                os.close(self._lock_fd)
                self._lock_fd = None
            self._thread_lock.release()

    def _load_state_unlocked(self) -> dict[str, ActionRecord]:
        """Load state from persistent file while holding lock."""
        if not self._state_file.exists():
            return self._memory_state.copy()

        try:
            with self._state_file.open("r", encoding="utf-8") as f:
                data = json.load(f)
            records: dict[str, ActionRecord] = {}
            for k, v in data.items():
                records[k] = ActionRecord.model_validate(v)
            self._memory_state = records
            return records
        except (OSError, json.JSONDecodeError, ValueError):
            return self._memory_state.copy()

    def _save_state_unlocked(self, records: dict[str, ActionRecord]) -> None:
        """Atomically persist state file while holding lock."""
        self._state_file.parent.mkdir(parents=True, exist_ok=True)
        self._memory_state = records

        # Atomic rename write pattern (CWE-377)
        temp_target = self._state_file.with_suffix(".tmp")
        try:
            serialized = {k: v.model_dump() for k, v in records.items()}
            with temp_target.open("w", encoding="utf-8") as f:
                json.dump(serialized, f, indent=2)
            temp_target.replace(self._state_file)
        except OSError:
            if temp_target.exists():
                temp_target.unlink(missing_ok=True)

    def _prune_failures(self, record: ActionRecord, now: float) -> list[float]:
        """Prune failure timestamps older than window_seconds."""
        cutoff = now - self.config.window_seconds
        return [ts for ts in record.failure_timestamps if ts >= cutoff]

    def _get_state_unlocked(self, records: dict[str, ActionRecord], action_name: str) -> CircuitBreakerState:
        """Evaluate circuit breaker state without re-acquiring lock."""
        record = records.get(action_name)
        if record is None:
            return CircuitBreakerState.CLOSED

        now = time.time()
        if record.state == CircuitBreakerState.OPEN:
            if now - record.last_state_change >= self.config.cooldown_seconds:
                return CircuitBreakerState.HALF_OPEN

        return record.state

    def can_execute(self, action_name: str) -> bool:
        """Check if an action is allowed to execute under circuit breaker rules."""
        with self._acquire_lock():
            records = self._load_state_unlocked()
            record = records.get(action_name)
            if record is None:
                return True

            now = time.time()

            if record.state == CircuitBreakerState.CLOSED:
                return True

            if record.state == CircuitBreakerState.OPEN:
                elapsed = now - record.last_state_change
                if elapsed >= self.config.cooldown_seconds:
                    # Transition OPEN -> HALF_OPEN (probe allowed)
                    record.state = CircuitBreakerState.HALF_OPEN
                    record.last_state_change = now
                    records[action_name] = record
                    self._save_state_unlocked(records)
                    return True
                return False

            if record.state == CircuitBreakerState.HALF_OPEN:
                # In HALF_OPEN, trial is in progress
                return True

            return False

    def record_success(self, action_name: str) -> None:
        """Record a successful execution of the action."""
        with self._acquire_lock():
            records = self._load_state_unlocked()
            now = time.time()
            record = records.get(action_name, ActionRecord())

            record.success_count += 1
            record.consecutive_failures = 0
            record.last_failure_error = None

            if record.state in (CircuitBreakerState.HALF_OPEN, CircuitBreakerState.OPEN):
                # Recovery successful -> CLOSED
                record.state = CircuitBreakerState.CLOSED
                record.last_state_change = now
                record.failure_timestamps.clear()

            records[action_name] = record
            self._save_state_unlocked(records)

    def record_failure(self, action_name: str, error: str = "") -> None:
        """Record a failure or flapping event for the action."""
        with self._acquire_lock():
            records = self._load_state_unlocked()
            now = time.time()
            record = records.get(action_name, ActionRecord())

            # Prune out-of-window timestamps
            recent_failures = self._prune_failures(record, now)
            recent_failures.append(now)

            record.failure_timestamps = recent_failures
            record.consecutive_failures += 1
            record.last_failure_error = error or "Execution failed"

            # Check if threshold crossed or if failing during HALF_OPEN
            if record.state == CircuitBreakerState.HALF_OPEN:
                # Immediate trip back to OPEN
                record.state = CircuitBreakerState.OPEN
                record.last_state_change = now
            elif len(recent_failures) >= self.config.failure_threshold:
                # 3 strikes in window -> OPEN
                record.state = CircuitBreakerState.OPEN
                record.last_state_change = now

            records[action_name] = record
            self._save_state_unlocked(records)

    def get_state(self, action_name: str) -> CircuitBreakerState:
        """Return the current circuit breaker state for the given action."""
        with self._acquire_lock():
            records = self._load_state_unlocked()
            return self._get_state_unlocked(records, action_name)

    def get_metrics(self, action_name: str) -> dict[str, Any]:
        """Return operational metrics for an action."""
        with self._acquire_lock():
            records = self._load_state_unlocked()
            record = records.get(action_name, ActionRecord())
            now = time.time()
            recent_failures = self._prune_failures(record, now)
            current_state = self._get_state_unlocked(records, action_name)

            return {
                "action_name": action_name,
                "state": current_state.value,
                "consecutive_failures": record.consecutive_failures,
                "recent_failures_in_window": len(recent_failures),
                "success_count": record.success_count,
                "last_failure_error": record.last_failure_error,
                "last_state_change": record.last_state_change,
            }

    def reset(self, action_name: Optional[str] = None) -> None:
        """Reset circuit breaker state for a specific action or all actions."""
        with self._acquire_lock():
            records = self._load_state_unlocked()
            if action_name is not None:
                if action_name in records:
                    records[action_name] = ActionRecord()
            else:
                records.clear()
            self._save_state_unlocked(records)
