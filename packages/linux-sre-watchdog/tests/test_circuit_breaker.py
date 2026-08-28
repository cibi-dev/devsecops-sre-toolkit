"""Unit tests for anti-flapping CircuitBreaker."""

from __future__ import annotations

import time
from pathlib import Path
from unittest.mock import patch

import pytest

from watchdog.circuit_breaker import (
    CircuitBreaker,
    CircuitBreakerConfig,
    CircuitBreakerState,
)


def test_initial_state_closed(tmp_path: Path):
    cb = CircuitBreaker(state_file=tmp_path / "cb.json")
    assert cb.get_state("restart_nginx") == CircuitBreakerState.CLOSED
    assert cb.can_execute("restart_nginx") is True


def test_success_keeps_closed(tmp_path: Path):
    cb = CircuitBreaker(state_file=tmp_path / "cb.json")
    cb.record_success("restart_nginx")
    assert cb.get_state("restart_nginx") == CircuitBreakerState.CLOSED
    metrics = cb.get_metrics("restart_nginx")
    assert metrics["success_count"] == 1
    assert metrics["consecutive_failures"] == 0


def test_three_strikes_in_window_trips_to_open(tmp_path: Path):
    config = CircuitBreakerConfig(failure_threshold=3, window_seconds=300.0, cooldown_seconds=300.0)
    cb = CircuitBreaker(config=config, state_file=tmp_path / "cb.json")

    action = "restart_service:api"

    # Strike 1
    cb.record_failure(action, "Failure 1")
    assert cb.get_state(action) == CircuitBreakerState.CLOSED
    assert cb.can_execute(action) is True

    # Strike 2
    cb.record_failure(action, "Failure 2")
    assert cb.get_state(action) == CircuitBreakerState.CLOSED
    assert cb.can_execute(action) is True

    # Strike 3 (trips breaker)
    cb.record_failure(action, "Failure 3")
    assert cb.get_state(action) == CircuitBreakerState.OPEN
    assert cb.can_execute(action) is False


def test_open_state_blocks_execution(tmp_path: Path):
    config = CircuitBreakerConfig(failure_threshold=3, window_seconds=300.0, cooldown_seconds=300.0)
    cb = CircuitBreaker(config=config, state_file=tmp_path / "cb.json")
    action = "clear_cache"

    for _ in range(3):
        cb.record_failure(action)

    assert cb.can_execute(action) is False
    assert cb.get_state(action) == CircuitBreakerState.OPEN


def test_cooldown_transitions_open_to_half_open(tmp_path: Path):
    config = CircuitBreakerConfig(failure_threshold=3, window_seconds=300.0, cooldown_seconds=10.0)
    cb = CircuitBreaker(config=config, state_file=tmp_path / "cb.json")
    action = "reap_zombies"

    now = 1000.0
    with patch("time.time", return_value=now):
        for _ in range(3):
            cb.record_failure(action)
        assert cb.get_state(action) == CircuitBreakerState.OPEN

    # Advance time by 5 seconds (still in cooldown)
    with patch("time.time", return_value=now + 5.0):
        assert cb.get_state(action) == CircuitBreakerState.OPEN
        assert cb.can_execute(action) is False

    # Advance time by 11 seconds (cooldown expired)
    with patch("time.time", return_value=now + 11.0):
        assert cb.get_state(action) == CircuitBreakerState.HALF_OPEN
        # Probe permitted
        assert cb.can_execute(action) is True


def test_half_open_success_recovers_to_closed(tmp_path: Path):
    config = CircuitBreakerConfig(failure_threshold=3, window_seconds=300.0, cooldown_seconds=10.0)
    cb = CircuitBreaker(config=config, state_file=tmp_path / "cb.json")
    action = "reap_zombies"

    now = 1000.0
    with patch("time.time", return_value=now):
        for _ in range(3):
            cb.record_failure(action)

    with patch("time.time", return_value=now + 15.0):
        # In HALF_OPEN, trial succeeds
        cb.record_success(action)
        assert cb.get_state(action) == CircuitBreakerState.CLOSED
        assert cb.can_execute(action) is True


def test_half_open_failure_immediately_reopens(tmp_path: Path):
    config = CircuitBreakerConfig(failure_threshold=3, window_seconds=300.0, cooldown_seconds=10.0)
    cb = CircuitBreaker(config=config, state_file=tmp_path / "cb.json")
    action = "reap_zombies"

    now = 1000.0
    with patch("time.time", return_value=now):
        for _ in range(3):
            cb.record_failure(action)

    # After cooldown, trial fails
    with patch("time.time", return_value=now + 15.0):
        cb.record_failure(action, "Trial failed")
        assert cb.get_state(action) == CircuitBreakerState.OPEN
        assert cb.can_execute(action) is False


def test_window_pruning_expires_old_failures(tmp_path: Path):
    config = CircuitBreakerConfig(failure_threshold=3, window_seconds=60.0, cooldown_seconds=300.0)
    cb = CircuitBreaker(config=config, state_file=tmp_path / "cb.json")
    action = "trim_journal"

    now = 1000.0
    with patch("time.time", return_value=now):
        cb.record_failure(action)
        cb.record_failure(action)

    # Advance time past 60s window
    with patch("time.time", return_value=now + 70.0):
        # 3rd failure happens after 1st and 2nd expired, so only 1 active failure
        cb.record_failure(action)
        assert cb.get_state(action) == CircuitBreakerState.CLOSED
        metrics = cb.get_metrics(action)
        assert metrics["recent_failures_in_window"] == 1


def test_reset_action_and_all_actions(tmp_path: Path):
    cb = CircuitBreaker(state_file=tmp_path / "cb.json")
    cb.record_failure("action_a")
    cb.record_failure("action_a")
    cb.record_failure("action_a")
    cb.record_failure("action_b")

    assert cb.get_state("action_a") == CircuitBreakerState.OPEN

    # Reset single action
    cb.reset("action_a")
    assert cb.get_state("action_a") == CircuitBreakerState.CLOSED

    # Reset all
    cb.record_failure("action_b")
    cb.record_failure("action_b")
    cb.record_failure("action_b")
    assert cb.get_state("action_b") == CircuitBreakerState.OPEN
    cb.reset()
    assert cb.get_state("action_b") == CircuitBreakerState.CLOSED


def test_corrupt_state_file_recovery(tmp_path: Path):
    state_file = tmp_path / "corrupt_cb.json"
    state_file.write_text("INVALID_JSON_CONTENT{{{", encoding="utf-8")

    cb = CircuitBreaker(state_file=state_file)
    assert cb.can_execute("any_action") is True
    cb.record_success("any_action")
    assert cb.get_state("any_action") == CircuitBreakerState.CLOSED
