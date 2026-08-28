"""Tests for Safety Guard and Dead-Man Switch module."""

from __future__ import annotations

import os
import signal
import time
from typing import Any
import pytest

from chaos.safety_guard import (
    DEFAULT_LOCK_TIMEOUT,
    DeadManSwitchTriggered,
    LockAcquisitionError,
    PrivilegeError,
    ProtectedTargetError,
    SafetyGuard,
    check_root_privileges,
    validate_target_interface,
    validate_target_pid,
    validate_target_process_name,
)


def test_check_root_privileges(monkeypatch: pytest.MonkeyPatch) -> None:
    """Test privilege verification behavior (CWE-250)."""
    # Dry run bypasses root check
    assert check_root_privileges(dry_run=True) is True

    # Root user
    monkeypatch.setattr("os.geteuid", lambda: 0)
    assert check_root_privileges(dry_run=False) is True

    # Non-root user
    monkeypatch.setattr("os.geteuid", lambda: 1000)
    with pytest.raises(PrivilegeError, match="Root privileges.*required"):
        check_root_privileges(dry_run=False)


def test_validate_target_interface() -> None:
    """Test interface validation and protected loopback rejection."""
    assert validate_target_interface("eth0") == "eth0"
    assert validate_target_interface("ens33") == "ens33"
    assert validate_target_interface("WLAN0") == "wlan0"

    with pytest.raises(ProtectedTargetError):
        validate_target_interface("lo")

    with pytest.raises(ProtectedTargetError):
        validate_target_interface("LOOPBACK")

    with pytest.raises(ValueError):
        validate_target_interface("")


def test_validate_target_pid() -> None:
    """Test PID validation against protected system PIDs."""
    assert validate_target_pid(12345) == 12345

    with pytest.raises(ProtectedTargetError):
        validate_target_pid(1)  # PID 1

    with pytest.raises(ProtectedTargetError):
        validate_target_pid(os.getpid())  # Current process

    with pytest.raises(ProtectedTargetError):
        validate_target_pid(os.getppid())  # Parent process

    with pytest.raises(ValueError):
        validate_target_pid(0)

    with pytest.raises(ValueError):
        validate_target_pid(-10)


def test_validate_target_process_name() -> None:
    """Test process name validation against system service whitelist."""
    assert validate_target_process_name("my-app-server") == "my-app-server"
    assert validate_target_process_name("worker_pool") == "worker_pool"

    with pytest.raises(ProtectedTargetError):
        validate_target_process_name("systemd")

    with pytest.raises(ProtectedTargetError):
        validate_target_process_name("sshd")

    with pytest.raises(ProtectedTargetError):
        validate_target_process_name("/usr/sbin/sshd")

    with pytest.raises(ProtectedTargetError):
        validate_target_process_name("dbus-daemon")

    with pytest.raises(ValueError):
        validate_target_process_name("")


def test_safety_guard_lock_and_cleanup(tmp_path: Any) -> None:
    """Test fcntl lock acquisition and release."""
    lock_file = str(tmp_path / "guard_test.lock")

    guard1 = SafetyGuard(lock_file_path=lock_file, auto_lock=True)
    assert guard1._lock_fd is not None

    # Attempting to acquire lock with second guard should time out
    with pytest.raises(LockAcquisitionError, match="Could not acquire experiment lock"):
        SafetyGuard(lock_file_path=lock_file, lock_timeout=0.2, auto_lock=True)

    guard1.cleanup()
    assert guard1._lock_fd is None

    # Now second guard can acquire lock
    guard2 = SafetyGuard(lock_file_path=lock_file, lock_timeout=1.0, auto_lock=True)
    guard2.cleanup()


def test_safety_guard_rollback_lifo_order(tmp_path: Any) -> None:
    """Test that atomic rollback executes in reverse (LIFO) order."""
    lock_file = str(tmp_path / "guard_lifo.lock")
    execution_order = []

    with SafetyGuard(lock_file_path=lock_file, auto_lock=True) as guard:
        guard.register_rollback(lambda: execution_order.append(1), "Step 1")
        guard.register_rollback(lambda: execution_order.append(2), "Step 2")
        guard.register_rollback(lambda: execution_order.append(3), "Step 3")

        assert guard.rollback_count == 3
        executed = guard.rollback_all()
        assert executed == ["Step 3", "Step 2", "Step 1"]
        assert execution_order == [3, 2, 1]
        assert guard.rollback_count == 0


def test_safety_guard_rollback_handles_exceptions(tmp_path: Any) -> None:
    """Ensure that failing rollback actions don't prevent subsequent rollbacks from running."""
    lock_file = str(tmp_path / "guard_err.lock")
    execution_order = []

    def failing_callback() -> None:
        raise RuntimeError("Rollback explosion")

    with SafetyGuard(lock_file_path=lock_file, auto_lock=True) as guard:
        guard.register_rollback(lambda: execution_order.append("A"), "Step A")
        guard.register_rollback(failing_callback, "Step Failed")
        guard.register_rollback(lambda: execution_order.append("B"), "Step B")

        executed = guard.rollback_all()
        assert execution_order == ["B", "A"]
        assert len(executed) == 3
        assert "FAILED: Step Failed" in executed[1]


def test_dead_man_switch_triggers(tmp_path: Any) -> None:
    """Verify dead-man switch auto-triggers rollback after timeout."""
    lock_file = str(tmp_path / "dead_man.lock")
    rolled_back = []
    timeout_called = []

    guard = SafetyGuard(lock_file_path=lock_file, auto_lock=True)
    guard.register_rollback(lambda: rolled_back.append("auto_rollback"), "Auto Rollback")

    guard.start_dead_man(
        timeout_seconds=0.2,
        on_timeout_callback=lambda: timeout_called.append(True),
    )
    assert guard.is_dead_man_active is True

    # Wait for timer to expire
    time.sleep(0.35)

    assert len(timeout_called) == 1
    assert len(rolled_back) == 1
    assert guard.rollback_count == 0

    guard.cleanup()


def test_dead_man_switch_heartbeat(tmp_path: Any) -> None:
    """Verify heartbeat resets the dead-man switch timer."""
    lock_file = str(tmp_path / "dead_man_hb.lock")
    timeout_called = []

    guard = SafetyGuard(lock_file_path=lock_file, auto_lock=True)
    guard.start_dead_man(
        timeout_seconds=0.3,
        on_timeout_callback=lambda: timeout_called.append(True),
    )

    # Feed heartbeat before expiration
    time.sleep(0.15)
    guard.heartbeat()
    time.sleep(0.15)
    guard.heartbeat()

    # Total elapsed 0.3s, but fed twice, so should not have fired yet
    assert len(timeout_called) == 0

    # Disarm
    guard.stop_dead_man()
    assert guard.is_dead_man_active is False
    time.sleep(0.35)
    assert len(timeout_called) == 0

    guard.cleanup()


def test_safety_guard_signal_handler(tmp_path: Any) -> None:
    """Test simulated signal handling triggering cleanup."""
    lock_file = str(tmp_path / "guard_sig.lock")
    guard = SafetyGuard(lock_file_path=lock_file, auto_lock=True)

    cleaned = []
    guard.register_rollback(lambda: cleaned.append(True), "Cleanup via signal")

    # Set mock chained signal handler
    old_called = []
    guard._old_signal_handlers[signal.SIGINT] = lambda s, f: old_called.append(s)

    guard._handle_signal(signal.SIGINT, None)

    assert len(cleaned) == 1
    assert old_called == [signal.SIGINT]

    # Test default fallback when old handler is not callable
    guard2 = SafetyGuard(lock_file_path=str(tmp_path / "guard_sig2.lock"), auto_lock=True)
    guard2._old_signal_handlers[signal.SIGTERM] = None
    with pytest.raises(SystemExit) as exc_info:
        guard2._handle_signal(signal.SIGTERM, None)
    assert exc_info.value.code == 128 + signal.SIGTERM
