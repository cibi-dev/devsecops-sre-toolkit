"""Tests for process killer and crash simulator module."""

from __future__ import annotations

import os
import signal
from unittest.mock import MagicMock, patch
import psutil
import pytest
from pydantic import ValidationError

from chaos.process_killer import (
    ProcessKillResult,
    ProcessTargetConfig,
    find_target_processes,
    is_process_whitelisted,
    kill_target_process,
    terminate_processes,
)
from chaos.safety_guard import ProtectedTargetError


def test_process_config_valid() -> None:
    """Test valid ProcessTargetConfig creation."""
    config = ProcessTargetConfig(
        pid=12345,
        process_name="my-worker",
        signal_name="SIGTERM",
        whitelist_patterns=["my-app*", "my-worker*"],
        dry_run=True,
    )
    assert config.pid == 12345
    assert config.process_name == "my-worker"
    assert config.signal_name == "SIGTERM"
    assert config.dry_run is True


def test_process_config_signal_normalization() -> None:
    """Test signal name normalization (e.g. 'kill' -> 'SIGKILL')."""
    cfg1 = ProcessTargetConfig(pid=1234, signal_name="kill")
    assert cfg1.signal_name == "SIGKILL"

    cfg2 = ProcessTargetConfig(pid=1234, signal_name="sigterm")
    assert cfg2.signal_name == "SIGTERM"

    with pytest.raises(ValidationError):
        ProcessTargetConfig(pid=1234, signal_name="INVALID_SIG")


def test_process_config_protected_pid_rejection() -> None:
    """Ensure protected PIDs (PID 1, self, parent) are strictly rejected."""
    with pytest.raises(ProtectedTargetError):
        ProcessTargetConfig(pid=1)

    with pytest.raises(ProtectedTargetError):
        ProcessTargetConfig(pid=os.getpid())

    with pytest.raises(ProtectedTargetError):
        ProcessTargetConfig(pid=os.getppid())

    with pytest.raises(ValueError):
        ProcessTargetConfig(pid=-5)


def test_process_config_protected_name_rejection() -> None:
    """Ensure protected system processes cannot be targeted."""
    with pytest.raises(ProtectedTargetError):
        ProcessTargetConfig(process_name="systemd")

    with pytest.raises(ProtectedTargetError):
        ProcessTargetConfig(process_name="sshd")

    with pytest.raises(ProtectedTargetError):
        ProcessTargetConfig(process_name="init")

    with pytest.raises(ProtectedTargetError):
        ProcessTargetConfig(process_name="dbus-daemon")


def test_is_process_whitelisted() -> None:
    """Test custom whitelist glob matching."""
    # Empty whitelist allows non-protected targets
    assert is_process_whitelisted("custom-service", []) is True

    # Pattern matches
    assert is_process_whitelisted("celery-worker-1", ["celery*", "redis*"]) is True
    assert is_process_whitelisted("redis-server", ["celery*", "redis*"]) is True
    assert is_process_whitelisted("nginx", ["celery*", "redis*"]) is False


def test_find_target_processes_empty_raises() -> None:
    """Ensure specifying neither pid nor name raises ValueError."""
    config = ProcessTargetConfig(dry_run=True)
    with pytest.raises(ValueError, match="Either 'pid' or 'process_name'"):
        find_target_processes(config)


def test_find_target_processes_by_pid() -> None:
    """Test finding process by PID with mocking."""
    config = ProcessTargetConfig(pid=9999, whitelist_patterns=["app*"])

    mock_proc = MagicMock(spec=psutil.Process)
    mock_proc.pid = 9999
    mock_proc.name.return_value = "app-server"

    with patch("psutil.Process", return_value=mock_proc):
        targets = find_target_processes(config)
        assert len(targets) == 1
        assert targets[0].pid == 9999


def test_find_target_processes_pid_not_found() -> None:
    """Test finding process by non-existent PID raises ValueError."""
    config = ProcessTargetConfig(pid=9999)
    with patch("psutil.Process", side_effect=psutil.NoSuchProcess(9999)):
        with pytest.raises(ValueError, match="No active process found with PID 9999"):
            find_target_processes(config)


def test_find_target_processes_whitelist_mismatch() -> None:
    """Test that whitelist pattern mismatch raises ProtectedTargetError."""
    config = ProcessTargetConfig(pid=9999, whitelist_patterns=["worker*"])

    mock_proc = MagicMock(spec=psutil.Process)
    mock_proc.pid = 9999
    mock_proc.name.return_value = "database-server"

    with patch("psutil.Process", return_value=mock_proc):
        with pytest.raises(ProtectedTargetError, match="does not match allowed whitelist"):
            find_target_processes(config)


def test_find_target_processes_by_name() -> None:
    """Test searching processes by name pattern across process table."""
    config = ProcessTargetConfig(
        process_name="worker",
        whitelist_patterns=["worker*"],
    )

    mock_p1 = MagicMock(spec=psutil.Process)
    mock_p1.info = {"pid": 5555, "name": "worker-task", "cmdline": ["python", "worker.py"]}
    mock_p1.pid = 5555
    mock_p1.name.return_value = "worker-task"

    mock_p2 = MagicMock(spec=psutil.Process)
    mock_p2.info = {"pid": 1, "name": "systemd", "cmdline": ["/sbin/init"]}

    mock_p3 = MagicMock(spec=psutil.Process)
    mock_p3.info = {"pid": 6666, "name": "other-app", "cmdline": ["other"]}

    with patch("psutil.process_iter", return_value=[mock_p1, mock_p2, mock_p3]):
        targets = find_target_processes(config)
        assert len(targets) == 1
        assert targets[0].pid == 5555


def test_kill_target_process_dry_run() -> None:
    """Test dry-run simulation of process termination."""
    mock_proc = MagicMock(spec=psutil.Process)
    mock_proc.pid = 8888
    mock_proc.name.return_value = "worker-task"

    res = kill_target_process(mock_proc, signal.SIGTERM, dry_run=True)
    assert isinstance(res, ProcessKillResult)
    assert res.success is True
    assert res.dry_run is True
    assert res.pid == 8888
    assert res.signal_sent == "SIGTERM"
    mock_proc.send_signal.assert_not_called()


def test_kill_target_process_real_mock() -> None:
    """Test real signal dispatch with mock."""
    mock_proc = MagicMock(spec=psutil.Process)
    mock_proc.pid = 8888
    mock_proc.name.return_value = "worker-task"

    res = kill_target_process(mock_proc, signal.SIGTERM, dry_run=False)
    assert res.success is True
    assert res.dry_run is False
    mock_proc.send_signal.assert_called_once_with(signal.SIGTERM)


def test_kill_target_process_access_denied(monkeypatch: pytest.MonkeyPatch) -> None:
    """Test error handling when AccessDenied is encountered."""
    monkeypatch.setattr("os.geteuid", lambda: 1000)
    mock_proc = MagicMock(spec=psutil.Process)
    mock_proc.pid = 8888
    mock_proc.name.return_value = "worker-task"
    mock_proc.send_signal.side_effect = psutil.AccessDenied()

    # AccessDenied calls check_root_privileges which raises PrivilegeError when non-root
    with pytest.raises(Exception):
        kill_target_process(mock_proc, signal.SIGKILL, dry_run=False)


def test_kill_target_process_no_such_process() -> None:
    """Test handling when process exits before signal delivery."""
    mock_proc = MagicMock(spec=psutil.Process)
    mock_proc.pid = 8888
    mock_proc.name.return_value = "worker-task"
    mock_proc.send_signal.side_effect = psutil.NoSuchProcess(8888)

    res = kill_target_process(mock_proc, signal.SIGTERM, dry_run=False)
    assert res.success is False
    assert "Process exited before signal could be delivered" in (res.error or "")


def test_kill_target_process_generic_exception() -> None:
    """Test handling when an unexpected exception occurs."""
    mock_proc = MagicMock(spec=psutil.Process)
    mock_proc.pid = 8888
    mock_proc.name.return_value = "worker-task"
    mock_proc.send_signal.side_effect = OSError("Hardware error")

    res = kill_target_process(mock_proc, signal.SIGTERM, dry_run=False)
    assert res.success is False
    assert "Hardware error" in (res.error or "")


def test_terminate_processes_empty() -> None:
    """Test terminate_processes when no targets found."""
    config = ProcessTargetConfig(process_name="nonexistent-svc", dry_run=True)
    with patch("psutil.process_iter", return_value=[]):
        results = terminate_processes(config)
        assert results == []


def test_terminate_processes_integration() -> None:
    """Test batch terminate_processes function."""
    config = ProcessTargetConfig(pid=7777, dry_run=True)

    mock_proc = MagicMock(spec=psutil.Process)
    mock_proc.pid = 7777
    mock_proc.name.return_value = "custom-daemon"

    with patch("psutil.Process", return_value=mock_proc):
        results = terminate_processes(config)
        assert len(results) == 1
        assert results[0].pid == 7777
        assert results[0].dry_run is True
