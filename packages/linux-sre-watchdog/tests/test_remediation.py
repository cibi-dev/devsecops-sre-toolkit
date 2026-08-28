"""Unit tests for RemediationManager privilege and runbook guards."""

from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import mock_open, patch

import pytest

from watchdog.circuit_breaker import CircuitBreaker, CircuitBreakerConfig
from watchdog.engine import AnomalyEvent, Severity
from watchdog.remediation import PrivilegeError, RemediationManager, RunbookResult


def test_is_root_reflects_geteuid():
    with patch("os.geteuid", return_value=0):
        assert RemediationManager.is_root() is True

    with patch("os.geteuid", return_value=1000):
        assert RemediationManager.is_root() is False


def test_dry_run_executes_without_root():
    with patch("os.geteuid", return_value=1000):
        mgr = RemediationManager()
        res_cache = mgr.execute_runbook("clear_pagecache", dry_run=True)
        assert res_cache.success is True
        assert res_cache.dry_run is True
        assert "[DRY-RUN]" in res_cache.stdout

        res_svc = mgr.execute_runbook("restart_service:nginx", dry_run=True)
        assert res_svc.success is True
        assert res_svc.dry_run is True
        assert "systemctl restart nginx" in res_svc.stdout

        res_trim = mgr.execute_runbook("trim_journal", dry_run=True)
        assert res_trim.success is True
        assert res_trim.dry_run is True

        res_cpu = mgr.execute_runbook("throttle_high_cpu_tasks", dry_run=True)
        assert res_cpu.success is True
        assert res_cpu.dry_run is True


def test_non_root_mutating_pagecache_fails_privilege_check():
    with patch("os.geteuid", return_value=1000):
        mgr = RemediationManager()
        res = mgr.execute_runbook("clear_pagecache", dry_run=False)
        assert res.success is False
        assert "requires root privileges" in res.stderr
        assert res.details.get("privilege_error") is True


def test_root_mutating_pagecache_success():
    with patch("os.geteuid", return_value=0), patch("os.sync"), patch("builtins.open", mock_open()):
        mgr = RemediationManager()
        res = mgr.execute_runbook("clear_pagecache", dry_run=False)
        assert res.success is True
        assert "Successfully synced" in res.stdout


def test_root_mutating_pagecache_oserror():
    with patch("os.geteuid", return_value=0), patch("os.sync"), patch("builtins.open", side_effect=OSError("Disk write error")):
        mgr = RemediationManager()
        res = mgr.execute_runbook("clear_pagecache", dry_run=False)
        assert res.success is False
        assert "Failed to drop caches" in res.stderr


def test_non_root_mutating_service_restart_fails_privilege_check():
    with patch("os.geteuid", return_value=1000):
        mgr = RemediationManager()
        res = mgr.execute_runbook("restart_service:nginx", dry_run=False)
        assert res.success is False
        assert "requires root privileges" in res.stderr
        assert res.details.get("privilege_error") is True


def test_non_root_mutating_trim_journal_fails_privilege_check():
    with patch("os.geteuid", return_value=1000):
        mgr = RemediationManager()
        res = mgr.execute_runbook("trim_journal", dry_run=False)
        assert res.success is False
        assert "requires root privileges" in res.stderr
        assert res.details.get("privilege_error") is True


def test_root_mutating_trim_journal_success():
    def mock_executor(cmd: list[str], timeout: float):
        assert cmd == ["journalctl", "--vacuum-size=100M"]
        return 0, "Vacuumed", ""

    with patch("os.geteuid", return_value=0):
        mgr = RemediationManager(custom_executor=mock_executor)
        res = mgr.execute_runbook("trim_journal", dry_run=False)
        assert res.success is True
        assert "Vacuumed" in res.stdout


def test_invalid_service_name_injection_rejected():
    mgr = RemediationManager()
    res = mgr.execute_runbook("restart_service:nginx; cat /etc/shadow", dry_run=True)
    assert res.success is False
    assert "Invalid service name syntax" in res.stderr


def test_root_service_restart_with_custom_executor():
    def mock_executor(cmd: list[str], timeout: float):
        assert cmd == ["systemctl", "restart", "nginx.service"]
        return 0, "", ""

    with patch("os.geteuid", return_value=0):
        mgr = RemediationManager(custom_executor=mock_executor)
        res = mgr.execute_runbook("restart_service:nginx.service", dry_run=False)
        assert res.success is True
        assert res.details["returncode"] == 0


def test_circuit_breaker_blocks_remediation(tmp_path: Path):
    cb = CircuitBreaker(
        config=CircuitBreakerConfig(failure_threshold=2),
        state_file=tmp_path / "cb.json",
    )
    mgr = RemediationManager(circuit_breaker=cb)

    # Trigger 2 failures to trip circuit breaker
    cb.record_failure("clear_pagecache")
    cb.record_failure("clear_pagecache")

    res = mgr.execute_runbook("clear_pagecache", dry_run=False)
    assert res.success is False
    assert "Blocked by anti-flapping circuit breaker" in res.stderr


def test_reap_zombies_execution():
    with patch("os.kill") as mock_kill, patch("os.geteuid", return_value=0):
        mgr = RemediationManager()
        res = mgr.execute_runbook(
            "reap_zombies",
            dry_run=False,
            details={"zombies": [{"pid": 500, "ppid": 100, "comm": "zombie_proc"}]},
        )
        assert res.success is True
        mock_kill.assert_called_once()


def test_reap_zombies_process_lookup_error_handled():
    with patch("os.kill", side_effect=ProcessLookupError), patch("os.geteuid", return_value=0):
        mgr = RemediationManager()
        res = mgr.execute_runbook(
            "reap_zombies",
            dry_run=False,
            details={"zombie_pids": [501]},
        )
        assert res.success is True


def test_reap_zombies_permission_error_non_root():
    with patch("os.kill", side_effect=PermissionError), patch("os.geteuid", return_value=1000):
        mgr = RemediationManager()
        res = mgr.execute_runbook(
            "reap_zombies",
            dry_run=False,
            details={"zombies": [{"pid": 500, "ppid": 100, "comm": "zombie_proc"}]},
        )
        assert res.success is False
        assert "requires root privileges" in res.stderr


def test_reap_zombies_permission_error_when_root():
    with patch("os.kill", side_effect=PermissionError), patch("os.geteuid", return_value=0):
        mgr = RemediationManager()
        res = mgr.execute_runbook(
            "reap_zombies",
            dry_run=False,
            details={"zombies": [{"pid": 500, "ppid": 100, "comm": "zombie_proc"}]},
        )
        assert res.success is False
        assert "Permission denied" in res.stderr


def test_throttle_cpu_non_dry_run():
    mgr = RemediationManager()
    res = mgr.execute_runbook("throttle_high_cpu_tasks", dry_run=False, details={"pid": 1234})
    assert res.success is True
    assert "recorded" in res.stdout


def test_execute_for_anomaly():
    mgr = RemediationManager()
    anomaly = AnomalyEvent(
        metric="memory",
        current_value=95.0,
        threshold_value=90.0,
        severity=Severity.CRITICAL,
        recommended_runbook="clear_pagecache",
        message="High memory",
    )

    res = mgr.execute_for_anomaly(anomaly, dry_run=True)
    assert res is not None
    assert res.runbook_name == "clear_pagecache"
    assert res.dry_run is True

    # Anomaly with no recommended runbook returns None
    no_rb = AnomalyEvent(
        metric="memory",
        current_value=85.0,
        threshold_value=80.0,
        severity=Severity.WARNING,
        recommended_runbook=None,
        message="Memory warning",
    )
    assert mgr.execute_for_anomaly(no_rb, dry_run=True) is None


def test_unknown_runbook():
    mgr = RemediationManager()
    res = mgr.execute_runbook("non_existent_runbook", dry_run=True)
    assert res.success is False
    assert "Unknown runbook" in res.stderr


def test_default_subprocess_run_command():
    mgr = RemediationManager()
    # Test real safe command execution via default runner
    code, stdout, stderr = mgr._run_command(["true"], timeout=5.0)
    assert code == 0

    # Test nonexistent command
    code, stdout, stderr = mgr._run_command(["nonexistent_command_12345"], timeout=5.0)
    assert code == 127
