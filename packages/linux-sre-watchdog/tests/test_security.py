"""Dedicated DevSecOps and CWE controls security test suite."""

from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import patch

import pytest
from pydantic import ValidationError

from watchdog.circuit_breaker import CircuitBreaker, CircuitBreakerConfig
from watchdog.collectors.systemd import SystemdCollector
from watchdog.engine import WatchdogConfig
from watchdog.logger import sanitize_string
from watchdog.remediation import PrivilegeError, RemediationManager


def test_cwe_798_no_hardcoded_secrets_in_codebase():
    """Verify that source files do not contain obvious raw secret strings."""
    src_dir = Path(__file__).resolve().parent.parent / "src"
    suspicious_substrings = [
        "ghp_" + "realtoken_forbidden",
        "AKIA" + "IOSFODNN7EXAMPLE",
        "BEGIN" + " RSA PRIVATE KEY",
    ]
    for py_file in src_dir.rglob("*.py"):
        content = py_file.read_text(encoding="utf-8")
        for bad in suspicious_substrings:
            assert bad not in content, f"Found suspicious secret in {py_file}"


def test_cwe_250_269_least_privilege_enforcement():
    """Mutating actions strictly require euid==0 and fail otherwise."""
    with patch("os.geteuid", return_value=1001):
        mgr = RemediationManager()
        # Mutating runbooks must abort
        for runbook in ["clear_pagecache", "restart_service:nginx", "trim_journal"]:
            res = mgr.execute_runbook(runbook, dry_run=False)
            assert res.success is False
            assert "requires root privileges" in res.stderr
            assert res.details.get("privilege_error") is True


def test_cwe_78_command_injection_mitigation():
    """Service names with command injection payloads are rejected before execution."""
    collector = SystemdCollector()
    bad_names = [
        "nginx; cat /etc/passwd",
        "app && rm -rf /",
        "$(reboot)",
        "service`id`",
        "foo|nc -l 8080",
    ]
    for bad in bad_names:
        status = collector.inspect_service(bad)
        assert status.error is not None
        assert "Invalid service name" in status.error

    mgr = RemediationManager()
    for bad in bad_names:
        res = mgr.execute_runbook(f"restart_service:{bad}", dry_run=True)
        assert res.success is False
        assert "Invalid service name" in res.stderr


def test_cwe_377_362_file_lock_timeout_anti_deadlock(tmp_path: Path):
    """Circuit breaker lock respects timeout and does not block indefinitely."""
    lock_file = tmp_path / "test_cb.json.lock"
    # Artificially lock the file
    import fcntl
    fd = os.open(str(lock_file), os.O_RDWR | os.O_CREAT, 0o600)
    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)

    try:
        cb = CircuitBreaker(state_file=tmp_path / "test_cb.json")
        cb.LOCK_TIMEOUT_SECONDS = 0.1  # Set short timeout for test

        with pytest.raises(TimeoutError) as exc_info:
            cb.can_execute("action")
        assert "Failed to acquire circuit breaker lock" in str(exc_info.value)
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def test_cwe_209_pii_and_token_redaction():
    """All sensitive credential formats are redacted from log outputs."""
    mock_api = "sk-" + "abcdef123456789012345678"
    mock_gh = "ghp_" + "1234567890abcdefghijklmnopqrstuvwxyz"
    mock_google = "AIzaSy" + "ABC12345678901234567890123456789"
    raw = (
        f"User logged in with token {mock_api} "
        f"and {mock_gh} "
        f"and {mock_google} "
        "from path /home/deploy/.ssh/authorized_keys "
        "with password: 'SuperSecretPassword123!'"
    )
    sanitized = sanitize_string(raw)
    assert mock_api not in sanitized
    assert mock_gh not in sanitized
    assert mock_google not in sanitized
    assert ".ssh/authorized_keys" not in sanitized
    assert "SuperSecretPassword123!" not in sanitized


def test_cwe_502_schema_validation_forbids_extra_fields():
    """Pydantic schemas forbid unvalidated extra fields."""
    with pytest.raises(ValidationError):
        WatchdogConfig.model_validate({
            "cpu_warning_percent": 80.0,
            "injected_untrusted_field": "malicious_payload",
        })
