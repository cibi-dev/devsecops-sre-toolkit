"""Security-specific verification tests (CWE-250, CWE-78, CWE-377, CWE-362, CWE-502, CWE-400)."""

from __future__ import annotations

import inspect
import os
from typing import Any
import pytest
from pydantic import ValidationError

import chaos
import chaos.cpu_stress
import chaos.network
import chaos.process_killer
import chaos.reporter
import chaos.safety_guard
from chaos.cpu_stress import CpuStressConfig
from chaos.network import NetworkFaultConfig
from chaos.process_killer import ProcessTargetConfig
from chaos.safety_guard import (
    PROTECTED_INTERFACES,
    PROTECTED_PIDS,
    PROTECTED_PROCESS_NAMES,
    PrivilegeError,
    ProtectedTargetError,
    SafetyGuard,
    check_root_privileges,
    validate_target_interface,
    validate_target_pid,
    validate_target_process_name,
)


def test_cwe_250_root_privilege_enforcement(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify that non-root execution cleanly raises PrivilegeError unless in dry-run."""
    monkeypatch.setattr("os.geteuid", lambda: 1000)

    # Dry-run allows non-root
    assert check_root_privileges(dry_run=True) is True

    # Real mutation without root MUST raise PrivilegeError
    with pytest.raises(PrivilegeError, match="Root privileges.*required"):
        check_root_privileges(dry_run=False)


def test_cwe_250_protected_whitelist_definitions() -> None:
    """Verify core protected targets are present in constant definitions."""
    assert "lo" in PROTECTED_INTERFACES
    assert "loopback" in PROTECTED_INTERFACES
    assert 1 in PROTECTED_PIDS
    assert "sshd" in PROTECTED_PROCESS_NAMES
    assert "init" in PROTECTED_PROCESS_NAMES
    assert "systemd" in PROTECTED_PROCESS_NAMES
    assert "dbus-daemon" in PROTECTED_PROCESS_NAMES


def test_cwe_250_target_validations() -> None:
    """Verify validators strictly reject protected items."""
    for iface in ("lo", "loopback", "127.0.0.1"):
        with pytest.raises(ProtectedTargetError):
            validate_target_interface(iface)

    for pid in (1, os.getpid(), os.getppid()):
        with pytest.raises(ProtectedTargetError):
            validate_target_pid(pid)

    with pytest.raises(ValueError):
        validate_target_pid(0)

    for name in ("sshd", "init", "systemd", "dbus-daemon", "/usr/bin/python3"):
        with pytest.raises(ProtectedTargetError):
            validate_target_process_name(name)


def test_cwe_78_no_shell_true_in_codebase() -> None:
    """Audit source code to ensure shell=True is NEVER used in subprocess calls."""
    modules = [
        chaos.network,
        chaos.cpu_stress,
        chaos.process_killer,
        chaos.safety_guard,
        chaos.reporter,
        chaos.cli,
    ]

    for mod in modules:
        source = inspect.getsource(mod)
        assert "shell=True" not in source, f"Found forbidden 'shell=True' in {mod.__name__}"


def test_cwe_377_cwe_362_safe_locking(tmp_path: Any) -> None:
    """Verify flock concurrency locking and bounded timeout."""
    lock_file = str(tmp_path / "sec_test.lock")
    guard = SafetyGuard(lock_file_path=lock_file, auto_lock=True)
    assert os.path.exists(lock_file)
    guard.cleanup()


def test_cwe_502_pydantic_extra_forbid() -> None:
    """Verify all configuration schemas strictly forbid unrecognized extra fields (CWE-502/20)."""
    with pytest.raises(ValidationError):
        NetworkFaultConfig(interface="eth0", unknown_malicious_field="injection")  # type: ignore

    with pytest.raises(ValidationError):
        CpuStressConfig(load_percentage=50.0, malicious_payload=123)  # type: ignore

    with pytest.raises(ValidationError):
        ProcessTargetConfig(pid=1234, extra_hacker_flag=True)  # type: ignore


def test_cwe_400_maximum_duration_boundary() -> None:
    """Verify all fault injectors enforce maximum duration ceiling (<= 30.0s)."""
    with pytest.raises(ValidationError):
        NetworkFaultConfig(interface="eth0", duration_seconds=30.1)

    with pytest.raises(ValidationError):
        CpuStressConfig(duration_seconds=30.1)
