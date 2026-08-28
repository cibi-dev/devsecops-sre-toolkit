"""Tests for network fault injection module (tc/netem)."""

from __future__ import annotations

import subprocess
from unittest.mock import MagicMock, patch
import pytest
from pydantic import ValidationError

from chaos.network import (
    NetworkFaultConfig,
    NetworkFaultResult,
    build_tc_command,
    build_tc_rollback_command,
    inject_network_fault,
    revert_network_fault,
)
from chaos.safety_guard import ProtectedTargetError, SafetyGuard


def test_network_config_valid() -> None:
    """Test valid network fault configuration creation."""
    config = NetworkFaultConfig(
        interface="eth0",
        latency_ms=100.0,
        jitter_ms=20.0,
        correlation_pct=25.0,
        loss_pct=5.0,
        corruption_pct=1.0,
        duplicate_pct=2.0,
        reorder_pct=3.0,
        duration_seconds=15.0,
        dry_run=True,
    )
    assert config.interface == "eth0"
    assert config.latency_ms == 100.0
    assert config.jitter_ms == 20.0
    assert config.loss_pct == 5.0
    assert config.duration_seconds == 15.0
    assert config.dry_run is True


def test_network_config_protected_interface_rejected() -> None:
    """Ensure loopback interface cannot be targeted (CWE-250 Whitelist)."""
    with pytest.raises(ProtectedTargetError):
        NetworkFaultConfig(interface="lo")

    with pytest.raises(ProtectedTargetError):
        NetworkFaultConfig(interface="loopback")

    with pytest.raises(ProtectedTargetError):
        NetworkFaultConfig(interface="127.0.0.1")


def test_network_config_out_of_bounds_validation() -> None:
    """Test boundary validation on config parameters."""
    with pytest.raises(ValidationError):
        NetworkFaultConfig(interface="eth0", loss_pct=105.0)

    with pytest.raises(ValidationError):
        NetworkFaultConfig(interface="eth0", latency_ms=-10.0)

    with pytest.raises(ValidationError):
        NetworkFaultConfig(interface="eth0", duration_seconds=45.0)  # Exceeds MAX_EXPERIMENT_DURATION (30s)

    with pytest.raises(ValidationError):
        NetworkFaultConfig(interface="", dry_run=True)


def test_build_tc_command() -> None:
    """Verify safe tc argument vector construction."""
    config = NetworkFaultConfig(
        interface="eth0",
        latency_ms=100.0,
        jitter_ms=20.0,
        correlation_pct=25.0,
        loss_pct=5.0,
        corruption_pct=1.0,
        duplicate_pct=2.0,
        reorder_pct=3.0,
    )
    cmd = build_tc_command(config)
    assert cmd == [
        "tc", "qdisc", "add", "dev", "eth0", "root", "netem",
        "delay", "100.0ms", "20.0ms", "25.0%",
        "loss", "5.0%",
        "corrupt", "1.0%",
        "duplicate", "2.0%",
        "reorder", "3.0%",
    ]


def test_build_tc_command_minimal() -> None:
    """Verify minimal tc command with only loss."""
    config = NetworkFaultConfig(interface="eth1", loss_pct=10.0, correlation_pct=15.0)
    cmd = build_tc_command(config)
    assert cmd == [
        "tc", "qdisc", "add", "dev", "eth1", "root", "netem",
        "loss", "10.0%", "15.0%",
    ]


def test_build_tc_rollback_command() -> None:
    """Verify tc rollback command format."""
    cmd = build_tc_rollback_command("eth0")
    assert cmd == ["tc", "qdisc", "del", "dev", "eth0", "root"]

    with pytest.raises(ProtectedTargetError):
        build_tc_rollback_command("lo")


def test_inject_network_fault_dry_run() -> None:
    """Verify dry-run mode does not execute real subprocesses."""
    config = NetworkFaultConfig(interface="eth0", latency_ms=50.0, dry_run=True)
    res = inject_network_fault(config)
    assert isinstance(res, NetworkFaultResult)
    assert res.success is True
    assert res.dry_run is True
    assert "[DRY-RUN]" in res.output
    assert res.interface == "eth0"
    assert "tc" in res.command_executed


def test_inject_network_fault_mock_success(monkeypatch: pytest.MonkeyPatch) -> None:
    """Test successful fault injection with mocked subprocess and root privileges."""
    monkeypatch.setattr("os.geteuid", lambda: 0)

    config = NetworkFaultConfig(interface="eth0", latency_ms=50.0, dry_run=False)

    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout="qdisc added", stderr="")
        res = inject_network_fault(config)
        assert res.success is True
        assert res.dry_run is False
        assert mock_run.call_count >= 1


def test_inject_network_fault_mock_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    """Test handling of subprocess failure during injection."""
    monkeypatch.setattr("os.geteuid", lambda: 0)
    config = NetworkFaultConfig(interface="eth0", latency_ms=50.0, dry_run=False)

    with patch("subprocess.run") as mock_run:
        # First call is revert (can succeed or fail), second call is inject (raises CalledProcessError)
        def _side_effect(cmd, **kwargs):
            if "add" in cmd:
                raise subprocess.CalledProcessError(1, cmd, stderr="RTNETLINK answers: Operation not permitted")
            return MagicMock(returncode=0, stdout="", stderr="")

        mock_run.side_effect = _side_effect
        res = inject_network_fault(config)
        assert res.success is False
        assert "Operation not permitted" in (res.error or "")


def test_inject_network_fault_file_not_found(monkeypatch: pytest.MonkeyPatch) -> None:
    """Test handling when tc executable is missing."""
    monkeypatch.setattr("os.geteuid", lambda: 0)
    config = NetworkFaultConfig(interface="eth0", latency_ms=50.0, dry_run=False)

    with patch("subprocess.run", side_effect=FileNotFoundError("No such file: tc")):
        res = inject_network_fault(config)
        assert res.success is False
        assert "tc executable not found" in (res.error or "")


def test_revert_network_fault_mock(monkeypatch: pytest.MonkeyPatch) -> None:
    """Test revert_network_fault function."""
    monkeypatch.setattr("os.geteuid", lambda: 0)

    # Dry-run
    assert revert_network_fault("eth0", dry_run=True) is True

    # Real mock
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
        assert revert_network_fault("eth0", dry_run=False) is True

    # Missing binary
    with patch("subprocess.run", side_effect=FileNotFoundError):
        assert revert_network_fault("eth0", dry_run=False) is False


def test_safety_guard_rollback_registration(monkeypatch: pytest.MonkeyPatch, tmp_path: Any) -> None:
    """Verify safety guard records atomic rollback before executing injection."""
    monkeypatch.setattr("os.geteuid", lambda: 0)
    lock_file = str(tmp_path / "test.lock")

    with SafetyGuard(lock_file_path=lock_file, auto_lock=True) as guard:
        config = NetworkFaultConfig(interface="eth0", latency_ms=20.0, dry_run=True)
        inject_network_fault(config, safety_guard=guard)
        assert guard.rollback_count == 1
        executed = guard.rollback_all()
        assert len(executed) == 1
        assert "Revert tc netem on interface eth0" in executed[0]
