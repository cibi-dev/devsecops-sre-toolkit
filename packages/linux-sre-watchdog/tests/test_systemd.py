"""Unit tests for SystemdCollector."""

from __future__ import annotations

import pytest

from watchdog.collectors.systemd import (
    ServiceStatus,
    SystemdCollector,
    _default_command_runner,
)


def test_inspect_service_active():
    def mock_runner(cmd: list[str], timeout: float):
        assert cmd[0] == "systemctl"
        assert cmd[1] == "show"
        assert "nginx.service" in cmd
        return 0, "LoadState=loaded\nActiveState=active\nSubState=running\nUnitFileState=enabled\nMainPID=1234\n", ""

    collector = SystemdCollector(command_runner=mock_runner)
    status = collector.inspect_service("nginx")

    assert status.name == "nginx.service"
    assert status.is_active is True
    assert status.is_failed is False
    assert status.main_pid == 1234
    assert status.sub_state == "running"
    assert collector.is_service_active("nginx") is True
    assert collector.is_service_failed("nginx") is False


def test_inspect_service_failed():
    def mock_runner(cmd: list[str], timeout: float):
        return 0, "LoadState=loaded\nActiveState=failed\nSubState=failed\nUnitFileState=enabled\nMainPID=0\n", ""

    collector = SystemdCollector(command_runner=mock_runner)
    status = collector.inspect_service("postgresql.service")

    assert status.name == "postgresql.service"
    assert status.is_active is False
    assert status.is_failed is True
    assert status.sub_state == "failed"
    assert collector.is_service_failed("postgresql.service") is True
    assert collector.is_service_active("postgresql.service") is False


def test_inspect_service_invalid_name_cwe78():
    collector = SystemdCollector()
    # Attempt command injection in service name
    status = collector.inspect_service("nginx; rm -rf /")

    assert status.error is not None
    assert "Invalid service name" in status.error
    assert status.is_active is False


def test_inspect_service_command_failure():
    def mock_runner(cmd: list[str], timeout: float):
        return 1, "", "Failed to connect to bus: No such file or directory"

    collector = SystemdCollector(command_runner=mock_runner)
    status = collector.inspect_service("redis")

    assert status.error is not None
    assert "Failed to connect to bus" in status.error
    assert status.is_active is False


def test_inspect_multiple_services():
    def mock_runner(cmd: list[str], timeout: float):
        unit = cmd[2]
        if "nginx" in unit:
            return 0, "LoadState=loaded\nActiveState=active\nSubState=running\nMainPID=10\n", ""
        return 0, "LoadState=loaded\nActiveState=failed\nSubState=failed\nMainPID=0\n", ""

    collector = SystemdCollector(command_runner=mock_runner)
    results = collector.inspect_services(["nginx", "redis.service"])

    assert len(results) == 2
    assert results["nginx"].is_active is True
    assert results["redis.service"].is_failed is True


def test_default_command_runner_execution():
    # Test valid execution
    code, stdout, stderr = _default_command_runner(["true"], timeout=2.0)
    assert code == 0

    # Test error/missing command
    code, stdout, stderr = _default_command_runner(["nonexistent_systemd_cmd_xyz"], timeout=2.0)
    assert code == 127
