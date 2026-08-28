"""Unit tests for deterministic auto-rollback manager (<30s SLA)."""

from pathlib import Path
from unittest.mock import MagicMock, patch
import httpx
import pytest

from deployer.config import DeployerConfig, EnvironmentSlot, RollbackConfig, RouterConfig, TargetEnvironmentConfig
from deployer.health import HealthChecker, HealthCheckResult
from deployer.rollback import RollbackManager, RollbackResult
from deployer.router import TrafficRouter


def test_rollback_execution_success(tmp_path: Path):
    """Verify clean rollback from failed GREEN back to BLUE in <30s."""
    symlink_file = tmp_path / "active.conf"
    blue_conf = tmp_path / "upstream_blue.conf"
    green_conf = tmp_path / "upstream_green.conf"
    blue_conf.write_text("server 127.0.0.1:8081;\n", encoding="utf-8")
    green_conf.write_text("server 127.0.0.1:8082;\n", encoding="utf-8")

    deployer_cfg = DeployerConfig(
        blue=TargetEnvironmentConfig(name=EnvironmentSlot.BLUE, host="127.0.0.1", port=8081, config_path=blue_conf),
        green=TargetEnvironmentConfig(name=EnvironmentSlot.GREEN, host="127.0.0.1", port=8082, config_path=green_conf),
        router=RouterConfig(symlink_path=symlink_file, enable_proxy_reload=False),
        rollback=RollbackConfig(max_rollback_timeout_seconds=30.0),
        allow_unprivileged=True,
    )

    router = TrafficRouter(config=deployer_cfg.router, allow_unprivileged=True)
    router.switch_to_target(EnvironmentSlot.GREEN, green_conf)

    manager = RollbackManager(deployer_config=deployer_cfg, router=router)

    mock_resp = httpx.Response(status_code=200, text="ok", request=httpx.Request("GET", deployer_cfg.blue.url))
    with patch.object(httpx.Client, "get", return_value=mock_resp):
        res = manager.execute_rollback(
            failed_slot=EnvironmentSlot.GREEN,
            reason="Post-switch smoke test failed",
        )

        assert res.success is True
        assert res.restored_slot == EnvironmentSlot.BLUE
        assert res.failed_slot == EnvironmentSlot.GREEN
        assert res.rollback_duration_ms < 30000.0  # <30s SLA
        assert res.restored_health is True
        assert router.get_active_slot(deployer_cfg) == EnvironmentSlot.BLUE


def test_rollback_symlink_switch_failure(tmp_path: Path):
    """Verify handling when symlink switch during rollback fails."""
    deployer_cfg = DeployerConfig(
        router=RouterConfig(symlink_path=tmp_path / "active.conf", enable_proxy_reload=False),
        allow_unprivileged=True,
    )
    manager = RollbackManager(deployer_config=deployer_cfg)

    with patch.object(TrafficRouter, "switch_to_target") as mock_switch:
        mock_switch.return_value = MagicMock(success=False, error_message="I/O Error")
        res = manager.execute_rollback(failed_slot=EnvironmentSlot.BLUE)
        assert res.success is False
        assert "I/O Error" in res.error_message


def test_rollback_sla_timeout_exceeded(tmp_path: Path):
    """Verify failure result when rollback exceeds SLA limit."""
    deployer_cfg = DeployerConfig(
        router=RouterConfig(symlink_path=tmp_path / "active.conf", enable_proxy_reload=False),
        rollback=RollbackConfig(max_rollback_timeout_seconds=0.001),
        allow_unprivileged=True,
    )
    manager = RollbackManager(deployer_config=deployer_cfg)

    call_count = 0
    def mock_perf():
        nonlocal call_count
        call_count += 1
        return 0.0 if call_count <= 2 else 100.0

    with patch("time.perf_counter", side_effect=mock_perf):
        res = manager.execute_rollback(failed_slot=EnvironmentSlot.GREEN, verify_health_after_rollback=False)
        assert res.success is False
        assert "SLA exceeded" in res.error_message


def test_rollback_result_to_dict():
    """Verify RollbackResult dictionary serialization."""
    res = RollbackResult(
        success=True,
        restored_slot=EnvironmentSlot.BLUE,
        failed_slot=EnvironmentSlot.GREEN,
        trigger_reason="HTTP 500 spike",
        rollback_duration_ms=12.4,
        restored_health=True,
    )
    d = res.to_dict()
    assert d["success"] is True
    assert d["restored_slot"] == "blue"
    assert d["failed_slot"] == "green"
    assert d["rollback_duration_ms"] == 12.4
    assert d["restored_health"] is True
