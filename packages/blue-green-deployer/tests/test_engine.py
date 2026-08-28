"""Unit tests for DeployEngine full Blue/Green deployment cycle."""

import json
from pathlib import Path
from unittest.mock import MagicMock, patch
import httpx
import pytest

from deployer.config import (
    DeployerConfig,
    DeploymentStatus,
    EnvironmentSlot,
    HealthCheckConfig,
    LockConfig,
    RollbackConfig,
    RouterConfig,
    TargetEnvironmentConfig,
)
from deployer.engine import DeployEngine, DeploymentResult
from deployer.lock import DeploymentLock, DeploymentLockTimeoutError


@pytest.fixture
def test_config(tmp_path: Path) -> DeployerConfig:
    """Provide an isolated DeployerConfig for test executions."""
    blue_conf = tmp_path / "upstream_blue.conf"
    green_conf = tmp_path / "upstream_green.conf"
    blue_conf.write_text("server 127.0.0.1:8081;\n", encoding="utf-8")
    green_conf.write_text("server 127.0.0.1:8082;\n", encoding="utf-8")

    return DeployerConfig(
        blue=TargetEnvironmentConfig(name=EnvironmentSlot.BLUE, host="127.0.0.1", port=8081, config_path=blue_conf),
        green=TargetEnvironmentConfig(name=EnvironmentSlot.GREEN, host="127.0.0.1", port=8082, config_path=green_conf),
        health=HealthCheckConfig(max_retries=2, retry_interval_seconds=0.01, consecutive_successes_required=1),
        router=RouterConfig(symlink_path=tmp_path / "active.conf", backup_dir=tmp_path / "backups", enable_proxy_reload=False),
        rollback=RollbackConfig(post_switch_health_checks=1, post_switch_interval_seconds=0.01, auto_rollback_enabled=True),
        lock=LockConfig(lock_file_path=tmp_path / "deploy.lock", lock_timeout_seconds=1.0),
        state_file=tmp_path / "state.json",
        allow_unprivileged=True,
    )


def test_full_deployment_success(test_config: DeployerConfig):
    """Verify complete deployment cycle from BLUE to GREEN."""
    engine = DeployEngine(config=test_config)

    # Set initial active to BLUE
    engine.router.switch_to_target(EnvironmentSlot.BLUE, test_config.blue.config_path, validate_proxy=False)
    assert engine.get_current_active_slot() == EnvironmentSlot.BLUE

    # Mock all HTTP health checks to succeed
    mock_resp = httpx.Response(200, text="OK", request=httpx.Request("GET", test_config.green.url))
    with patch.object(httpx.Client, "get", return_value=mock_resp):
        res = engine.deploy(target_slot=EnvironmentSlot.GREEN)

        assert res.success is True
        assert res.status == DeploymentStatus.SUCCESS
        assert res.previous_active_slot == EnvironmentSlot.BLUE
        assert res.new_active_slot == EnvironmentSlot.GREEN
        assert res.target_slot == EnvironmentSlot.GREEN
        assert engine.get_current_active_slot() == EnvironmentSlot.GREEN


def test_pre_switch_health_failure_aborts_deploy(test_config: DeployerConfig):
    """Verify deployment aborts cleanly without switching traffic if passive slot is unhealthy."""
    engine = DeployEngine(config=test_config)
    engine.router.switch_to_target(EnvironmentSlot.BLUE, test_config.blue.config_path, validate_proxy=False)

    # Mock passive environment GREEN failing health check
    with patch.object(httpx.Client, "get", side_effect=httpx.ConnectError("Connection refused")):
        res = engine.deploy(target_slot=EnvironmentSlot.GREEN)

        assert res.success is False
        assert res.status == DeploymentStatus.HEALTH_CHECK_FAILED
        assert res.new_active_slot == EnvironmentSlot.BLUE  # Unchanged
        assert engine.get_current_active_slot() == EnvironmentSlot.BLUE
        assert "Traffic unchanged" in res.message


def test_post_switch_health_failure_triggers_auto_rollback(test_config: DeployerConfig):
    """Verify automatic rollback to previous slot when post-switch health check fails."""
    engine = DeployEngine(config=test_config)
    engine.router.switch_to_target(EnvironmentSlot.BLUE, test_config.blue.config_path, validate_proxy=False)

    # Sequence: 1. Pre-switch green (200 OK), 2. Post-switch green (500 ERR), 3. Rollback blue check (200 OK)
    responses = [
        httpx.Response(200, text="OK", request=httpx.Request("GET", test_config.green.url)),
        httpx.Response(500, text="Internal Error", request=httpx.Request("GET", test_config.green.url)),
        httpx.Response(200, text="OK", request=httpx.Request("GET", test_config.blue.url)),
    ]

    with patch.object(httpx.Client, "get", side_effect=responses):
        res = engine.deploy(target_slot=EnvironmentSlot.GREEN)

        assert res.success is False
        assert res.status == DeploymentStatus.ROLLED_BACK
        assert res.new_active_slot == EnvironmentSlot.BLUE
        assert res.rollback_result is not None
        assert res.rollback_result.success is True
        assert engine.get_current_active_slot() == EnvironmentSlot.BLUE


def test_deploy_lock_contention(test_config: DeployerConfig):
    """Verify deployment fails gracefully when deployment lock is already held."""
    engine = DeployEngine(config=test_config)

    with patch.object(DeploymentLock, "acquire", side_effect=DeploymentLockTimeoutError("Lock held")):
        res = engine.deploy(target_slot=EnvironmentSlot.GREEN)
        assert res.success is False
        assert res.status == DeploymentStatus.FAILED
        assert "contention" in res.message.lower()


def test_manual_switch(test_config: DeployerConfig):
    """Verify manual switch command with health check and forced bypass."""
    engine = DeployEngine(config=test_config)

    mock_resp = httpx.Response(200, text="OK", request=httpx.Request("GET", test_config.green.url))
    with patch.object(httpx.Client, "get", return_value=mock_resp):
        res = engine.manual_switch(EnvironmentSlot.GREEN, skip_health=False)
        assert res.success is True
        assert res.new_active_slot == EnvironmentSlot.GREEN

    # Force switch to BLUE bypassing health check
    res_force = engine.manual_switch(EnvironmentSlot.BLUE, skip_health=True)
    assert res_force.success is True
    assert res_force.new_active_slot == EnvironmentSlot.BLUE


def test_manual_rollback(test_config: DeployerConfig):
    """Verify manual operator rollback execution."""
    engine = DeployEngine(config=test_config)
    engine.router.switch_to_target(EnvironmentSlot.GREEN, test_config.green.config_path, validate_proxy=False)

    mock_resp = httpx.Response(200, text="OK", request=httpx.Request("GET", test_config.blue.url))
    with patch.object(httpx.Client, "get", return_value=mock_resp):
        res = engine.manual_rollback(reason="Operator emergency rollback")
        assert res.success is True
        assert res.restored_slot == EnvironmentSlot.BLUE


def test_get_status(test_config: DeployerConfig):
    """Verify status query outputs full telemetry for active, passive and live health."""
    engine = DeployEngine(config=test_config)
    engine.router.switch_to_target(EnvironmentSlot.BLUE, test_config.blue.config_path, validate_proxy=False)

    mock_resp = httpx.Response(200, text="OK", request=httpx.Request("GET", test_config.blue.url))
    with patch.object(httpx.Client, "get", return_value=mock_resp):
        status = engine.get_status()
        assert status["active_slot"] == "blue"
        assert status["passive_slot"] == "green"
        assert status["blue"]["healthy"] is True
        assert status["green"]["healthy"] is True


def test_deployment_result_to_dict():
    """Verify DeploymentResult serialization."""
    res = DeploymentResult(
        success=True,
        status=DeploymentStatus.SUCCESS,
        previous_active_slot=EnvironmentSlot.BLUE,
        new_active_slot=EnvironmentSlot.GREEN,
        target_slot=EnvironmentSlot.GREEN,
        total_duration_ms=45.2,
        message="Deployed",
    )
    d = res.to_dict()
    assert d["success"] is True
    assert d["status"] == "success"
    assert d["previous_active_slot"] == "blue"
    assert d["new_active_slot"] == "green"
    assert d["total_duration_ms"] == 45.2
