"""Unit tests for configuration validation (Pydantic v2)."""

import json
import tempfile
from pathlib import Path
import pytest
from pydantic import ValidationError

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


def test_environment_slot_enum():
    """Verify EnvironmentSlot enum behaviors and opposite toggle."""
    assert EnvironmentSlot.BLUE.value == "blue"
    assert EnvironmentSlot.GREEN.value == "green"
    assert str(EnvironmentSlot.BLUE) == "blue"
    assert EnvironmentSlot.BLUE.opposite() == EnvironmentSlot.GREEN
    assert EnvironmentSlot.GREEN.opposite() == EnvironmentSlot.BLUE


def test_target_environment_config_properties():
    """Verify URL construction and upstream representation."""
    target = TargetEnvironmentConfig(
        name=EnvironmentSlot.BLUE,
        host="10.0.0.5",
        port=8080,
        health_endpoint="api/v1/health",
    )
    assert target.url == "http://10.0.0.5:8080/api/v1/health"
    assert target.upstream_target == "10.0.0.5:8080"


def test_target_environment_invalid_port():
    """Verify validation error on invalid port numbers."""
    with pytest.raises(ValidationError):
        TargetEnvironmentConfig(name=EnvironmentSlot.BLUE, host="127.0.0.1", port=0)
    with pytest.raises(ValidationError):
        TargetEnvironmentConfig(name=EnvironmentSlot.BLUE, host="127.0.0.1", port=70000)


def test_deployer_config_defaults():
    """Verify default values in DeployerConfig."""
    cfg = DeployerConfig()
    assert cfg.blue.name == EnvironmentSlot.BLUE
    assert cfg.green.name == EnvironmentSlot.GREEN
    assert cfg.blue.port == 8081
    assert cfg.green.port == 8082
    assert cfg.health.endpoint == "/health"
    assert cfg.health.expected_status == 200
    assert cfg.lock.lock_timeout_seconds <= 5.0
    assert cfg.rollback.auto_rollback_enabled is True


def test_deployer_config_distinct_slots_validation():
    """Verify validation when Blue and Green slots conflict."""
    with pytest.raises(ValidationError, match="distinct host:port bindings"):
        DeployerConfig(
            blue=TargetEnvironmentConfig(name=EnvironmentSlot.BLUE, host="127.0.0.1", port=8080),
            green=TargetEnvironmentConfig(name=EnvironmentSlot.GREEN, host="127.0.0.1", port=8080),
        )


def test_router_config_empty_command_validation():
    """Verify that empty or whitespace-only reload commands are rejected."""
    with pytest.raises(ValidationError):
        RouterConfig(reload_command=[])
    with pytest.raises(ValidationError):
        RouterConfig(reload_command=[" "])
    with pytest.raises(ValidationError):
        RouterConfig(reload_command=[123])  # type: ignore


def test_lock_config_timeout_cap():
    """Verify that lock timeout > 5s is rejected by Pydantic validator."""
    with pytest.raises(ValidationError):
        LockConfig(lock_timeout_seconds=10.0)


def test_get_slot_config():
    """Verify slot retrieval by enum and string."""
    cfg = DeployerConfig()
    blue_cfg = cfg.get_slot_config(EnvironmentSlot.BLUE)
    assert blue_cfg.name == EnvironmentSlot.BLUE

    green_cfg = cfg.get_slot_config("green")
    assert green_cfg.name == EnvironmentSlot.GREEN

    with pytest.raises(ValueError, match="Invalid environment slot"):
        cfg.get_slot_config("yellow")


def test_config_serialization_roundtrip(tmp_path: Path):
    """Verify JSON dump and from_file loading."""
    cfg = DeployerConfig(allow_unprivileged=True)
    conf_file = tmp_path / "deployer_test_conf.json"
    conf_file.write_text(json.dumps(cfg.to_dict()), encoding="utf-8")

    loaded = DeployerConfig.from_file(conf_file)
    assert loaded.allow_unprivileged is True
    assert loaded.blue.port == 8081
    assert loaded.green.port == 8082


def test_config_from_dict():
    """Verify creation via from_dict()."""
    d = {"allow_unprivileged": True, "blue": {"name": "blue", "port": 8000}, "green": {"name": "green", "port": 8001}}
    cfg = DeployerConfig.from_dict(d)
    assert cfg.allow_unprivileged is True
    assert cfg.blue.port == 8000


def test_config_from_file_not_found():
    """Verify FileNotFoundError when config file does not exist."""
    with pytest.raises(FileNotFoundError):
        DeployerConfig.from_file(Path(tempfile.gettempdir()) / "non_existent_config_file_xyz.json")


def test_config_from_json_string():
    """Verify deserialization from JSON string."""
    json_str = json.dumps({
        "blue": {"name": "blue", "host": "127.0.0.1", "port": 9001},
        "green": {"name": "green", "host": "127.0.0.1", "port": 9002},
        "allow_unprivileged": True
    })
    cfg = DeployerConfig.from_json(json_str)
    assert cfg.blue.port == 9001
    assert cfg.green.port == 9002
    assert cfg.allow_unprivileged is True
