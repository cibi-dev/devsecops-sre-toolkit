"""Configuration module for Blue/Green Deployer using Pydantic v2.

Defines schemas, constraints, and validation for Blue/Green environments,
health check parameters, atomic router symlinks, concurrency locks, and auto-rollback policies.
"""

from __future__ import annotations

import json
import tempfile
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


def _default_base_dir() -> Path:
    """Return platform-safe base runtime directory."""
    return Path(tempfile.gettempdir()) / "blue_green"


class EnvironmentSlot(str, Enum):
    """Identifier for Blue/Green deployment slots."""

    BLUE = "blue"
    GREEN = "green"

    def opposite(self) -> EnvironmentSlot:
        """Return the opposite deployment slot."""
        return EnvironmentSlot.GREEN if self == EnvironmentSlot.BLUE else EnvironmentSlot.BLUE

    def __str__(self) -> str:
        return self.value


class DeploymentStatus(str, Enum):
    """Lifecycle status of a Blue/Green deployment."""

    IDLE = "idle"
    VALIDATING_HEALTH = "validating_health"
    HEALTH_CHECK_FAILED = "health_check_failed"
    SWITCHING_TRAFFIC = "switching_traffic"
    SWITCHED = "switched"
    VALIDATING_POST_SWITCH = "validating_post_switch"
    SUCCESS = "success"
    ROLLING_BACK = "rolling_back"
    ROLLED_BACK = "rolled_back"
    FAILED = "failed"


class TargetEnvironmentConfig(BaseModel):
    """Configuration for an individual Blue or Green target environment."""

    name: EnvironmentSlot
    host: str = Field(default="127.0.0.1", min_length=1)
    port: int = Field(default=8081, ge=1, le=65535)
    health_endpoint: str = Field(default="/health")
    config_path: Optional[Path] = None
    weight: int = Field(default=1, ge=1, le=100)
    headers: Dict[str, str] = Field(default_factory=dict)

    @property
    def url(self) -> str:
        """Construct the absolute HTTP health check URL for this slot."""
        clean_endpoint = self.health_endpoint if self.health_endpoint.startswith("/") else f"/{self.health_endpoint}"
        return f"http://{self.host}:{self.port}{clean_endpoint}"

    @property
    def upstream_target(self) -> str:
        """Return host:port upstream representation."""
        return f"{self.host}:{self.port}"


class HealthCheckConfig(BaseModel):
    """Configuration for active HTTP health check probes."""

    endpoint: str = Field(default="/health")
    expected_status: int = Field(default=200, ge=100, le=599)
    expected_body_contains: Optional[str] = None
    timeout_seconds: float = Field(default=2.0, gt=0, le=60.0)
    max_retries: int = Field(default=3, ge=1, le=20)
    retry_interval_seconds: float = Field(default=0.5, ge=0.01, le=10.0)
    consecutive_successes_required: int = Field(default=2, ge=1, le=10)
    verify_ssl: bool = True


class RouterConfig(BaseModel):
    """Configuration for atomic symlink traffic routing and safe proxy reload."""

    symlink_path: Path = Field(default_factory=lambda: _default_base_dir() / "active_upstream.conf")
    backup_dir: Path = Field(default_factory=lambda: _default_base_dir() / "backups")
    reload_command: List[str] = Field(default_factory=lambda: ["nginx", "-s", "reload"])
    test_command: List[str] = Field(default_factory=lambda: ["nginx", "-t"])
    enable_proxy_reload: bool = True
    require_root: bool = False

    @field_validator("reload_command", "test_command")
    @classmethod
    def validate_command_not_empty(cls, v: List[str]) -> List[str]:
        """Ensure command list contains valid non-empty arguments."""
        if not v or not isinstance(v, list) or not all(isinstance(arg, str) and arg.strip() for arg in v):
            raise ValueError("Command must be a non-empty list of string arguments")
        return v


class RollbackConfig(BaseModel):
    """Configuration for deterministic auto-rollback triggers."""

    auto_rollback_enabled: bool = True
    post_switch_health_checks: int = Field(default=3, ge=1, le=10)
    post_switch_interval_seconds: float = Field(default=0.5, ge=0.01, le=10.0)
    max_rollback_timeout_seconds: float = Field(default=30.0, gt=0, le=30.0)


class LockConfig(BaseModel):
    """Configuration for concurrency flock locking (CWE-362 guardrail)."""

    lock_file_path: Path = Field(default_factory=lambda: Path(tempfile.gettempdir()) / "blue_green_deploy.lock")
    lock_timeout_seconds: float = Field(default=5.0, gt=0, le=5.0)  # CWE-362 guardrail: timeout <= 5s


class DeployerConfig(BaseModel):
    """Master configuration for the Blue/Green deployment engine."""

    model_config = ConfigDict(arbitrary_types_allowed=True, validate_assignment=True)

    blue: TargetEnvironmentConfig = Field(
        default_factory=lambda: TargetEnvironmentConfig(
            name=EnvironmentSlot.BLUE, host="127.0.0.1", port=8081, config_path=_default_base_dir() / "upstream_blue.conf"
        )
    )
    green: TargetEnvironmentConfig = Field(
        default_factory=lambda: TargetEnvironmentConfig(
            name=EnvironmentSlot.GREEN, host="127.0.0.1", port=8082, config_path=_default_base_dir() / "upstream_green.conf"
        )
    )
    health: HealthCheckConfig = Field(default_factory=HealthCheckConfig)
    router: RouterConfig = Field(default_factory=RouterConfig)
    rollback: RollbackConfig = Field(default_factory=RollbackConfig)
    lock: LockConfig = Field(default_factory=LockConfig)
    allow_unprivileged: bool = False
    state_file: Path = Field(default_factory=lambda: _default_base_dir() / "state.json")

    @model_validator(mode="after")
    def validate_distinct_slots(self) -> DeployerConfig:
        """Verify that Blue and Green environments use distinct endpoints and slots."""
        if self.blue.name == self.green.name:
            raise ValueError("Blue and Green configurations must have distinct slot names (blue, green)")
        if self.blue.host == self.green.host and self.blue.port == self.green.port:
            raise ValueError("Blue and Green environments must have distinct host:port bindings")
        return self

    def get_slot_config(self, slot: Union[EnvironmentSlot, str]) -> TargetEnvironmentConfig:
        """Retrieve target configuration by slot identifier."""
        slot_str = slot.value if isinstance(slot, EnvironmentSlot) else str(slot).lower()
        if slot_str == EnvironmentSlot.BLUE.value:
            return self.blue
        elif slot_str == EnvironmentSlot.GREEN.value:
            return self.green
        raise ValueError(f"Invalid environment slot: {slot}. Must be 'blue' or 'green'")

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> DeployerConfig:
        """Create DeployerConfig from dictionary."""
        return cls.model_validate(data)

    @classmethod
    def from_json(cls, json_str: str) -> DeployerConfig:
        """Load configuration from JSON string."""
        return cls.model_validate_json(json_str)

    @classmethod
    def from_file(cls, path: Union[str, Path]) -> DeployerConfig:
        """Load configuration from JSON file (or dictionary source)."""
        file_path = Path(path).resolve()
        if not file_path.exists():
            raise FileNotFoundError(f"Configuration file not found: {file_path}")
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return cls.model_validate(data)

    def to_dict(self) -> Dict[str, Any]:
        """Export configuration to dictionary."""
        return self.model_dump(mode="json")
