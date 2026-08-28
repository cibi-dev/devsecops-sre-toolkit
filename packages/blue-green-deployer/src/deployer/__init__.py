"""Enterprise-grade Zero-Downtime Blue/Green Deployment Orchestrator for Linux.

Exports core configuration, router, health checker, rollback manager,
concurrency lock, and deploy engine.
"""

from __future__ import annotations

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
from deployer.health import HealthChecker, HealthCheckResult, HealthProbeResult
from deployer.lock import DeploymentLock, DeploymentLockError, DeploymentLockTimeoutError
from deployer.rollback import RollbackError, RollbackManager, RollbackResult
from deployer.router import PrivilegeError, ProxyReloadError, RouterError, SwitchResult, TrafficRouter

__version__ = "0.1.0"

__all__ = [
    "DeployerConfig",
    "DeploymentStatus",
    "EnvironmentSlot",
    "HealthCheckConfig",
    "LockConfig",
    "RollbackConfig",
    "RouterConfig",
    "TargetEnvironmentConfig",
    "DeployEngine",
    "DeploymentResult",
    "HealthChecker",
    "HealthCheckResult",
    "HealthProbeResult",
    "DeploymentLock",
    "DeploymentLockError",
    "DeploymentLockTimeoutError",
    "RollbackError",
    "RollbackManager",
    "RollbackResult",
    "PrivilegeError",
    "ProxyReloadError",
    "RouterError",
    "SwitchResult",
    "TrafficRouter",
    "__version__",
]
