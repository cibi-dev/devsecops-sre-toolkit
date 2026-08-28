"""Deterministic fast rollback controller for Blue/Green deployments.

Guarantees atomic rollback of traffic to the previous healthy slot in <30 seconds
upon post-switch validation failures or manual rollback requests.
"""

from __future__ import annotations

import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Optional

from deployer.config import DeployerConfig, EnvironmentSlot, RollbackConfig
from deployer.health import HealthChecker
from deployer.router import SwitchResult, TrafficRouter


class RollbackError(Exception):
    """Raised when a rollback operation encounters a critical failure."""
    pass


@dataclass
class RollbackResult:
    """Detailed summary of a completed or failed rollback operation."""

    success: bool
    restored_slot: EnvironmentSlot
    failed_slot: EnvironmentSlot
    trigger_reason: str
    rollback_duration_ms: float
    restored_health: bool
    switch_result: Optional[SwitchResult] = None
    error_message: Optional[str] = None
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize rollback result to dictionary."""
        return {
            "success": self.success,
            "restored_slot": self.restored_slot.value,
            "failed_slot": self.failed_slot.value,
            "trigger_reason": self.trigger_reason,
            "rollback_duration_ms": round(self.rollback_duration_ms, 2),
            "restored_health": self.restored_health,
            "switch_result": self.switch_result.to_dict() if self.switch_result else None,
            "error_message": self.error_message,
            "timestamp": self.timestamp,
        }


class RollbackManager:
    """Orchestrates deterministic rollbacks with health verification and strict SLA timing."""

    def __init__(
        self,
        deployer_config: DeployerConfig,
        router: Optional[TrafficRouter] = None,
        health_checker: Optional[HealthChecker] = None,
    ) -> None:
        self.config = deployer_config
        self.rollback_config: RollbackConfig = deployer_config.rollback
        self.router = router or TrafficRouter(
            config=deployer_config.router,
            allow_unprivileged=deployer_config.allow_unprivileged,
        )
        self.health_checker = health_checker or HealthChecker(config=deployer_config.health)

    def execute_rollback(
        self,
        failed_slot: EnvironmentSlot,
        target_restore_slot: Optional[EnvironmentSlot] = None,
        reason: str = "Post-switch health check failure",
        verify_health_after_rollback: bool = True,
    ) -> RollbackResult:
        """Execute deterministic traffic rollback to previous healthy slot within SLA limit (<30s).

        Args:
            failed_slot: The slot that failed post-switch or needs to be abandoned.
            target_restore_slot: The slot to restore (defaults to opposite of failed_slot).
            reason: Description of the failure trigger.
            verify_health_after_rollback: Whether to probe restored slot health immediately.

        Returns:
            RollbackResult containing timings, health state, and switch outcome.
        """
        start_time = time.perf_counter()
        restore_slot = target_restore_slot or failed_slot.opposite()
        restore_target_cfg = self.config.get_slot_config(restore_slot)

        if restore_target_cfg.config_path is None:
            config_path = Path(tempfile.gettempdir()) / "blue_green" / f"upstream_{restore_slot.value}.conf"
        else:
            config_path = restore_target_cfg.config_path

        # 1. Atomically revert symlink & reload proxy
        switch_res = self.router.switch_to_target(
            target_slot=restore_slot,
            target_config_path=config_path,
            from_slot=failed_slot,
            validate_proxy=True,
        )

        if not switch_res.success:
            elapsed_ms = (time.perf_counter() - start_time) * 1000.0
            return RollbackResult(
                success=False,
                restored_slot=restore_slot,
                failed_slot=failed_slot,
                trigger_reason=reason,
                rollback_duration_ms=elapsed_ms,
                restored_health=False,
                switch_result=switch_res,
                error_message=f"Symlink switch during rollback failed: {switch_res.error_message}",
            )

        # 2. Verify restored environment health
        restored_healthy = True
        if verify_health_after_rollback:
            health_res = self.health_checker.check_target(
                restore_target_cfg,
                custom_retries=2,
                custom_interval=0.2,
                custom_required_consecutive=1,
            )
            restored_healthy = health_res.healthy

        elapsed_ms = (time.perf_counter() - start_time) * 1000.0

        # Verify SLA (<30s SLA)
        if elapsed_ms > self.rollback_config.max_rollback_timeout_seconds * 1000.0:
            return RollbackResult(
                success=False,
                restored_slot=restore_slot,
                failed_slot=failed_slot,
                trigger_reason=reason,
                rollback_duration_ms=elapsed_ms,
                restored_health=restored_healthy,
                switch_result=switch_res,
                error_message=f"Rollback SLA exceeded: {elapsed_ms:.1f}ms > {self.rollback_config.max_rollback_timeout_seconds * 1000:.1f}ms",
            )

        return RollbackResult(
            success=True,
            restored_slot=restore_slot,
            failed_slot=failed_slot,
            trigger_reason=reason,
            rollback_duration_ms=elapsed_ms,
            restored_health=restored_healthy,
            switch_result=switch_res,
        )
