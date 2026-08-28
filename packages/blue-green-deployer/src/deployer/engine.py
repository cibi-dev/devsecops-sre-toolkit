"""Main orchestrator engine for zero-downtime Blue/Green deployments.

Coordinates concurrency locks, pre-switch health validation, atomic symlink switching,
post-switch health validation, and deterministic auto-rollback.
"""

from __future__ import annotations

import json
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Optional

from deployer.config import (
    DeployerConfig,
    DeploymentStatus,
    EnvironmentSlot,
    TargetEnvironmentConfig,
)
from deployer.health import HealthChecker, HealthCheckResult
from deployer.lock import DeploymentLock, DeploymentLockTimeoutError
from deployer.rollback import RollbackManager, RollbackResult
from deployer.router import SwitchResult, TrafficRouter


@dataclass
class DeploymentResult:
    """Complete summary of a deployment execution."""

    success: bool
    status: DeploymentStatus
    previous_active_slot: Optional[EnvironmentSlot]
    new_active_slot: Optional[EnvironmentSlot]
    target_slot: EnvironmentSlot
    pre_switch_health: Optional[HealthCheckResult] = None
    switch_result: Optional[SwitchResult] = None
    post_switch_health: Optional[HealthCheckResult] = None
    rollback_result: Optional[RollbackResult] = None
    total_duration_ms: float = 0.0
    message: str = ""
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        """Convert deployment result to a serializable dictionary."""
        return {
            "success": self.success,
            "status": self.status.value,
            "previous_active_slot": self.previous_active_slot.value if self.previous_active_slot else None,
            "new_active_slot": self.new_active_slot.value if self.new_active_slot else None,
            "target_slot": self.target_slot.value,
            "total_duration_ms": round(self.total_duration_ms, 2),
            "message": self.message,
            "timestamp": self.timestamp,
            "pre_switch_health": self.pre_switch_health.to_dict() if self.pre_switch_health else None,
            "switch_result": self.switch_result.to_dict() if self.switch_result else None,
            "post_switch_health": self.post_switch_health.to_dict() if self.post_switch_health else None,
            "rollback_result": self.rollback_result.to_dict() if self.rollback_result else None,
        }


class DeployEngine:
    """Orchestrator for managing Blue/Green deployments."""

    def __init__(self, config: Optional[DeployerConfig] = None) -> None:
        self.config = config or DeployerConfig()
        self.lock = DeploymentLock(config=self.config.lock)
        self.router = TrafficRouter(
            config=self.config.router,
            allow_unprivileged=self.config.allow_unprivileged,
        )
        self.health_checker = HealthChecker(config=self.config.health)
        self.rollback_manager = RollbackManager(
            deployer_config=self.config,
            router=self.router,
            health_checker=self.health_checker,
        )

    def get_current_active_slot(self) -> Optional[EnvironmentSlot]:
        """Determine the current active slot from router symlink or persistent state."""
        return self.router.get_active_slot(self.config)

    def _persist_state(self, active_slot: EnvironmentSlot, status: DeploymentStatus) -> None:
        """Save deployment state to disk atomically."""
        try:
            self.config.state_file.parent.mkdir(parents=True, exist_ok=True)
            data = {
                "active_slot": active_slot.value,
                "status": status.value,
                "updated_at": time.time(),
            }
            tmp_state = self.config.state_file.parent / f".tmp_{self.config.state_file.name}_{time.time()}"
            with open(tmp_state, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
            tmp_state.replace(self.config.state_file)
        except Exception:
            pass  # Non-fatal state persistence failure

    def get_status(self) -> Dict[str, Any]:
        """Query deployment status, active/passive slots, and live health of both environments."""
        active_slot = self.get_current_active_slot()
        passive_slot = active_slot.opposite() if active_slot else EnvironmentSlot.GREEN

        blue_health = self.health_checker.check_target(
            self.config.blue, custom_retries=1, custom_required_consecutive=1
        )
        green_health = self.health_checker.check_target(
            self.config.green, custom_retries=1, custom_required_consecutive=1
        )

        return {
            "active_slot": active_slot.value if active_slot else "uninitialized",
            "passive_slot": passive_slot.value if active_slot else "uninitialized",
            "symlink_target": str(self.router.get_current_target_path()),
            "blue": {
                "url": self.config.blue.url,
                "healthy": blue_health.healthy,
                "latency_ms": round(blue_health.total_duration_ms, 2),
            },
            "green": {
                "url": self.config.green.url,
                "healthy": green_health.healthy,
                "latency_ms": round(green_health.total_duration_ms, 2),
            },
            "lock_held": self.lock.is_locked,
        }

    def deploy(self, target_slot: Optional[EnvironmentSlot] = None) -> DeploymentResult:
        """Execute a full zero-downtime Blue/Green deployment cycle with active verification and auto-rollback.

        Args:
            target_slot: Explicit target slot to activate. If None, targets the currently passive slot.

        Returns:
            DeploymentResult with full lifecycle metrics and status.
        """
        start_time = time.perf_counter()

        # Step 1: Acquire exclusive flock deployment lock (CWE-362)
        try:
            self.lock.acquire()
        except DeploymentLockTimeoutError as exc:
            elapsed_ms = (time.perf_counter() - start_time) * 1000.0
            return DeploymentResult(
                success=False,
                status=DeploymentStatus.FAILED,
                previous_active_slot=None,
                new_active_slot=None,
                target_slot=target_slot or EnvironmentSlot.GREEN,
                total_duration_ms=elapsed_ms,
                message=f"Deployment lock contention error: {exc}",
            )

        try:
            current_active = self.get_current_active_slot()
            if target_slot is None:
                destination_slot = current_active.opposite() if current_active else EnvironmentSlot.GREEN
            else:
                destination_slot = target_slot

            target_cfg: TargetEnvironmentConfig = self.config.get_slot_config(destination_slot)
            if target_cfg.config_path is None:
                target_conf_path = Path(tempfile.gettempdir()) / "blue_green" / f"upstream_{destination_slot.value}.conf"
            else:
                target_conf_path = target_cfg.config_path

            # Step 2: Pre-switch active HTTP health check on the passive/target environment
            pre_health = self.health_checker.check_target(target_cfg)
            if not pre_health.healthy:
                elapsed_ms = (time.perf_counter() - start_time) * 1000.0
                return DeploymentResult(
                    success=False,
                    status=DeploymentStatus.HEALTH_CHECK_FAILED,
                    previous_active_slot=current_active,
                    new_active_slot=current_active,
                    target_slot=destination_slot,
                    pre_switch_health=pre_health,
                    total_duration_ms=elapsed_ms,
                    message=f"Pre-switch health verification failed on {destination_slot.value.upper()}. Traffic unchanged.",
                )

            # Step 3: Atomic symlink traffic switch & proxy reload
            switch_res = self.router.switch_to_target(
                target_slot=destination_slot,
                target_config_path=target_conf_path,
                from_slot=current_active,
                validate_proxy=True,
            )

            if not switch_res.success:
                elapsed_ms = (time.perf_counter() - start_time) * 1000.0
                return DeploymentResult(
                    success=False,
                    status=DeploymentStatus.FAILED,
                    previous_active_slot=current_active,
                    new_active_slot=current_active,
                    target_slot=destination_slot,
                    pre_switch_health=pre_health,
                    switch_result=switch_res,
                    total_duration_ms=elapsed_ms,
                    message=f"Atomic traffic switch failed: {switch_res.error_message}",
                )

            # Step 4: Post-switch active HTTP health check verification
            post_health = self.health_checker.check_target(
                target_cfg,
                custom_retries=self.config.rollback.post_switch_health_checks,
                custom_interval=self.config.rollback.post_switch_interval_seconds,
                custom_required_consecutive=self.config.rollback.post_switch_health_checks,
            )

            # Step 5: If post-switch health check fails, execute automatic rollback
            if not post_health.healthy:
                rollback_res: Optional[RollbackResult] = None
                if self.config.rollback.auto_rollback_enabled and current_active is not None:
                    rollback_res = self.rollback_manager.execute_rollback(
                        failed_slot=destination_slot,
                        target_restore_slot=current_active,
                        reason="Post-switch health validation failed",
                        verify_health_after_rollback=True,
                    )
                    self._persist_state(current_active, DeploymentStatus.ROLLED_BACK)

                elapsed_ms = (time.perf_counter() - start_time) * 1000.0
                return DeploymentResult(
                    success=False,
                    status=DeploymentStatus.ROLLED_BACK if rollback_res and rollback_res.success else DeploymentStatus.FAILED,
                    previous_active_slot=current_active,
                    new_active_slot=current_active if rollback_res and rollback_res.success else destination_slot,
                    target_slot=destination_slot,
                    pre_switch_health=pre_health,
                    switch_result=switch_res,
                    post_switch_health=post_health,
                    rollback_result=rollback_res,
                    total_duration_ms=elapsed_ms,
                    message="Post-switch verification failed. Automatic rollback executed."
                    if (rollback_res and rollback_res.success)
                    else "Post-switch verification failed.",
                )

            # Step 6: Successful deployment completion
            self._persist_state(destination_slot, DeploymentStatus.SUCCESS)
            elapsed_ms = (time.perf_counter() - start_time) * 1000.0

            return DeploymentResult(
                success=True,
                status=DeploymentStatus.SUCCESS,
                previous_active_slot=current_active,
                new_active_slot=destination_slot,
                target_slot=destination_slot,
                pre_switch_health=pre_health,
                switch_result=switch_res,
                post_switch_health=post_health,
                total_duration_ms=elapsed_ms,
                message=f"Deployment successfully completed. Active slot: {destination_slot.value.upper()}.",
            )

        finally:
            self.lock.release()

    def manual_switch(self, target_slot: EnvironmentSlot, skip_health: bool = False) -> DeploymentResult:
        """Manually switch traffic to a target slot with optional health bypass.

        Args:
            target_slot: The slot to switch traffic to.
            skip_health: If True, bypasses pre-switch health check.

        Returns:
            DeploymentResult summarizing the switch.
        """
        start_time = time.perf_counter()
        self.lock.acquire()
        try:
            current_active = self.get_current_active_slot()
            target_cfg = self.config.get_slot_config(target_slot)
            target_conf = target_cfg.config_path or (Path(tempfile.gettempdir()) / "blue_green" / f"upstream_{target_slot.value}.conf")

            pre_health = None
            if not skip_health:
                pre_health = self.health_checker.check_target(target_cfg)
                if not pre_health.healthy:
                    elapsed_ms = (time.perf_counter() - start_time) * 1000.0
                    return DeploymentResult(
                        success=False,
                        status=DeploymentStatus.HEALTH_CHECK_FAILED,
                        previous_active_slot=current_active,
                        new_active_slot=current_active,
                        target_slot=target_slot,
                        pre_switch_health=pre_health,
                        total_duration_ms=elapsed_ms,
                        message=f"Manual switch aborted: target slot {target_slot.value.upper()} is unhealthy.",
                    )

            switch_res = self.router.switch_to_target(
                target_slot=target_slot,
                target_config_path=target_conf,
                from_slot=current_active,
                validate_proxy=True,
            )

            elapsed_ms = (time.perf_counter() - start_time) * 1000.0
            if switch_res.success:
                self._persist_state(target_slot, DeploymentStatus.SUCCESS)
                return DeploymentResult(
                    success=True,
                    status=DeploymentStatus.SUCCESS,
                    previous_active_slot=current_active,
                    new_active_slot=target_slot,
                    target_slot=target_slot,
                    pre_switch_health=pre_health,
                    switch_result=switch_res,
                    total_duration_ms=elapsed_ms,
                    message=f"Traffic manually switched to {target_slot.value.upper()}.",
                )
            else:
                return DeploymentResult(
                    success=False,
                    status=DeploymentStatus.FAILED,
                    previous_active_slot=current_active,
                    new_active_slot=current_active,
                    target_slot=target_slot,
                    pre_switch_health=pre_health,
                    switch_result=switch_res,
                    total_duration_ms=elapsed_ms,
                    message=f"Manual switch failed: {switch_res.error_message}",
                )
        finally:
            self.lock.release()

    def manual_rollback(self, reason: str = "Manual operator rollback") -> RollbackResult:
        """Trigger immediate manual rollback to the opposite environment slot."""
        self.lock.acquire()
        try:
            current_active = self.get_current_active_slot()
            if current_active is None:
                current_active = EnvironmentSlot.GREEN
            restore_slot = current_active.opposite()

            res = self.rollback_manager.execute_rollback(
                failed_slot=current_active,
                target_restore_slot=restore_slot,
                reason=reason,
                verify_health_after_rollback=True,
            )
            if res.success:
                self._persist_state(restore_slot, DeploymentStatus.ROLLED_BACK)
            return res
        finally:
            self.lock.release()
