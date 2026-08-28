"""Network fault injector module using Linux tc / netem.

Supports:
- Packet latency (ms) with optional jitter (ms) and correlation (%)
- Packet loss (%)
- Packet corruption (%)
- Packet duplication (%)
- Packet reordering (%)
- Atomic rollback via tc qdisc del
- Strict subprocess execution (shell=False) and root verification (CWE-250/CWE-78)
"""

from __future__ import annotations

import datetime
import subprocess
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field, field_validator

from chaos.safety_guard import (
    MAX_EXPERIMENT_DURATION,
    SafetyGuard,
    check_root_privileges,
    validate_target_interface,
)


class NetworkFaultConfig(BaseModel):
    """Configuration schema for Linux tc / netem network fault injection."""

    model_config = ConfigDict(extra="forbid")

    interface: str = Field(..., description="Target network interface (e.g. eth0, ens33)")
    latency_ms: Optional[float] = Field(None, ge=0.0, le=10000.0, description="Added latency in milliseconds")
    jitter_ms: Optional[float] = Field(None, ge=0.0, le=5000.0, description="Latency jitter in milliseconds")
    correlation_pct: Optional[float] = Field(None, ge=0.0, le=100.0, description="Jitter/loss correlation percentage")
    loss_pct: Optional[float] = Field(None, ge=0.0, le=100.0, description="Packet loss percentage")
    corruption_pct: Optional[float] = Field(None, ge=0.0, le=100.0, description="Packet corruption percentage")
    duplicate_pct: Optional[float] = Field(None, ge=0.0, le=100.0, description="Packet duplicate percentage")
    reorder_pct: Optional[float] = Field(None, ge=0.0, le=100.0, description="Packet reordering percentage")
    duration_seconds: float = Field(
        default=10.0,
        gt=0.0,
        le=MAX_EXPERIMENT_DURATION,
        description="Fault duration before auto-recovery",
    )
    dry_run: bool = Field(default=False, description="Simulate without mutating tc qdisc")

    @field_validator("interface")
    @classmethod
    def validate_iface(cls, v: str) -> str:
        return validate_target_interface(v)

    @field_validator("jitter_ms")
    @classmethod
    def validate_jitter(cls, v: Optional[float], info: Any) -> Optional[float]:
        # If jitter is specified, latency should be present or valid
        return v


class NetworkFaultResult(BaseModel):
    """Execution result of a network fault injection."""

    model_config = ConfigDict(extra="forbid")

    interface: str
    success: bool
    dry_run: bool
    command_executed: List[str]
    rollback_command: List[str]
    timestamp: str
    duration_seconds: float
    output: str = ""
    error: Optional[str] = None
    parameters: Dict[str, Any] = Field(default_factory=dict)


def build_tc_command(config: NetworkFaultConfig) -> List[str]:
    """Construct the tc netem argument vector safely with shell=False (CWE-78)."""
    cmd = ["tc", "qdisc", "add", "dev", config.interface, "root", "netem"]

    if config.latency_ms is not None:
        cmd.extend(["delay", f"{config.latency_ms}ms"])
        if config.jitter_ms is not None:
            cmd.append(f"{config.jitter_ms}ms")
            if config.correlation_pct is not None:
                cmd.append(f"{config.correlation_pct}%")

    if config.loss_pct is not None:
        cmd.extend(["loss", f"{config.loss_pct}%"])
        if config.correlation_pct is not None and config.latency_ms is None:
            cmd.append(f"{config.correlation_pct}%")

    if config.corruption_pct is not None:
        cmd.extend(["corrupt", f"{config.corruption_pct}%"])

    if config.duplicate_pct is not None:
        cmd.extend(["duplicate", f"{config.duplicate_pct}%"])

    if config.reorder_pct is not None:
        cmd.extend(["reorder", f"{config.reorder_pct}%"])

    return cmd


def build_tc_rollback_command(interface: str) -> List[str]:
    """Construct the inverse tc command to clean up netem qdisc."""
    sanitized_iface = validate_target_interface(interface)
    return ["tc", "qdisc", "del", "dev", sanitized_iface, "root"]


def revert_network_fault(interface: str, dry_run: bool = False) -> bool:
    """Revert any tc netem configuration on the given interface.

    Args:
        interface: Target network interface.
        dry_run: If True, simulate rollback.

    Returns:
        True if rollback succeeded or no qdisc existed.
    """
    check_root_privileges(dry_run=dry_run)
    sanitized_iface = validate_target_interface(interface)
    rollback_cmd = build_tc_rollback_command(sanitized_iface)

    if dry_run:
        return True

    try:
        res = subprocess.run(
            rollback_cmd,
            capture_output=True,
            text=True,
            check=False,
            shell=False,
        )
        # Returncode 0 means deleted, 2 usually means "Cannot delete qdisc with handle of zero" / "No such file or directory"
        return res.returncode == 0 or "Cannot delete qdisc" in res.stderr or "No such file" in res.stderr
    except FileNotFoundError:
        # tc binary not found
        return False


def inject_network_fault(
    config: NetworkFaultConfig,
    safety_guard: Optional[SafetyGuard] = None,
) -> NetworkFaultResult:
    """Inject network fault via tc netem with automatic rollback registration.

    Args:
        config: NetworkFaultConfig parameters.
        safety_guard: Optional SafetyGuard instance for registering atomic rollback.

    Returns:
        NetworkFaultResult.
    """
    check_root_privileges(dry_run=config.dry_run)
    cmd = build_tc_command(config)
    rollback_cmd = build_tc_rollback_command(config.interface)
    now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()

    # Pre-register rollback in SafetyGuard before executing mutation
    if safety_guard is not None:
        safety_guard.register_rollback(
            callback=lambda: revert_network_fault(config.interface, dry_run=config.dry_run),
            description=f"Revert tc netem on interface {config.interface}",
        )

    if config.dry_run:
        return NetworkFaultResult(
            interface=config.interface,
            success=True,
            dry_run=True,
            command_executed=cmd,
            rollback_command=rollback_cmd,
            timestamp=now_iso,
            duration_seconds=config.duration_seconds,
            output="[DRY-RUN] Simulated tc netem command execution",
            parameters=config.model_dump(exclude={"dry_run"}),
        )

    try:
        # Clean any existing qdisc first to avoid conflict
        revert_network_fault(config.interface, dry_run=False)

        res = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=True,
            shell=False,
        )
        return NetworkFaultResult(
            interface=config.interface,
            success=True,
            dry_run=False,
            command_executed=cmd,
            rollback_command=rollback_cmd,
            timestamp=now_iso,
            duration_seconds=config.duration_seconds,
            output=res.stdout.strip(),
            parameters=config.model_dump(exclude={"dry_run"}),
        )
    except subprocess.CalledProcessError as e:
        return NetworkFaultResult(
            interface=config.interface,
            success=False,
            dry_run=False,
            command_executed=cmd,
            rollback_command=rollback_cmd,
            timestamp=now_iso,
            duration_seconds=config.duration_seconds,
            output=e.stdout or "",
            error=e.stderr.strip() if e.stderr else str(e),
            parameters=config.model_dump(exclude={"dry_run"}),
        )
    except FileNotFoundError as e:
        return NetworkFaultResult(
            interface=config.interface,
            success=False,
            dry_run=False,
            command_executed=cmd,
            rollback_command=rollback_cmd,
            timestamp=now_iso,
            duration_seconds=config.duration_seconds,
            output="",
            error=f"tc executable not found: {e}",
            parameters=config.model_dump(exclude={"dry_run"}),
        )
