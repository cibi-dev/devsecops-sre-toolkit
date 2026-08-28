"""Process killer and crash simulator module with strict security whitelisting (CWE-250/CWE-20).

Supports:
- Target selection by PID or process name
- Signal dispatch (SIGTERM, SIGKILL, SIGINT, SIGHUP, SIGQUIT)
- System whitelist protection (PID 1, sshd, init, dbus, systemd, self)
- Custom user whitelist pattern enforcement
- Dry-run simulation
"""

from __future__ import annotations

import datetime
import fnmatch
import os
import signal
from typing import Any, Dict, List, Optional
import psutil
from pydantic import BaseModel, ConfigDict, Field, field_validator

from chaos.safety_guard import (
    ChaosSecurityError,
    ProtectedTargetError,
    SafetyGuard,
    check_root_privileges,
    validate_target_pid,
    validate_target_process_name,
)

VALID_SIGNALS: Dict[str, signal.Signals] = {
    "SIGTERM": signal.SIGTERM,
    "SIGKILL": signal.SIGKILL,
    "SIGINT": signal.SIGINT,
    "SIGHUP": signal.SIGHUP,
    "SIGQUIT": signal.SIGQUIT,
}


class ProcessTargetConfig(BaseModel):
    """Configuration schema for targeted process termination."""

    model_config = ConfigDict(extra="forbid")

    pid: Optional[int] = Field(default=None, description="Specific target PID")
    process_name: Optional[str] = Field(default=None, description="Process name or glob to target")
    signal_name: str = Field(
        default="SIGTERM",
        description="Signal to send (SIGTERM, SIGKILL, SIGINT, SIGHUP, SIGQUIT)",
    )
    whitelist_patterns: List[str] = Field(
        default_factory=list,
        description="Allowed process name patterns (e.g. ['worker*', 'redis*', 'app-*'])",
    )
    dry_run: bool = Field(default=False, description="Simulate termination without sending signal")

    @field_validator("signal_name")
    @classmethod
    def validate_sig(cls, v: str) -> str:
        upper = v.upper()
        if not upper.startswith("SIG"):
            upper = f"SIG{upper}"
        if upper not in VALID_SIGNALS:
            raise ValueError(
                f"Invalid signal '{v}'. Supported signals: {', '.join(VALID_SIGNALS.keys())}"
            )
        return upper

    @field_validator("pid")
    @classmethod
    def validate_target_pid_field(cls, v: Optional[int]) -> Optional[int]:
        if v is not None:
            return validate_target_pid(v)
        return v

    @field_validator("process_name")
    @classmethod
    def validate_target_name_field(cls, v: Optional[str]) -> Optional[str]:
        if v is not None:
            return validate_target_process_name(v)
        return v


class ProcessKillResult(BaseModel):
    """Result of terminating a single process."""

    model_config = ConfigDict(extra="forbid")

    pid: int
    name: str
    signal_sent: str
    signal_number: int
    timestamp: str
    dry_run: bool
    success: bool
    error: Optional[str] = None
    details: Dict[str, Any] = Field(default_factory=dict)


def is_process_whitelisted(proc_name: str, whitelist_patterns: List[str]) -> bool:
    """Check if process name matches any allowed whitelist pattern.

    If whitelist_patterns is empty, returns True provided it passed protected checks.
    """
    if not whitelist_patterns:
        return True

    name_lower = proc_name.lower()
    for pattern in whitelist_patterns:
        pat_lower = pattern.lower()
        if fnmatch.fnmatch(name_lower, pat_lower) or pat_lower in name_lower:
            return True
    return False


def find_target_processes(config: ProcessTargetConfig) -> List[psutil.Process]:
    """Find and validate target processes matching the configuration."""
    if config.pid is None and not config.process_name:
        raise ValueError("Either 'pid' or 'process_name' must be specified.")

    targets: List[psutil.Process] = []

    if config.pid is not None:
        validate_target_pid(config.pid)
        try:
            p = psutil.Process(config.pid)
            proc_name = p.name()
            validate_target_process_name(proc_name)

            if not is_process_whitelisted(proc_name, config.whitelist_patterns):
                raise ProtectedTargetError(
                    f"Process '{proc_name}' (PID {config.pid}) does not match allowed whitelist patterns: "
                    f"{config.whitelist_patterns}"
                )
            targets.append(p)
        except psutil.NoSuchProcess:
            raise ValueError(f"No active process found with PID {config.pid}")

    elif config.process_name:
        sanitized_name = validate_target_process_name(config.process_name)

        if config.whitelist_patterns and not is_process_whitelisted(sanitized_name, config.whitelist_patterns):
            raise ProtectedTargetError(
                f"Target process name '{sanitized_name}' does not match allowed whitelist patterns: "
                f"{config.whitelist_patterns}"
            )

        for p in psutil.process_iter(["pid", "name", "cmdline"]):
            try:
                p_name = p.info.get("name") or ""
                p_pid = p.info.get("pid")
                if not p_pid or not p_name:
                    continue

                if fnmatch.fnmatch(p_name.lower(), sanitized_name.lower()) or sanitized_name.lower() in p_name.lower():
                    # Validate PID and name against protected lists
                    try:
                        validate_target_pid(p_pid)
                        validate_target_process_name(p_name)
                        if is_process_whitelisted(p_name, config.whitelist_patterns):
                            targets.append(p)
                    except ChaosSecurityError:
                        continue
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

    return targets


def kill_target_process(
    proc: psutil.Process,
    sig: signal.Signals,
    dry_run: bool = False,
) -> ProcessKillResult:
    """Send signal to target process with safety validation."""
    pid = proc.pid
    name = proc.name() if hasattr(proc, "name") else "unknown"
    now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()

    validate_target_pid(pid)
    validate_target_process_name(name)

    if dry_run:
        return ProcessKillResult(
            pid=pid,
            name=name,
            signal_sent=sig.name,
            signal_number=sig.value,
            timestamp=now_iso,
            dry_run=True,
            success=True,
            details={"status": "simulated_kill"},
        )

    try:
        proc.send_signal(sig)
        return ProcessKillResult(
            pid=pid,
            name=name,
            signal_sent=sig.name,
            signal_number=sig.value,
            timestamp=now_iso,
            dry_run=False,
            success=True,
            details={"status": "signal_dispatched"},
        )
    except psutil.AccessDenied as e:
        check_root_privileges(dry_run=False)
        return ProcessKillResult(
            pid=pid,
            name=name,
            signal_sent=sig.name,
            signal_number=sig.value,
            timestamp=now_iso,
            dry_run=False,
            success=False,
            error=f"Permission denied: {e}",
        )
    except psutil.NoSuchProcess:
        return ProcessKillResult(
            pid=pid,
            name=name,
            signal_sent=sig.name,
            signal_number=sig.value,
            timestamp=now_iso,
            dry_run=False,
            success=False,
            error="Process exited before signal could be delivered",
        )
    except Exception as e:
        return ProcessKillResult(
            pid=pid,
            name=name,
            signal_sent=sig.name,
            signal_number=sig.value,
            timestamp=now_iso,
            dry_run=False,
            success=False,
            error=str(e),
        )


def terminate_processes(
    config: ProcessTargetConfig,
    safety_guard: Optional[SafetyGuard] = None,
) -> List[ProcessKillResult]:
    """Find and terminate matching processes according to security policy.

    Args:
        config: ProcessTargetConfig parameters.
        safety_guard: Optional SafetyGuard instance.

    Returns:
        List of ProcessKillResult.
    """
    sig = VALID_SIGNALS[config.signal_name]
    targets = find_target_processes(config)

    if not targets:
        return []

    results: List[ProcessKillResult] = []
    for proc in targets:
        res = kill_target_process(proc, sig, dry_run=config.dry_run)
        results.append(res)

    return results
