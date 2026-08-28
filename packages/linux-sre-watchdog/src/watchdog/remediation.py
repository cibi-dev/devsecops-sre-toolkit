"""Safe execution of predefined SRE runbooks for Linux SRE Watchdog.

Enforces strict privilege separation (CWE-250 / CWE-269) and whitelisted, non-shell
subprocess execution (CWE-78).
"""

from __future__ import annotations

import os
import re
import signal
import subprocess
import time
from typing import Any, Callable, Optional

from pydantic import BaseModel, ConfigDict, Field

from watchdog.circuit_breaker import CircuitBreaker
from watchdog.engine import AnomalyEvent


class PrivilegeError(PermissionError):
    """Raised when a mutating runbook is executed without root privileges."""


class RunbookResult(BaseModel):
    """Result of an executed or simulated remediation runbook."""

    model_config = ConfigDict(extra="forbid")

    runbook_name: str = Field(description="Identifier of executed runbook")
    success: bool = Field(description="True if remediation completed successfully")
    dry_run: bool = Field(description="True if run in dry-run simulation mode")
    stdout: str = Field(default="", description="Captured standard output")
    stderr: str = Field(default="", description="Captured standard error or failure message")
    execution_time_ms: float = Field(default=0.0, description="Duration of runbook execution in ms")
    details: dict[str, Any] = Field(default_factory=dict, description="Metadata and outcome details")


# Safe whitelist for service names (CWE-78)
SERVICE_NAME_RE = re.compile(r"^[a-zA-Z0-9_\-\.@]+$")


class RemediationManager:
    """Manages secure execution of predefined SRE runbooks."""

    def __init__(
        self,
        circuit_breaker: Optional[CircuitBreaker] = None,
        custom_executor: Optional[Callable[[list[str], float], tuple[int, str, str]]] = None,
    ) -> None:
        self.circuit_breaker = circuit_breaker or CircuitBreaker()
        self._custom_executor = custom_executor

    @staticmethod
    def is_root() -> bool:
        """Verify if current process possesses root privileges (EUID == 0)."""
        return os.geteuid() == 0

    def _run_command(self, cmd: list[str], timeout: float = 15.0) -> tuple[int, str, str]:
        """Execute command safely via subprocess (shell=False, CWE-78)."""
        if self._custom_executor is not None:
            return self._custom_executor(cmd, timeout)

        try:
            proc = subprocess.run(
                cmd,
                shell=False,
                timeout=timeout,
                capture_output=True,
                text=True,
                check=False,
            )
            return proc.returncode, proc.stdout, proc.stderr
        except (subprocess.TimeoutExpired, OSError) as e:
            return 127, "", str(e)

    def execute_for_anomaly(
        self,
        anomaly: AnomalyEvent,
        dry_run: bool = False,
    ) -> Optional[RunbookResult]:
        """Execute recommended runbook for a detected anomaly."""
        if not anomaly.recommended_runbook:
            return None

        return self.execute_runbook(
            runbook_name=anomaly.recommended_runbook,
            dry_run=dry_run,
            details=anomaly.details,
        )

    def execute_runbook(
        self,
        runbook_name: str,
        dry_run: bool = False,
        details: Optional[dict[str, Any]] = None,
    ) -> RunbookResult:
        """Execute a specific runbook with circuit breaker and privilege guards."""
        start_time = time.monotonic()
        details = details or {}

        # 1. Anti-Flapping Circuit Breaker Guard
        if not self.circuit_breaker.can_execute(runbook_name):
            state = self.circuit_breaker.get_state(runbook_name)
            elapsed_ms = round((time.monotonic() - start_time) * 1000, 2)
            return RunbookResult(
                runbook_name=runbook_name,
                success=False,
                dry_run=dry_run,
                stderr=f"Blocked by anti-flapping circuit breaker (state={state.value})",
                execution_time_ms=elapsed_ms,
                details={"circuit_breaker_state": state.value, **details},
            )

        # 2. Dispatch to specific handler
        try:
            if runbook_name == "clear_pagecache":
                result = self._remediate_clear_pagecache(dry_run)
            elif runbook_name == "reap_zombies":
                result = self._remediate_reap_zombies(dry_run, details)
            elif runbook_name == "trim_journal":
                result = self._remediate_trim_journal(dry_run)
            elif runbook_name.startswith("restart_service:"):
                service = runbook_name.split(":", 1)[1]
                result = self._remediate_restart_service(service, dry_run)
            elif runbook_name == "throttle_high_cpu_tasks":
                result = self._remediate_throttle_cpu(dry_run, details)
            else:
                elapsed_ms = round((time.monotonic() - start_time) * 1000, 2)
                return RunbookResult(
                    runbook_name=runbook_name,
                    success=False,
                    dry_run=dry_run,
                    stderr=f"Unknown runbook: '{runbook_name}'",
                    execution_time_ms=elapsed_ms,
                    details=details,
                )

            elapsed_ms = round((time.monotonic() - start_time) * 1000, 2)
            result = result.model_copy(update={"execution_time_ms": elapsed_ms})

            # 3. Update Circuit Breaker state (only on non-dry-run executions)
            if not dry_run:
                if result.success:
                    self.circuit_breaker.record_success(runbook_name)
                else:
                    self.circuit_breaker.record_failure(runbook_name, result.stderr)

            return result

        except PrivilegeError as e:
            elapsed_ms = round((time.monotonic() - start_time) * 1000, 2)
            msg = str(e)
            if not dry_run:
                self.circuit_breaker.record_failure(runbook_name, msg)
            return RunbookResult(
                runbook_name=runbook_name,
                success=False,
                dry_run=dry_run,
                stderr=msg,
                execution_time_ms=elapsed_ms,
                details={"privilege_error": True, **details},
            )

    def _require_root(self, action: str) -> None:
        """Enforce root privileges (CWE-250/269) for mutating operations."""
        if not self.is_root():
            euid = os.geteuid()
            raise PrivilegeError(
                f"Action '{action}' requires root privileges (euid=0), currently euid={euid}. Aborting."
            )

    def _remediate_clear_pagecache(self, dry_run: bool) -> RunbookResult:
        """Flush dirty pages and safely drop Linux kernel pagecache."""
        if dry_run:
            return RunbookResult(
                runbook_name="clear_pagecache",
                success=True,
                dry_run=True,
                stdout="[DRY-RUN] Would sync dirty pages and write '1' to /proc/sys/vm/drop_caches",
            )

        self._require_root("clear_pagecache")

        try:
            # Sync filesystem before dropping cache
            os.sync()
            drop_caches_path = "/proc/sys/vm/drop_caches"
            with open(drop_caches_path, "w", encoding="utf-8") as f:
                f.write("1\n")
            return RunbookResult(
                runbook_name="clear_pagecache",
                success=True,
                dry_run=False,
                stdout="Successfully synced and flushed kernel pagecache.",
            )
        except OSError as e:
            return RunbookResult(
                runbook_name="clear_pagecache",
                success=False,
                dry_run=False,
                stderr=f"Failed to drop caches: {e}",
            )

    def _remediate_reap_zombies(self, dry_run: bool, details: dict[str, Any]) -> RunbookResult:
        """Send SIGCHLD to parents of zombie processes to trigger waitpid reap."""
        zombies = details.get("zombies", [])
        if not zombies and "zombie_pids" in details:
            zombies = [{"pid": p, "ppid": 1, "comm": "unknown"} for p in details["zombie_pids"]]

        if dry_run:
            return RunbookResult(
                runbook_name="reap_zombies",
                success=True,
                dry_run=True,
                stdout=f"[DRY-RUN] Would send SIGCHLD to parents of {len(zombies)} zombies.",
                details={"target_zombies": zombies},
            )

        signaled_ppids: set[int] = set()
        errors: list[str] = []

        for z in zombies:
            ppid = z.get("ppid", 1)
            if ppid > 1 and ppid not in signaled_ppids:
                try:
                    os.kill(ppid, signal.SIGCHLD)
                    signaled_ppids.add(ppid)
                except ProcessLookupError:
                    pass
                except PermissionError:
                    # Root privilege required to signal processes of other users
                    if not self.is_root():
                        raise PrivilegeError(
                            f"Signaling PPID {ppid} requires root privileges (euid={os.geteuid()})"
                        )
                    errors.append(f"Permission denied signaling PPID {ppid}")

        success = len(errors) == 0
        return RunbookResult(
            runbook_name="reap_zombies",
            success=success,
            dry_run=False,
            stdout=f"Sent SIGCHLD to {len(signaled_ppids)} parent process(es).",
            stderr="; ".join(errors) if errors else "",
            details={"signaled_ppids": list(signaled_ppids)},
        )

    def _remediate_restart_service(self, service_name: str, dry_run: bool) -> RunbookResult:
        """Restart a failed or degraded systemd unit safely."""
        # Sanitize service name against injection (CWE-78)
        if not SERVICE_NAME_RE.match(service_name):
            return RunbookResult(
                runbook_name=f"restart_service:{service_name}",
                success=False,
                dry_run=dry_run,
                stderr=f"Invalid service name syntax: '{service_name}'",
            )

        if dry_run:
            return RunbookResult(
                runbook_name=f"restart_service:{service_name}",
                success=True,
                dry_run=True,
                stdout=f"[DRY-RUN] Would execute 'systemctl restart {service_name}'",
            )

        self._require_root(f"restart_service:{service_name}")

        cmd = ["systemctl", "restart", service_name]
        code, stdout, stderr = self._run_command(cmd, timeout=15.0)

        return RunbookResult(
            runbook_name=f"restart_service:{service_name}",
            success=(code == 0),
            dry_run=False,
            stdout=stdout.strip() or f"Service {service_name} restarted successfully.",
            stderr=stderr.strip(),
            details={"returncode": code},
        )

    def _remediate_trim_journal(self, dry_run: bool) -> RunbookResult:
        """Vacuum systemd journal logs to prevent disk saturation."""
        if dry_run:
            return RunbookResult(
                runbook_name="trim_journal",
                success=True,
                dry_run=True,
                stdout="[DRY-RUN] Would execute 'journalctl --vacuum-size=100M'",
            )

        self._require_root("trim_journal")

        cmd = ["journalctl", "--vacuum-size=100M"]
        code, stdout, stderr = self._run_command(cmd, timeout=15.0)

        return RunbookResult(
            runbook_name="trim_journal",
            success=(code == 0),
            dry_run=False,
            stdout=stdout.strip() or "Journal logs vacuumed to 100M limit.",
            stderr=stderr.strip(),
            details={"returncode": code},
        )

    def _remediate_throttle_cpu(self, dry_run: bool, details: dict[str, Any]) -> RunbookResult:
        """Placeholder for CPU throttle runbook."""
        if dry_run:
            return RunbookResult(
                runbook_name="throttle_high_cpu_tasks",
                success=True,
                dry_run=True,
                stdout="[DRY-RUN] CPU throttle alert evaluated.",
            )

        return RunbookResult(
            runbook_name="throttle_high_cpu_tasks",
            success=True,
            dry_run=False,
            stdout="CPU throttle alert recorded.",
            details=details,
        )
