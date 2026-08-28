"""Systemd service inspection collector for Linux SRE Watchdog.

Inspects systemd service unit health with secure subprocess execution (CWE-78 compliant)
and deterministic mockable interfaces for headless/containerized environments.
"""

from __future__ import annotations

import re
import subprocess
from typing import Callable, Optional

from pydantic import BaseModel, ConfigDict, Field

# Strict whitelist pattern for valid systemd unit names (mitigates CWE-78)
SERVICE_NAME_PATTERN = re.compile(r"^[a-zA-Z0-9_\-\.@]+$")


class ServiceStatus(BaseModel):
    """Normalized status of an inspected systemd unit."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(description="Unit name, e.g. nginx.service")
    load_state: str = Field(default="unknown", description="LoadState: loaded, not-found, etc.")
    active_state: str = Field(default="unknown", description="ActiveState: active, inactive, failed, etc.")
    sub_state: str = Field(default="unknown", description="SubState: running, dead, exited, etc.")
    unit_file_state: str = Field(default="unknown", description="UnitFileState: enabled, disabled, static, etc.")
    main_pid: int = Field(default=0, description="Main PID of the service process")
    is_active: bool = Field(default=False, description="True if ActiveState == 'active'")
    is_failed: bool = Field(default=False, description="True if ActiveState == 'failed'")
    error: Optional[str] = Field(default=None, description="Error message if inspection failed")


CommandRunner = Callable[[list[str], float], tuple[int, str, str]]


def _default_command_runner(args: list[str], timeout: float = 5.0) -> tuple[int, str, str]:
    """Default secure subprocess runner with shell=False and timeout (CWE-78)."""
    try:
        proc = subprocess.run(
            args,
            shell=False,
            timeout=timeout,
            capture_output=True,
            text=True,
            check=False,
        )
        return proc.returncode, proc.stdout, proc.stderr
    except (subprocess.TimeoutExpired, OSError) as e:
        return 127, "", str(e)


class SystemdCollector:
    """Systemd service state inspector with mockable runner."""

    def __init__(
        self,
        command_runner: Optional[CommandRunner] = None,
        timeout: float = 5.0,
    ) -> None:
        self._runner = command_runner or _default_command_runner
        self._timeout = timeout

    def inspect_service(self, service_name: str) -> ServiceStatus:
        """Inspect a single systemd unit securely."""
        # Sanitize service name against injection characters (CWE-78)
        if not SERVICE_NAME_PATTERN.match(service_name):
            return ServiceStatus(
                name=service_name,
                error=f"Invalid service name format: '{service_name}'",
            )

        if not service_name.endswith(".service") and "." not in service_name:
            unit_name = f"{service_name}.service"
        else:
            unit_name = service_name

        cmd = [
            "systemctl",
            "show",
            unit_name,
            "--no-page",
            "-p",
            "LoadState",
            "-p",
            "ActiveState",
            "-p",
            "SubState",
            "-p",
            "UnitFileState",
            "-p",
            "MainPID",
        ]

        code, stdout, stderr = self._runner(cmd, self._timeout)

        if code != 0 and not stdout.strip():
            return ServiceStatus(
                name=unit_name,
                error=stderr.strip() or f"systemctl exited with code {code}",
            )

        props: dict[str, str] = {}
        for line in stdout.splitlines():
            if "=" in line:
                key, val = line.split("=", 1)
                props[key.strip()] = val.strip()

        load_state = props.get("LoadState", "unknown")
        active_state = props.get("ActiveState", "unknown")
        sub_state = props.get("SubState", "unknown")
        unit_file_state = props.get("UnitFileState", "unknown")

        try:
            main_pid = int(props.get("MainPID", "0"))
        except ValueError:
            main_pid = 0

        is_active = active_state == "active"
        is_failed = active_state == "failed"

        return ServiceStatus(
            name=unit_name,
            load_state=load_state,
            active_state=active_state,
            sub_state=sub_state,
            unit_file_state=unit_file_state,
            main_pid=main_pid,
            is_active=is_active,
            is_failed=is_failed,
        )

    def inspect_services(self, service_names: list[str]) -> dict[str, ServiceStatus]:
        """Inspect multiple services sequentially with timeout guarantees."""
        results: dict[str, ServiceStatus] = {}
        for name in service_names:
            results[name] = self.inspect_service(name)
        return results

    def is_service_active(self, service_name: str) -> bool:
        """Check if a service is currently active."""
        status = self.inspect_service(service_name)
        return status.is_active

    def is_service_failed(self, service_name: str) -> bool:
        """Check if a service is in failed state."""
        status = self.inspect_service(service_name)
        return status.is_failed
