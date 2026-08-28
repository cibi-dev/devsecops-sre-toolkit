"""Read-only inspector for systemd services (CWE-78, CWE-250)."""

from __future__ import annotations

import re
import shutil
import subprocess
from typing import Callable, NamedTuple


class ServiceLiveState(NamedTuple):
    """Live status of a systemd unit."""

    name: str
    active_state: str  # e.g., 'active', 'inactive', 'failed'
    unit_file_state: str  # e.g., 'enabled', 'disabled', 'static', 'masked', 'unknown'
    load_state: str  # e.g., 'loaded', 'not-found'
    exists: bool = True
    is_running: bool = False
    is_enabled: bool = False


# Whitelist regex for systemd service unit names to strictly prevent command injection (CWE-78)
RE_SAFE_SERVICE_NAME = re.compile(r"^[a-zA-Z0-9_.@-]+(?:\.(?:service|socket|target|timer|mount))?$")


class ServiceInspector:
    """Read-only inspector for systemd service states."""

    def __init__(
        self,
        command_runner: Callable[[list[str]], tuple[int, str, str]] | None = None,
    ) -> None:
        self._runner = command_runner or self._default_runner

    @staticmethod
    def _default_runner(cmd: list[str]) -> tuple[int, str, str]:
        """Execute command safely without shell (CWE-78)."""
        systemctl_path = shutil.which("systemctl")
        if not systemctl_path:
            return 127, "", "systemctl not found"

        try:
            res = subprocess.run(
                [systemctl_path] + cmd[1:],
                capture_output=True,
                text=True,
                shell=False,
                check=False,
                timeout=5,
            )
            return res.returncode, res.stdout, res.stderr
        except (subprocess.SubprocessError, OSError) as exc:
            return 1, "", str(exc)

    def inspect_service(self, service_name: str) -> ServiceLiveState:
        """Inspect the live state of a systemd unit.

        Args:
            service_name: Name of the service unit (e.g. 'ssh', 'nginx.service')

        Returns:
            ServiceLiveState describing current status.
        """
        # Validate unit name to prevent command injection (CWE-78)
        if not RE_SAFE_SERVICE_NAME.match(service_name):
            return ServiceLiveState(
                name=service_name,
                active_state="invalid",
                unit_file_state="invalid",
                load_state="not-found",
                exists=False,
                is_running=False,
                is_enabled=False,
            )

        unit_name = service_name if "." in service_name else f"{service_name}.service"

        code, stdout, stderr = self._runner(
            ["systemctl", "show", unit_name, "--property=ActiveState,UnitFileState,LoadState"]
        )

        if code == 127:
            # systemctl missing (e.g., in lightweight containers or CI without init system)
            return ServiceLiveState(
                name=service_name,
                active_state="unknown",
                unit_file_state="unknown",
                load_state="unknown",
                exists=False,
                is_running=False,
                is_enabled=False,
            )

        props: dict[str, str] = {}
        for line in stdout.splitlines():
            line = line.strip()
            if "=" in line:
                k, v = line.split("=", 1)
                props[k.strip()] = v.strip()

        active_state = props.get("ActiveState", "inactive")
        unit_file_state = props.get("UnitFileState", "unknown")
        load_state = props.get("LoadState", "not-found")

        exists = load_state == "loaded" or active_state not in ("inactive", "not-found", "")
        is_running = active_state == "active"
        is_enabled = unit_file_state in ("enabled", "static")

        return ServiceLiveState(
            name=service_name,
            active_state=active_state,
            unit_file_state=unit_file_state,
            load_state=load_state,
            exists=exists,
            is_running=is_running,
            is_enabled=is_enabled,
        )
