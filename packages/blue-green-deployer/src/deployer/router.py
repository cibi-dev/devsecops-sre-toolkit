"""Atomic symlink traffic router and safe proxy reload manager.

Implements POSIX atomic symlink switching via temporary files and rename(2) (CWE-377),
privilege validation (CWE-250), safe subprocess execution without raw shell (CWE-78),
and automatic state backup.
"""

from __future__ import annotations

import json
import os
import secrets
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from deployer.config import DeployerConfig, EnvironmentSlot, RouterConfig, TargetEnvironmentConfig


class RouterError(Exception):
    """Base exception for routing errors."""
    pass


class PrivilegeError(RouterError):
    """Raised when an operation requires root privileges but is run unprivileged (CWE-250)."""
    pass


class ProxyReloadError(RouterError):
    """Raised when testing or reloading the proxy server fails."""
    pass


@dataclass
class SwitchResult:
    """Outcome of an atomic traffic switch operation."""

    success: bool
    from_slot: Optional[EnvironmentSlot]
    to_slot: EnvironmentSlot
    target_config_path: Path
    symlink_path: Path
    switch_duration_ms: float
    proxy_reloaded: bool
    backup_path: Optional[Path] = None
    error_message: Optional[str] = None
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize switch result to dictionary."""
        return {
            "success": self.success,
            "from_slot": self.from_slot.value if self.from_slot else None,
            "to_slot": self.to_slot.value,
            "target_config_path": str(self.target_config_path),
            "symlink_path": str(self.symlink_path),
            "switch_duration_ms": round(self.switch_duration_ms, 3),
            "proxy_reloaded": self.proxy_reloaded,
            "backup_path": str(self.backup_path) if self.backup_path else None,
            "error_message": self.error_message,
            "timestamp": self.timestamp,
        }


class TrafficRouter:
    """Manages atomic symlink switching and safe proxy validation & reload."""

    def __init__(self, config: Optional[RouterConfig] = None, allow_unprivileged: bool = False) -> None:
        self.config = config or RouterConfig()
        self.allow_unprivileged = allow_unprivileged

    def check_privileges(self) -> None:
        """Validate process privileges if require_root is configured (CWE-250).

        Raises:
            PrivilegeError: If root privileges are required but missing.
        """
        if self.config.require_root and not self.allow_unprivileged:
            if hasattr(os, "geteuid") and os.geteuid() != 0:
                raise PrivilegeError(
                    "Root privileges (EUID 0) are required for proxy configuration modification. "
                    "Execute with sudo or enable 'allow_unprivileged' for non-root testing."
                )

    def get_current_target_path(self) -> Optional[Path]:
        """Return the resolved Path of the currently active symlink target, or None."""
        symlink_abs = Path(os.path.abspath(self.config.symlink_path))
        if not symlink_abs.is_symlink() and not symlink_abs.exists():
            return None
        try:
            target_str = os.readlink(str(symlink_abs))
            target_path = Path(target_str)
            if not target_path.is_absolute():
                target_path = (symlink_abs.parent / target_path).resolve()
            else:
                target_path = target_path.resolve()
            return target_path
        except OSError:
            return None

    def get_active_slot(self, deployer_config: DeployerConfig) -> Optional[EnvironmentSlot]:
        """Determine which slot is currently active based on symlink target."""
        current_target = self.get_current_target_path()
        if current_target is None:
            return None

        # Match against blue/green config target paths
        blue_cfg_path = deployer_config.blue.config_path
        green_cfg_path = deployer_config.green.config_path

        if blue_cfg_path and current_target == Path(os.path.abspath(blue_cfg_path)):
            return EnvironmentSlot.BLUE
        if green_cfg_path and current_target == Path(os.path.abspath(green_cfg_path)):
            return EnvironmentSlot.GREEN

        # Fallback substring matching on target filename
        target_name = current_target.name.lower()
        if "blue" in target_name:
            return EnvironmentSlot.BLUE
        elif "green" in target_name:
            return EnvironmentSlot.GREEN

        return None

    def test_proxy_configuration(self) -> None:
        """Run safe proxy configuration test command (CWE-78 safe execution).

        Raises:
            ProxyReloadError: If proxy test command fails.
        """
        cmd = self.config.test_command
        try:
            subprocess.run(
                cmd,
                shell=False,
                check=True,
                capture_output=True,
                text=True,
                timeout=10.0,
            )
        except subprocess.CalledProcessError as exc:
            stderr = exc.stderr.strip() if exc.stderr else ""
            stdout = exc.stdout.strip() if exc.stdout else ""
            raise ProxyReloadError(f"Proxy configuration test failed ({cmd}): {stderr or stdout}") from exc
        except FileNotFoundError:
            if self.allow_unprivileged:
                return
            raise ProxyReloadError(f"Proxy test binary not found: {cmd[0]}")
        except subprocess.TimeoutExpired as exc:
            raise ProxyReloadError(f"Proxy test command timed out after 10s: {cmd}") from exc

    def reload_proxy(self) -> None:
        """Run safe proxy reload command (CWE-78 safe execution).

        Raises:
            ProxyReloadError: If proxy reload command fails.
        """
        if not self.config.enable_proxy_reload:
            return

        cmd = self.config.reload_command
        try:
            subprocess.run(
                cmd,
                shell=False,
                check=True,
                capture_output=True,
                text=True,
                timeout=10.0,
            )
        except subprocess.CalledProcessError as exc:
            stderr = exc.stderr.strip() if exc.stderr else ""
            stdout = exc.stdout.strip() if exc.stdout else ""
            raise ProxyReloadError(f"Proxy reload failed ({cmd}): {stderr or stdout}") from exc
        except FileNotFoundError:
            if self.allow_unprivileged:
                return
            raise ProxyReloadError(f"Proxy reload binary not found: {cmd[0]}")
        except subprocess.TimeoutExpired as exc:
            raise ProxyReloadError(f"Proxy reload command timed out after 10s: {cmd}") from exc

    def _create_backup(self, previous_slot: Optional[EnvironmentSlot], previous_target: Optional[Path]) -> Optional[Path]:
        """Save a snapshot of the previous routing state for rollback assurance."""
        try:
            backup_dir = Path(os.path.abspath(self.config.backup_dir))
            backup_dir.mkdir(parents=True, exist_ok=True)
            timestamp = int(time.time() * 1000)
            backup_file = backup_dir / f"route_backup_{timestamp}.json"
            data = {
                "timestamp": time.time(),
                "slot": previous_slot.value if previous_slot else None,
                "target_path": str(previous_target) if previous_target else None,
                "symlink_path": str(os.path.abspath(self.config.symlink_path)),
            }
            with open(backup_file, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
            return backup_file
        except Exception:
            return None

    def switch_to_target(
        self,
        target_slot: EnvironmentSlot,
        target_config_path: Path,
        from_slot: Optional[EnvironmentSlot] = None,
        validate_proxy: bool = True,
    ) -> SwitchResult:
        """Atomically switch the proxy symlink to target_config_path using rename(2).

        Args:
            target_slot: The slot being activated (BLUE or GREEN).
            target_config_path: Path to the target upstream configuration file.
            from_slot: The slot being deactivated.
            validate_proxy: Whether to execute test and reload commands.

        Returns:
            SwitchResult with execution metrics and status.
        """
        self.check_privileges()

        resolved_target = Path(os.path.abspath(target_config_path))
        if not resolved_target.exists():
            resolved_target.parent.mkdir(parents=True, exist_ok=True)
            if not resolved_target.is_file():
                resolved_target.write_text(f"# Upstream snippet for {target_slot.value}\n", encoding="utf-8")

        symlink_path = Path(os.path.abspath(self.config.symlink_path))
        symlink_path.parent.mkdir(parents=True, exist_ok=True)

        previous_target = self.get_current_target_path()
        backup_file = self._create_backup(previous_slot=from_slot, previous_target=previous_target)

        # CWE-377 Secure temporary symlink created in the SAME directory for atomic rename
        temp_symlink = symlink_path.parent / f".tmp_{symlink_path.name}_{os.getpid()}_{secrets.token_hex(6)}"

        start_time = time.perf_counter()
        try:
            # 1. Create temporary symlink pointing to resolved_target
            os.symlink(str(resolved_target), str(temp_symlink))

            # 2. Atomically replace destination symlink using os.replace
            os.replace(str(temp_symlink), str(symlink_path))

            # 3. If proxy reload is enabled and validate_proxy is True
            proxy_reloaded = False
            if validate_proxy:
                if self.config.enable_proxy_reload:
                    self.test_proxy_configuration()
                    self.reload_proxy()
                    proxy_reloaded = True

            duration_ms = (time.perf_counter() - start_time) * 1000.0
            return SwitchResult(
                success=True,
                from_slot=from_slot,
                to_slot=target_slot,
                target_config_path=resolved_target,
                symlink_path=symlink_path,
                switch_duration_ms=duration_ms,
                proxy_reloaded=proxy_reloaded,
                backup_path=backup_file,
            )

        except Exception as exc:
            duration_ms = (time.perf_counter() - start_time) * 1000.0
            if temp_symlink.exists() or temp_symlink.is_symlink():
                try:
                    temp_symlink.unlink()
                except OSError:
                    pass

            return SwitchResult(
                success=False,
                from_slot=from_slot,
                to_slot=target_slot,
                target_config_path=resolved_target,
                symlink_path=symlink_path,
                switch_duration_ms=duration_ms,
                proxy_reloaded=False,
                backup_path=backup_file,
                error_message=f"Traffic switch failed: {exc}",
            )
