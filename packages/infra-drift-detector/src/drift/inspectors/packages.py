"""Read-only inspector for system packages (dpkg/rpm) (CWE-78, CWE-250)."""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path
from typing import Callable, NamedTuple


class PackageLiveState(NamedTuple):
    """Live state of an installed system package."""

    name: str
    version: str | None
    installed: bool = True


# Whitelist regex for package names to prevent command injection (CWE-78)
RE_SAFE_PKG_NAME = re.compile(r"^[a-zA-Z0-9.+~:-]+$")


class PackageInspector:
    """Read-only inspector for system package installations."""

    def __init__(
        self,
        dpkg_status_path: Path | str | None = None,
        command_runner: Callable[[list[str]], tuple[int, str, str]] | None = None,
    ) -> None:
        self.dpkg_status_path = Path(dpkg_status_path) if dpkg_status_path else None
        self._runner = command_runner or self._default_runner

    @staticmethod
    def _default_runner(cmd: list[str]) -> tuple[int, str, str]:
        """Safe subprocess runner (CWE-78)."""
        bin_path = shutil.which(cmd[0])
        if not bin_path:
            return 127, "", f"{cmd[0]} not found"
        try:
            res = subprocess.run(
                [bin_path] + cmd[1:],
                capture_output=True,
                text=True,
                shell=False,
                check=False,
                timeout=5,
            )
            return res.returncode, res.stdout, res.stderr
        except (subprocess.SubprocessError, OSError) as exc:
            return 1, "", str(exc)

    def _inspect_dpkg_status_file(self, pkg_name: str) -> PackageLiveState | None:
        """Inspect package directly from /var/lib/dpkg/status if available."""
        if not self.dpkg_status_path or not self.dpkg_status_path.exists():
            return None

        current_pkg: str | None = None
        current_status: str | None = None
        current_version: str | None = None

        try:
            with open(self.dpkg_status_path, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    line = line.rstrip()
                    if line.startswith("Package: "):
                        current_pkg = line.split(":", 1)[1].strip()
                    elif line.startswith("Status: "):
                        current_status = line.split(":", 1)[1].strip()
                    elif line.startswith("Version: "):
                        current_version = line.split(":", 1)[1].strip()
                    elif line == "":
                        if current_pkg == pkg_name:
                            is_installed = "install ok installed" in (current_status or "")
                            return PackageLiveState(
                                name=pkg_name,
                                version=current_version,
                                installed=is_installed,
                            )
                        current_pkg = None
                        current_status = None
                        current_version = None
        except OSError:
            pass
        return None

    def inspect_package(self, package_name: str) -> PackageLiveState:
        """Inspect installation state and version of a system package."""
        if not RE_SAFE_PKG_NAME.match(package_name):
            return PackageLiveState(name=package_name, version=None, installed=False)

        # 1. Try file-based status if configured
        if self.dpkg_status_path:
            status = self._inspect_dpkg_status_file(package_name)
            if status:
                return status
            return PackageLiveState(name=package_name, version=None, installed=False)

        # 2. Try dpkg-query
        code, stdout, _ = self._runner(
            ["dpkg-query", "-W", "-f=${Status}|${Version}", package_name]
        )
        if code == 0 and "|" in stdout:
            st, ver = stdout.split("|", 1)
            is_installed = "installed" in st
            return PackageLiveState(
                name=package_name,
                version=ver.strip() if is_installed else None,
                installed=is_installed,
            )

        # 3. Try rpm
        code, stdout, _ = self._runner(["rpm", "-q", "--qf", "%{VERSION}-%{RELEASE}", package_name])
        if code == 0 and "not installed" not in stdout:
            return PackageLiveState(
                name=package_name,
                version=stdout.strip(),
                installed=True,
            )

        return PackageLiveState(name=package_name, version=None, installed=False)
