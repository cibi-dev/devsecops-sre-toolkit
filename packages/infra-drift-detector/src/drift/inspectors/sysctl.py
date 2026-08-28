"""Read-only inspector for Linux kernel sysctl parameters via procfs (CWE-22, CWE-250)."""

from __future__ import annotations

import os
from pathlib import Path
import re
from typing import NamedTuple


class SysctlLiveState(NamedTuple):
    """Live state of a kernel sysctl parameter."""

    key: str
    value: str
    exists: bool = True


# Key validation pattern: only alphanumeric, dot, underscore, dash
RE_SYSCTL_KEY = re.compile(r"^[a-zA-Z0-9_.-]+$")


class SysctlInspector:
    """Read-only inspector for Linux kernel sysctl parameters via procfs."""

    def __init__(self, proc_sys_root: Path | str = "/proc/sys") -> None:
        self.proc_sys_root = Path(proc_sys_root).resolve()

    def get_parameter_path(self, key: str) -> Path | None:
        """Resolve a dot-separated sysctl key to its procfs path with traversal defense (CWE-22)."""
        clean_key = key.strip()
        if not RE_SYSCTL_KEY.match(clean_key) or ".." in clean_key or "/" in clean_key or "\\" in clean_key:
            return None

        parts = clean_key.split(".")
        param_path = self.proc_sys_root.joinpath(*parts)

        # Path traversal guard: ensure resolved path is inside proc_sys_root
        try:
            resolved = param_path.resolve()
            if not resolved.is_relative_to(self.proc_sys_root):
                return None
            return resolved
        except (ValueError, RuntimeError):
            return None

    def inspect_key(self, key: str) -> SysctlLiveState:
        """Read live value of a sysctl flag from procfs."""
        param_path = self.get_parameter_path(key)
        if not param_path or not param_path.exists() or not param_path.is_file():
            return SysctlLiveState(key=key, value="", exists=False)

        try:
            with open(param_path, "r", encoding="utf-8", errors="replace") as f:
                # Kernel sysctl files are single or space/tab separated values
                raw_val = f.read().strip()
                # Normalize internal whitespace
                val = " ".join(raw_val.split())
                return SysctlLiveState(key=key, value=val, exists=True)
        except OSError:
            return SysctlLiveState(key=key, value="", exists=False)
