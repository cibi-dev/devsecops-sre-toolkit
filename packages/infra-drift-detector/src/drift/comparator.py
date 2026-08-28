"""Deterministic infrastructure drift comparator engine."""

from __future__ import annotations

import difflib
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any

from drift.inspectors.files import FileInspector, FileLiveState
from drift.inspectors.packages import PackageInspector, PackageLiveState
from drift.inspectors.ports import PortInspector, PortLiveState
from drift.inspectors.services import ServiceInspector, ServiceLiveState
from drift.inspectors.sysctl import SysctlInspector, SysctlLiveState
from drift.inspectors.users import UserInspector, UserLiveState
from drift.schema import Manifest


class DriftType(str, Enum):
    """Classification of infrastructure drift status."""

    MATCH = "MATCH"
    MISSING = "MISSING"
    UNEXPECTED = "UNEXPECTED"
    MODIFIED = "MODIFIED"


class DriftSeverity(str, Enum):
    """Risk severity associated with a detected drift."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"
    INFO = "INFO"


CRITICAL_FILE_PATHS = {
    "/etc/shadow",
    "/etc/gshadow",
    "/etc/sudoers",
    "/etc/passwd",
    "/etc/group",
    "/etc/ssh/sshd_config",
    "/root/.ssh/authorized_keys",
}


def compute_unified_diff(
    identifier: str,
    desired_data: dict[str, Any],
    actual_data: dict[str, Any],
) -> str:
    """Generate a unified diff between desired and live attributes."""
    desired_lines = [
        f"{k}: {v}\n"
        for k, v in sorted(desired_data.items())
        if v is not None and k not in ("name", "key", "path", "port")
    ]
    actual_lines = [
        f"{k}: {v}\n"
        for k, v in sorted(actual_data.items())
        if v is not None and k not in ("name", "key", "path", "port")
    ]
    diff = difflib.unified_diff(
        desired_lines,
        actual_lines,
        fromfile=f"desired/{identifier}",
        tofile=f"live/{identifier}",
        lineterm="",
    )
    return "\n".join(diff)


class DriftItem:
    """Represents the drift comparison result for a single resource."""

    def __init__(
        self,
        category: str,
        name: str,
        drift_type: DriftType,
        severity: DriftSeverity,
        desired: dict[str, Any],
        actual: dict[str, Any],
        differences: dict[str, tuple[Any, Any]] | None = None,
        unified_diff: str = "",
        message: str = "",
    ) -> None:
        self.category = category
        self.name = name
        self.drift_type = drift_type
        self.severity = severity
        self.desired = desired
        self.actual = actual
        self.differences = differences or {}
        self.unified_diff = unified_diff
        self.message = message

    def to_dict(self) -> dict[str, Any]:
        """Serialize item to dictionary."""
        return {
            "category": self.category,
            "name": self.name,
            "drift_type": self.drift_type.value,
            "severity": self.severity.value,
            "desired": self.desired,
            "actual": self.actual,
            "differences": {
                k: {"desired": v[0], "actual": v[1]} for k, v in self.differences.items()
            },
            "unified_diff": self.unified_diff,
            "message": self.message,
        }


class DriftResult:
    """Aggregated results of an infrastructure audit."""

    def __init__(self, manifest_name: str, items: list[DriftItem] | None = None) -> None:
        self.manifest_name = manifest_name
        self.timestamp = datetime.now(timezone.utc).isoformat()
        self.items: list[DriftItem] = items or []

    @property
    def total_checked(self) -> int:
        return len(self.items)

    @property
    def drift_items(self) -> list[DriftItem]:
        return [i for i in self.items if i.drift_type != DriftType.MATCH]

    @property
    def drift_detected(self) -> bool:
        return len(self.drift_items) > 0

    @property
    def missing_count(self) -> int:
        return sum(1 for i in self.items if i.drift_type == DriftType.MISSING)

    @property
    def unexpected_count(self) -> int:
        return sum(1 for i in self.items if i.drift_type == DriftType.UNEXPECTED)

    @property
    def modified_count(self) -> int:
        return sum(1 for i in self.items if i.drift_type == DriftType.MODIFIED)

    @property
    def match_count(self) -> int:
        return sum(1 for i in self.items if i.drift_type == DriftType.MATCH)

    @property
    def critical_count(self) -> int:
        return sum(
            1
            for i in self.items
            if i.drift_type != DriftType.MATCH and i.severity == DriftSeverity.CRITICAL
        )

    @property
    def high_count(self) -> int:
        return sum(
            1
            for i in self.items
            if i.drift_type != DriftType.MATCH and i.severity == DriftSeverity.HIGH
        )

    @property
    def medium_count(self) -> int:
        return sum(
            1
            for i in self.items
            if i.drift_type != DriftType.MATCH and i.severity == DriftSeverity.MEDIUM
        )

    @property
    def low_count(self) -> int:
        return sum(
            1
            for i in self.items
            if i.drift_type != DriftType.MATCH and i.severity == DriftSeverity.LOW
        )

    def to_dict(self) -> dict[str, Any]:
        """Serialize full result to dict for JSON output."""
        return {
            "manifest_name": self.manifest_name,
            "timestamp": self.timestamp,
            "drift_detected": self.drift_detected,
            "summary": {
                "total_checked": self.total_checked,
                "matches": self.match_count,
                "drifts": len(self.drift_items),
                "missing": self.missing_count,
                "unexpected": self.unexpected_count,
                "modified": self.modified_count,
                "severity_counts": {
                    "critical": self.critical_count,
                    "high": self.high_count,
                    "medium": self.medium_count,
                    "low": self.low_count,
                },
            },
            "items": [item.to_dict() for item in self.items],
        }


class DriftComparator:
    """Orchestrates inspectors and compares live state with desired manifest."""

    def __init__(
        self,
        user_inspector: UserInspector | None = None,
        service_inspector: ServiceInspector | None = None,
        sysctl_inspector: SysctlInspector | None = None,
        port_inspector: PortInspector | None = None,
        file_inspector: FileInspector | None = None,
        package_inspector: PackageInspector | None = None,
    ) -> None:
        self.user_inspector = user_inspector or UserInspector()
        self.service_inspector = service_inspector or ServiceInspector()
        self.sysctl_inspector = sysctl_inspector or SysctlInspector()
        self.port_inspector = port_inspector or PortInspector()
        self.file_inspector = file_inspector or FileInspector()
        self.package_inspector = package_inspector or PackageInspector()

    def compare(self, manifest: Manifest) -> DriftResult:
        """Perform end-to-end drift detection against the manifest."""
        items: list[DriftItem] = []

        # 1. Compare Users
        for u in manifest.users:
            live_user = self.user_inspector.inspect_user(u.name)
            desired_dict = u.model_dump()

            if u.state == "absent":
                if live_user and live_user.exists:
                    items.append(
                        DriftItem(
                            category="users",
                            name=u.name,
                            drift_type=DriftType.UNEXPECTED,
                            severity=DriftSeverity.HIGH,
                            desired={"state": "absent"},
                            actual={"state": "present", "uid": live_user.uid},
                            message=f"User '{u.name}' is present but desired absent",
                        )
                    )
                else:
                    items.append(
                        DriftItem(
                            category="users",
                            name=u.name,
                            drift_type=DriftType.MATCH,
                            severity=DriftSeverity.INFO,
                            desired=desired_dict,
                            actual={"state": "absent"},
                            message=f"User '{u.name}' correctly absent",
                        )
                    )
                continue

            # State is present
            if not live_user or not live_user.exists:
                items.append(
                    DriftItem(
                        category="users",
                        name=u.name,
                        drift_type=DriftType.MISSING,
                        severity=DriftSeverity.HIGH,
                        desired=desired_dict,
                        actual={"state": "missing"},
                        message=f"User '{u.name}' does not exist on host",
                    )
                )
                continue

            actual_dict = {
                "name": live_user.name,
                "uid": live_user.uid,
                "gid": live_user.gid,
                "shell": live_user.shell,
                "home": live_user.home,
                "groups": live_user.groups,
                "state": "present",
            }

            diffs: dict[str, tuple[Any, Any]] = {}
            if u.uid is not None and u.uid != live_user.uid:
                diffs["uid"] = (u.uid, live_user.uid)
            if u.gid is not None and u.gid != live_user.gid:
                diffs["gid"] = (u.gid, live_user.gid)
            if u.shell is not None and u.shell != live_user.shell:
                diffs["shell"] = (u.shell, live_user.shell)
            if u.home is not None and u.home != live_user.home:
                diffs["home"] = (u.home, live_user.home)
            if u.groups:
                missing_groups = set(u.groups) - set(live_user.groups)
                if missing_groups:
                    diffs["groups"] = (u.groups, live_user.groups)

            if diffs:
                items.append(
                    DriftItem(
                        category="users",
                        name=u.name,
                        drift_type=DriftType.MODIFIED,
                        severity=DriftSeverity.MEDIUM,
                        desired=desired_dict,
                        actual=actual_dict,
                        differences=diffs,
                        unified_diff=compute_unified_diff(u.name, desired_dict, actual_dict),
                        message=f"User '{u.name}' attributes drifted: {', '.join(diffs.keys())}",
                    )
                )
            else:
                items.append(
                    DriftItem(
                        category="users",
                        name=u.name,
                        drift_type=DriftType.MATCH,
                        severity=DriftSeverity.INFO,
                        desired=desired_dict,
                        actual=actual_dict,
                        message=f"User '{u.name}' matches desired state",
                    )
                )

        # 2. Compare Services
        for s in manifest.services:
            live_svc = self.service_inspector.inspect_service(s.name)
            desired_dict = s.model_dump()
            actual_dict = {
                "name": live_svc.name,
                "active_state": live_svc.active_state,
                "unit_file_state": live_svc.unit_file_state,
                "is_running": live_svc.is_running,
                "is_enabled": live_svc.is_enabled,
                "exists": live_svc.exists,
            }

            if s.state == "absent":
                if live_svc.is_running or live_svc.exists:
                    items.append(
                        DriftItem(
                            category="services",
                            name=s.name,
                            drift_type=DriftType.UNEXPECTED,
                            severity=DriftSeverity.HIGH,
                            desired=desired_dict,
                            actual=actual_dict,
                            message=f"Service '{s.name}' exists/running but desired absent",
                        )
                    )
                else:
                    items.append(
                        DriftItem(
                            category="services",
                            name=s.name,
                            drift_type=DriftType.MATCH,
                            severity=DriftSeverity.INFO,
                            desired=desired_dict,
                            actual=actual_dict,
                            message=f"Service '{s.name}' correctly absent",
                        )
                    )
                continue

            # State is running or present
            diffs = {}
            if s.state in ("running", "present") and not live_svc.is_running:
                diffs["state"] = (s.state, live_svc.active_state)
            elif s.state in ("stopped", "disabled") and live_svc.is_running:
                diffs["state"] = (s.state, live_svc.active_state)

            if s.enabled is not None and s.enabled != live_svc.is_enabled:
                diffs["enabled"] = (s.enabled, live_svc.is_enabled)

            if not live_svc.exists and s.state in ("running", "present"):
                items.append(
                    DriftItem(
                        category="services",
                        name=s.name,
                        drift_type=DriftType.MISSING,
                        severity=DriftSeverity.HIGH,
                        desired=desired_dict,
                        actual=actual_dict,
                        message=f"Service unit '{s.name}' not found",
                    )
                )
            elif diffs:
                items.append(
                    DriftItem(
                        category="services",
                        name=s.name,
                        drift_type=DriftType.MODIFIED,
                        severity=DriftSeverity.HIGH,
                        desired=desired_dict,
                        actual=actual_dict,
                        differences=diffs,
                        unified_diff=compute_unified_diff(s.name, desired_dict, actual_dict),
                        message=f"Service '{s.name}' status drifted: {', '.join(diffs.keys())}",
                    )
                )
            else:
                items.append(
                    DriftItem(
                        category="services",
                        name=s.name,
                        drift_type=DriftType.MATCH,
                        severity=DriftSeverity.INFO,
                        desired=desired_dict,
                        actual=actual_dict,
                        message=f"Service '{s.name}' matches desired state",
                    )
                )

        # 3. Compare Sysctl
        for sc in manifest.sysctl:
            live_sc = self.sysctl_inspector.inspect_key(sc.key)
            desired_dict = sc.model_dump()
            actual_dict = {"key": sc.key, "value": live_sc.value, "exists": live_sc.exists}

            if not live_sc.exists:
                items.append(
                    DriftItem(
                        category="sysctl",
                        name=sc.key,
                        drift_type=DriftType.MISSING,
                        severity=DriftSeverity.MEDIUM,
                        desired=desired_dict,
                        actual=actual_dict,
                        message=f"Kernel parameter '{sc.key}' not found in procfs",
                    )
                )
            elif live_sc.value != str(sc.value):
                diffs = {"value": (str(sc.value), live_sc.value)}
                items.append(
                    DriftItem(
                        category="sysctl",
                        name=sc.key,
                        drift_type=DriftType.MODIFIED,
                        severity=DriftSeverity.MEDIUM,
                        desired=desired_dict,
                        actual=actual_dict,
                        differences=diffs,
                        unified_diff=compute_unified_diff(sc.key, desired_dict, actual_dict),
                        message=f"Sysctl '{sc.key}' value is '{live_sc.value}', expected '{sc.value}'",
                    )
                )
            else:
                items.append(
                    DriftItem(
                        category="sysctl",
                        name=sc.key,
                        drift_type=DriftType.MATCH,
                        severity=DriftSeverity.INFO,
                        desired=desired_dict,
                        actual=actual_dict,
                        message=f"Sysctl '{sc.key}' matches desired state",
                    )
                )

        # 4. Compare Ports
        for p in manifest.ports:
            is_listening = self.port_inspector.is_port_listening(
                port=p.port, protocol=p.protocol, address=p.address
            )
            desired_dict = p.model_dump()
            actual_dict = {
                "port": p.port,
                "protocol": p.protocol,
                "address": p.address,
                "state": "listening" if is_listening else "closed",
            }

            port_label = f"{p.protocol}/{p.port} ({p.address})"

            if p.state == "listening" and not is_listening:
                items.append(
                    DriftItem(
                        category="ports",
                        name=port_label,
                        drift_type=DriftType.MISSING,
                        severity=DriftSeverity.HIGH,
                        desired=desired_dict,
                        actual=actual_dict,
                        message=f"Port {port_label} is not listening",
                    )
                )
            elif p.state == "closed" and is_listening:
                items.append(
                    DriftItem(
                        category="ports",
                        name=port_label,
                        drift_type=DriftType.UNEXPECTED,
                        severity=DriftSeverity.HIGH,
                        desired=desired_dict,
                        actual=actual_dict,
                        message=f"Port {port_label} is open but expected closed",
                    )
                )
            else:
                items.append(
                    DriftItem(
                        category="ports",
                        name=port_label,
                        drift_type=DriftType.MATCH,
                        severity=DriftSeverity.INFO,
                        desired=desired_dict,
                        actual=actual_dict,
                        message=f"Port {port_label} state matches",
                    )
                )

        # 5. Compare Files
        for f in manifest.files:
            live_f = self.file_inspector.inspect_file(
                f.path, compute_sha256=bool(f.sha256 or f.content)
            )
            desired_dict = f.model_dump()
            actual_dict = {
                "path": live_f.path,
                "exists": live_f.exists,
                "mode": live_f.mode,
                "owner": live_f.owner,
                "group": live_f.group,
                "sha256": live_f.sha256,
            }

            is_critical_path = f.path in CRITICAL_FILE_PATHS or f.path.startswith(
                ("/etc/sudoers.d/", "/etc/ssh/")
            )
            severity = DriftSeverity.CRITICAL if is_critical_path else DriftSeverity.MEDIUM

            if f.state == "absent":
                if live_f.exists:
                    items.append(
                        DriftItem(
                            category="files",
                            name=f.path,
                            drift_type=DriftType.UNEXPECTED,
                            severity=severity,
                            desired=desired_dict,
                            actual=actual_dict,
                            message=f"File '{f.path}' exists but desired absent",
                        )
                    )
                else:
                    items.append(
                        DriftItem(
                            category="files",
                            name=f.path,
                            drift_type=DriftType.MATCH,
                            severity=DriftSeverity.INFO,
                            desired=desired_dict,
                            actual=actual_dict,
                            message=f"File '{f.path}' correctly absent",
                        )
                    )
                continue

            # State is present
            if not live_f.exists:
                items.append(
                    DriftItem(
                        category="files",
                        name=f.path,
                        drift_type=DriftType.MISSING,
                        severity=severity,
                        desired=desired_dict,
                        actual=actual_dict,
                        message=f"File '{f.path}' does not exist",
                    )
                )
                continue

            diffs = {}
            if f.mode is not None:
                desired_mode = f.mode.zfill(4)
                actual_mode = (live_f.mode or "").zfill(4)
                if desired_mode != actual_mode:
                    diffs["mode"] = (desired_mode, actual_mode)

            if f.owner is not None and f.owner != live_f.owner:
                diffs["owner"] = (f.owner, live_f.owner)

            if f.group is not None and f.group != live_f.group:
                diffs["group"] = (f.group, live_f.group)

            if f.sha256 is not None and f.sha256.lower() != (live_f.sha256 or "").lower():
                diffs["sha256"] = (f.sha256.lower(), live_f.sha256)

            if diffs:
                items.append(
                    DriftItem(
                        category="files",
                        name=f.path,
                        drift_type=DriftType.MODIFIED,
                        severity=severity,
                        desired=desired_dict,
                        actual=actual_dict,
                        differences=diffs,
                        unified_diff=compute_unified_diff(f.path, desired_dict, actual_dict),
                        message=f"File '{f.path}' drifted attributes: {', '.join(diffs.keys())}",
                    )
                )
            else:
                items.append(
                    DriftItem(
                        category="files",
                        name=f.path,
                        drift_type=DriftType.MATCH,
                        severity=DriftSeverity.INFO,
                        desired=desired_dict,
                        actual=actual_dict,
                        message=f"File '{f.path}' matches desired state",
                    )
                )

        # 6. Compare Packages
        for pkg in manifest.packages:
            live_pkg = self.package_inspector.inspect_package(pkg.name)
            desired_dict = pkg.model_dump()
            actual_dict = {
                "name": live_pkg.name,
                "installed": live_pkg.installed,
                "version": live_pkg.version,
            }

            if pkg.state == "absent":
                if live_pkg.installed:
                    items.append(
                        DriftItem(
                            category="packages",
                            name=pkg.name,
                            drift_type=DriftType.UNEXPECTED,
                            severity=DriftSeverity.MEDIUM,
                            desired=desired_dict,
                            actual=actual_dict,
                            message=f"Package '{pkg.name}' is installed but desired absent",
                        )
                    )
                else:
                    items.append(
                        DriftItem(
                            category="packages",
                            name=pkg.name,
                            drift_type=DriftType.MATCH,
                            severity=DriftSeverity.INFO,
                            desired=desired_dict,
                            actual=actual_dict,
                            message=f"Package '{pkg.name}' correctly absent",
                        )
                    )
                continue

            if not live_pkg.installed:
                items.append(
                    DriftItem(
                        category="packages",
                        name=pkg.name,
                        drift_type=DriftType.MISSING,
                        severity=DriftSeverity.MEDIUM,
                        desired=desired_dict,
                        actual=actual_dict,
                        message=f"Package '{pkg.name}' is missing",
                    )
                )
            elif pkg.version and live_pkg.version and pkg.version != live_pkg.version:
                diffs = {"version": (pkg.version, live_pkg.version)}
                items.append(
                    DriftItem(
                        category="packages",
                        name=pkg.name,
                        drift_type=DriftType.MODIFIED,
                        severity=DriftSeverity.LOW,
                        desired=desired_dict,
                        actual=actual_dict,
                        differences=diffs,
                        unified_diff=compute_unified_diff(pkg.name, desired_dict, actual_dict),
                        message=f"Package '{pkg.name}' version mismatch: expected {pkg.version}, got {live_pkg.version}",
                    )
                )
            else:
                items.append(
                    DriftItem(
                        category="packages",
                        name=pkg.name,
                        drift_type=DriftType.MATCH,
                        severity=DriftSeverity.INFO,
                        desired=desired_dict,
                        actual=actual_dict,
                        message=f"Package '{pkg.name}' matches desired state",
                    )
                )

        return DriftResult(manifest_name=manifest.name, items=items)
