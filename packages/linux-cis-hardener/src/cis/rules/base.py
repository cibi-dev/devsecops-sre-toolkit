"""Base classes and data models for CIS Benchmark Level 1 security rules."""

from __future__ import annotations

import os
import re
from abc import ABC, abstractmethod
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field


class Severity(str, Enum):
    """CIS Rule severity levels."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class RuleStatus(str, Enum):
    """Status of an audited rule."""

    PASSED = "PASSED"
    FAILED = "FAILED"
    SKIPPED = "SKIPPED"
    ERROR = "ERROR"


class CISSection(str, Enum):
    """Standard CIS Linux Benchmark sections."""

    INITIAL_SETUP = "1.0 Initial Setup & OS Hardening"
    SERVICES = "2.0 Services & Daemons"
    NETWORK_SYSCTL = "3.2 Network & Kernel Parameters"
    FIREWALL = "3.5 Firewall Configuration"
    ACCESS_CONTROL = "5.0 Access, Authentication & Authorization"
    SSH = "5.2 SSH Server Hardening"
    FILE_PERMISSIONS = "6.1 System File Permissions"


SEVERITY_WEIGHTS: dict[Severity, int] = {
    Severity.CRITICAL: 4,
    Severity.HIGH: 3,
    Severity.MEDIUM: 2,
    Severity.LOW: 1,
}


def resolve_target_path(root_prefix: str, target_path: str) -> str:
    """Safely resolve a target filesystem path against an optional root prefix (CWE-22 defense).

    Args:
        root_prefix: Base directory path for sandbox/chroot (or empty for system root).
        target_path: Absolute path to the configuration file (e.g. /etc/ssh/sshd_config).

    Returns:
        The safe absolute path on the host.

    Raises:
        ValueError: If path traversal is detected outside root_prefix.
    """
    cleaned_target = target_path.lstrip("/")
    if not root_prefix:
        return os.path.abspath(target_path)

    base_abs = os.path.abspath(root_prefix)
    combined = os.path.abspath(os.path.join(base_abs, cleaned_target))

    # Path traversal check using commonpath
    if os.path.commonpath([base_abs, combined]) != base_abs:
        raise ValueError(f"Path traversal detected: {target_path!r} outside {root_prefix!r}")
    return combined


def safe_read_file(path: str, max_bytes: int = 10 * 1024 * 1024) -> Optional[str]:
    """Safely read a text file with size limit (CWE-400 anti-DoS)."""
    if not os.path.exists(path) or os.path.isdir(path):
        return None
    try:
        size = os.path.getsize(path)
        if size > max_bytes:
            raise ValueError(f"File {path!r} exceeds size limit of {max_bytes} bytes")
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return f.read()
    except (OSError, PermissionError):
        return None


def safe_write_file(path: str, content: str, mode: int = 0o600) -> bool:
    """Safely write content to a file with proper permissions and atomic write."""
    temp_path = f"{path}.tmp.{os.getpid()}"
    try:
        parent_dir = os.path.dirname(path)
        if parent_dir:
            os.makedirs(parent_dir, exist_ok=True)
        # Write to temporary adjacent file and replace atomically
        with open(temp_path, "w", encoding="utf-8") as f:
            f.write(content)
        os.chmod(temp_path, mode)
        os.replace(temp_path, path)
        return True
    except OSError:
        if os.path.exists(temp_path):
            try:
                os.unlink(temp_path)
            except OSError:
                pass
        return False


class AuditResult(BaseModel):
    """Result of auditing a single CIS rule."""

    model_config = {"extra": "forbid"}

    rule_id: str = Field(..., description="Unique CIS rule identifier")
    name: str = Field(..., description="Human-readable rule title")
    section: str = Field(..., description="CIS Benchmark section")
    status: RuleStatus = Field(..., description="Audit outcome")
    severity: Severity = Field(..., description="Severity level")
    details: str = Field(..., description="Context or findings")
    current_value: Optional[str] = Field(default=None, description="Observed system state")
    expected_value: Optional[str] = Field(default=None, description="Compliant target state")
    remediation_available: bool = Field(default=True, description="Whether rule can be auto-remediated")
    error_message: Optional[str] = Field(default=None, description="Sanitized error message if failed")


class RemediationResult(BaseModel):
    """Result of remediating a single CIS rule."""

    model_config = {"extra": "forbid"}

    rule_id: str = Field(..., description="Unique CIS rule identifier")
    name: str = Field(..., description="Human-readable rule title")
    changed: bool = Field(..., description="Whether system state was modified")
    backup_path: Optional[str] = Field(default=None, description="Path to created .bak file")
    details: str = Field(..., description="Summary of remediation performed")
    error_message: Optional[str] = Field(default=None, description="Sanitized error message if failed")


class RollbackResult(BaseModel):
    """Result of rolling back a single CIS rule."""

    model_config = {"extra": "forbid"}

    rule_id: str = Field(..., description="Unique CIS rule identifier")
    name: str = Field(..., description="Human-readable rule title")
    restored: bool = Field(..., description="Whether rollback succeeded")
    details: str = Field(..., description="Summary of rollback action")
    error_message: Optional[str] = Field(default=None, description="Sanitized error message if failed")


class CISRule(ABC):
    """Abstract Base Class for all CIS Benchmark Level 1 rules."""

    rule_id: str
    title: str
    description: str
    severity: Severity
    section: str
    remediation_supported: bool = True

    @abstractmethod
    def audit(self, root_prefix: str = "") -> AuditResult:
        """Audit the system or target prefix against the CIS rule specification.

        Args:
            root_prefix: Optional root directory prefix for chroot/test sandbox.

        Returns:
            AuditResult instance with status, current vs expected values and details.
        """
        raise NotImplementedError

    @abstractmethod
    def remediate(
        self,
        root_prefix: str = "",
        dry_run: bool = False,
        backup_manager: Any = None,
    ) -> RemediationResult:
        """Remediate non-compliant configuration idempotently.

        Args:
            root_prefix: Optional root directory prefix.
            dry_run: If True, preview changes without modifying filesystem.
            backup_manager: Optional BackupManager instance to create .bak snapshots.

        Returns:
            RemediationResult indicating whether changes were made.
        """
        raise NotImplementedError

    @abstractmethod
    def rollback(self, backup_manager: Any, root_prefix: str = "") -> RollbackResult:
        """Revert changes made during remediation using the backup manager.

        Args:
            backup_manager: BackupManager holding .bak snapshot.
            root_prefix: Optional root directory prefix.

        Returns:
            RollbackResult indicating restoration outcome.
        """
        raise NotImplementedError
