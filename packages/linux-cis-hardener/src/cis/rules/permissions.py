"""CIS Benchmark Level 1 rules for critical system file permissions and umask."""

from __future__ import annotations

import os
import re
import stat
from typing import Any, Optional

from cis.rules.base import (
    AuditResult,
    CISRule,
    CISSection,
    RemediationResult,
    RollbackResult,
    RuleStatus,
    Severity,
    resolve_target_path,
    safe_read_file,
    safe_write_file,
)

DEFAULT_FILE_CONTENTS: dict[str, str] = {
    "/etc/passwd": "root:x:0:0:root:/root:/bin/bash\n",
    "/etc/shadow": "root:*:19000:0:99999:7:::\n",
    "/etc/gshadow": "root:*::\n",
    "/etc/group": "root:x:0:\n",
    "/etc/ssh/sshd_config": "# CIS Hardened sshd_config\n",
}


class BaseFilePermissionRule(CISRule):
    """Base class for system file permission and ownership auditing."""

    section = CISSection.FILE_PERMISSIONS.value
    target_file: str
    max_mode: int  # Maximum permitted octal mode (e.g., 0o644)
    target_mode: int  # Exact mode applied during remediation (e.g., 0o644)
    allowed_uids: tuple[int, ...] = (0,)  # Default root uid 0
    allowed_gids: tuple[int, ...] = (0,)  # Default root gid 0

    def _get_target_file_path(self, root_prefix: str) -> str:
        return resolve_target_path(root_prefix, self.target_file)

    def audit(self, root_prefix: str = "") -> AuditResult:
        file_path = self._get_target_file_path(root_prefix)
        if not os.path.exists(file_path):
            return AuditResult(
                rule_id=self.rule_id,
                name=self.title,
                section=self.section,
                status=RuleStatus.FAILED,
                severity=self.severity,
                details=f"Target file {file_path} does not exist",
                current_value="MISSING",
                expected_value=f"mode <= {oct(self.max_mode)}, uid in {self.allowed_uids}",
                remediation_available=self.remediation_supported,
            )

        try:
            st = os.stat(file_path)
            mode = stat.S_IMODE(st.st_mode)
            uid = st.st_uid
            gid = st.st_gid

            # Check mode violation: any bit in mode that exceeds max_mode is invalid
            mode_violates = bool(mode & ~self.max_mode)
            uid_violates = (uid not in self.allowed_uids) if not root_prefix else False
            gid_violates = (gid not in self.allowed_gids) if not root_prefix else False

            is_compliant = not (mode_violates or uid_violates or gid_violates)
            status = RuleStatus.PASSED if is_compliant else RuleStatus.FAILED

            current_desc = f"mode={oct(mode)}, uid={uid}, gid={gid}"
            expected_desc = f"mode<={oct(self.max_mode)}, uid={self.allowed_uids[0]}, gid={self.allowed_gids[0]}"

            return AuditResult(
                rule_id=self.rule_id,
                name=self.title,
                section=self.section,
                status=status,
                severity=self.severity,
                details=f"File permissions: {current_desc} (target {expected_desc})",
                current_value=current_desc,
                expected_value=expected_desc,
                remediation_available=self.remediation_supported,
            )
        except (OSError, PermissionError) as e:
            return AuditResult(
                rule_id=self.rule_id,
                name=self.title,
                section=self.section,
                status=RuleStatus.ERROR,
                severity=self.severity,
                details=f"Failed to stat {file_path}: {e}",
                current_value="ERROR",
                expected_value=f"mode<={oct(self.max_mode)}",
                remediation_available=self.remediation_supported,
                error_message=str(e),
            )

    def remediate(
        self,
        root_prefix: str = "",
        dry_run: bool = False,
        backup_manager: Any = None,
    ) -> RemediationResult:
        file_path = self._get_target_file_path(root_prefix)
        file_exists = os.path.exists(file_path)

        if not file_exists:
            if dry_run:
                return RemediationResult(
                    rule_id=self.rule_id,
                    name=self.title,
                    changed=True,
                    details=f"[DRY-RUN] Would create {file_path} with mode {oct(self.target_mode)}",
                )
            backup_entry = None
            if backup_manager is not None:
                backup_entry = backup_manager.backup_file(file_path)

            default_content = DEFAULT_FILE_CONTENTS.get(self.target_file, "\n")
            success = safe_write_file(file_path, default_content, mode=self.target_mode)
            if not success:
                return RemediationResult(
                    rule_id=self.rule_id,
                    name=self.title,
                    changed=False,
                    details=f"Failed to create {file_path}",
                    error_message=f"Write error on {file_path}",
                )
            return RemediationResult(
                rule_id=self.rule_id,
                name=self.title,
                changed=True,
                backup_path=backup_entry.backup_path if backup_entry else None,
                details=f"Created {file_path} with mode {oct(self.target_mode)}",
            )

        audit_res = self.audit(root_prefix=root_prefix)
        if audit_res.status == RuleStatus.PASSED:
            return RemediationResult(
                rule_id=self.rule_id,
                name=self.title,
                changed=False,
                details=f"File {file_path} already has compliant permissions ({oct(self.target_mode)})",
            )

        if dry_run:
            return RemediationResult(
                rule_id=self.rule_id,
                name=self.title,
                changed=True,
                details=f"[DRY-RUN] Would chmod {oct(self.target_mode)} and chown {self.allowed_uids[0]}:{self.allowed_gids[0]} on {file_path}",
            )

        backup_entry = None
        if backup_manager is not None:
            backup_entry = backup_manager.backup_file(file_path)

        try:
            os.chmod(file_path, self.target_mode)
            if os.geteuid() == 0:
                os.chown(file_path, self.allowed_uids[0], self.allowed_gids[0])

            return RemediationResult(
                rule_id=self.rule_id,
                name=self.title,
                changed=True,
                backup_path=backup_entry.backup_path if backup_entry else None,
                details=f"Remediated {file_path} to mode {oct(self.target_mode)}",
            )
        except (OSError, PermissionError) as e:
            return RemediationResult(
                rule_id=self.rule_id,
                name=self.title,
                changed=False,
                details=f"Failed to remediate permissions for {file_path}",
                error_message=str(e),
            )

    def rollback(self, backup_manager: Any, root_prefix: str = "") -> RollbackResult:
        file_path = self._get_target_file_path(root_prefix)
        if backup_manager is None:
            return RollbackResult(
                rule_id=self.rule_id,
                name=self.title,
                restored=False,
                details="Missing backup manager",
                error_message="No backup manager provided",
            )
        success = backup_manager.restore_file(file_path)
        return RollbackResult(
            rule_id=self.rule_id,
            name=self.title,
            restored=success,
            details=f"Restored permissions and content for {file_path}" if success else f"Failed rollback on {file_path}",
        )


class PermPasswd(BaseFilePermissionRule):
    """CIS 6.1.2: Ensure permissions on /etc/passwd are 0644 or stricter and owned by root:root."""

    rule_id = "CIS-PERM-001"
    title = "Verify /etc/passwd Permissions"
    description = "Ensure /etc/passwd is owned by root:root with mode 0644 or stricter to prevent unauthorized user tampering."
    severity = Severity.HIGH
    target_file = "/etc/passwd"
    max_mode = 0o644
    target_mode = 0o644
    allowed_uids = (0,)
    allowed_gids = (0,)


class PermShadow(BaseFilePermissionRule):
    """CIS 6.1.3: Ensure permissions on /etc/shadow are 0640 or 0600 and owned by root:root or root:shadow."""

    rule_id = "CIS-PERM-002"
    title = "Verify /etc/shadow Permissions"
    description = "Ensure /etc/shadow contains sensitive password hashes with mode 0640 or stricter and restricted ownership."
    severity = Severity.CRITICAL
    target_file = "/etc/shadow"
    max_mode = 0o640
    target_mode = 0o640
    allowed_uids = (0,)
    allowed_gids = (0, 42)


class PermGShadow(BaseFilePermissionRule):
    """CIS 6.1.4: Ensure permissions on /etc/gshadow are 0640 or 0600 and owned by root:root or root:shadow."""

    rule_id = "CIS-PERM-003"
    title = "Verify /etc/gshadow Permissions"
    description = "Ensure /etc/gshadow contains group passwords with mode 0640 or stricter."
    severity = Severity.CRITICAL
    target_file = "/etc/gshadow"
    max_mode = 0o640
    target_mode = 0o640
    allowed_uids = (0,)
    allowed_gids = (0, 42)


class PermGroup(BaseFilePermissionRule):
    """CIS 6.1.5: Ensure permissions on /etc/group are 0644 or stricter and owned by root:root."""

    rule_id = "CIS-PERM-004"
    title = "Verify /etc/group Permissions"
    description = "Ensure /etc/group is owned by root:root with mode 0644 or stricter."
    severity = Severity.HIGH
    target_file = "/etc/group"
    max_mode = 0o644
    target_mode = 0o644
    allowed_uids = (0,)
    allowed_gids = (0,)


class PermSSHConfig(BaseFilePermissionRule):
    """CIS 6.1.10: Ensure permissions on /etc/ssh/sshd_config are 0600 and owned by root:root."""

    rule_id = "CIS-PERM-006"
    title = "Verify sshd_config File Permissions"
    description = "Ensure /etc/ssh/sshd_config is readable only by root (mode 0600) to protect SSH configuration."
    severity = Severity.HIGH
    target_file = "/etc/ssh/sshd_config"
    max_mode = 0o600
    target_mode = 0o600
    allowed_uids = (0,)
    allowed_gids = (0,)


class PermDefaultUmask(CISRule):
    """CIS 5.4.4: Ensure default user umask is 027 or more restrictive in /etc/login.defs."""

    rule_id = "CIS-PERM-005"
    title = "Configure Default User umask"
    description = "Ensure default user umask is set to 027 in /etc/login.defs to restrict default file permissions."
    severity = Severity.MEDIUM
    section = CISSection.ACCESS_CONTROL.value
    target_file = "/etc/login.defs"
    compliant_umask = "027"

    def _get_target_file_path(self, root_prefix: str) -> str:
        return resolve_target_path(root_prefix, self.target_file)

    def audit(self, root_prefix: str = "") -> AuditResult:
        file_path = self._get_target_file_path(root_prefix)
        content = safe_read_file(file_path)
        if content is None:
            return AuditResult(
                rule_id=self.rule_id,
                name=self.title,
                section=self.section,
                status=RuleStatus.FAILED,
                severity=self.severity,
                details=f"Configuration file {file_path} not found",
                current_value="MISSING",
                expected_value=f"UMASK {self.compliant_umask}",
                remediation_available=self.remediation_supported,
            )

        match = re.search(r"^\s*UMASK\s+(\d+)", content, re.MULTILINE | re.IGNORECASE)
        if not match:
            return AuditResult(
                rule_id=self.rule_id,
                name=self.title,
                section=self.section,
                status=RuleStatus.FAILED,
                severity=self.severity,
                details="UMASK directive is not defined in /etc/login.defs",
                current_value="UNSET",
                expected_value=f"UMASK {self.compliant_umask}",
                remediation_available=self.remediation_supported,
            )

        current_val = match.group(1).strip()
        try:
            oct_val = int(current_val, 8)
            is_compliant = (oct_val & 0o027) == 0o027
        except ValueError:
            is_compliant = False

        status = RuleStatus.PASSED if is_compliant else RuleStatus.FAILED
        return AuditResult(
            rule_id=self.rule_id,
            name=self.title,
            section=self.section,
            status=status,
            severity=self.severity,
            details=f"UMASK is set to {current_val} (expected {self.compliant_umask} or stricter)",
            current_value=current_val,
            expected_value=self.compliant_umask,
            remediation_available=self.remediation_supported,
        )

    def remediate(
        self,
        root_prefix: str = "",
        dry_run: bool = False,
        backup_manager: Any = None,
    ) -> RemediationResult:
        file_path = self._get_target_file_path(root_prefix)
        content = safe_read_file(file_path) or "# /etc/login.defs\n"

        audit_res = self.audit(root_prefix=root_prefix)
        if audit_res.status == RuleStatus.PASSED:
            return RemediationResult(
                rule_id=self.rule_id,
                name=self.title,
                changed=False,
                details=f"UMASK is already compliant ({self.compliant_umask})",
            )

        if dry_run:
            return RemediationResult(
                rule_id=self.rule_id,
                name=self.title,
                changed=True,
                details=f"[DRY-RUN] Would set UMASK {self.compliant_umask} in {file_path}",
            )

        backup_entry = None
        if backup_manager is not None:
            backup_entry = backup_manager.backup_file(file_path)

        pattern = re.compile(r"^\s*UMASK\s+\d+", re.MULTILINE | re.IGNORECASE)
        if pattern.search(content):
            new_content = pattern.sub(f"UMASK           {self.compliant_umask}", content, count=1)
        else:
            delimiter = "\n" if not content.endswith("\n") and content else ""
            new_content = f"{content}{delimiter}UMASK           {self.compliant_umask}\n"

        success = safe_write_file(file_path, new_content, mode=0o644)
        if not success:
            return RemediationResult(
                rule_id=self.rule_id,
                name=self.title,
                changed=False,
                details="Failed to write /etc/login.defs",
                error_message=f"Write error on {file_path}",
            )

        return RemediationResult(
            rule_id=self.rule_id,
            name=self.title,
            changed=True,
            backup_path=backup_entry.backup_path if backup_entry else None,
            details=f"Configured UMASK {self.compliant_umask} in {file_path}",
        )

    def rollback(self, backup_manager: Any, root_prefix: str = "") -> RollbackResult:
        file_path = self._get_target_file_path(root_prefix)
        if backup_manager is None:
            return RollbackResult(
                rule_id=self.rule_id,
                name=self.title,
                restored=False,
                details="Missing backup manager",
                error_message="No backup manager provided",
            )
        success = backup_manager.restore_file(file_path)
        return RollbackResult(
            rule_id=self.rule_id,
            name=self.title,
            restored=success,
            details=f"Restored /etc/login.defs from backup" if success else f"Failed rollback on {file_path}",
        )
