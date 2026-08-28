"""CIS Benchmark Level 1 rules for OpenSSH Server configuration (/etc/ssh/sshd_config)."""

from __future__ import annotations

import os
import re
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

SSH_CONFIG_FILE = "/etc/ssh/sshd_config"


def parse_ssh_directives(content: str) -> dict[str, str]:
    """Parse active SSH directives into a case-insensitive dictionary."""
    directives: dict[str, str] = {}
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = re.split(r"\s+", line, maxsplit=1)
        if len(parts) == 2:
            directives[parts[0].lower()] = parts[1].strip()
        elif len(parts) == 1 and "=" in parts[0]:
            k, v = parts[0].split("=", 1)
            directives[k.lower()] = v.strip()
    return directives


def update_ssh_directive(content: str, key: str, value: str) -> tuple[str, bool]:
    """Idempotently update or add an SSH configuration directive in sshd_config.

    Returns:
        tuple (updated_content, changed_boolean)
    """
    key_lower = key.lower()
    pattern_active = re.compile(rf"^(\s*){re.escape(key)}\s+(.*)$", re.IGNORECASE | re.MULTILINE)
    pattern_commented = re.compile(rf"^(\s*)#\s*{re.escape(key)}\b.*$", re.IGNORECASE | re.MULTILINE)

    match = pattern_active.search(content)
    if match:
        current_val = match.group(2).strip()
        if current_val.lower() == value.lower():
            return content, False
        # Replace active directive
        new_content = pattern_active.sub(rf"\1{key} {value}", content, count=1)
        return new_content, True

    # If commented out, replace the comment with active directive
    if pattern_commented.search(content):
        new_content = pattern_commented.sub(rf"{key} {value}", content, count=1)
        return new_content, True

    # If not present at all, append to config
    delimiter = "\n" if not content.endswith("\n") else ""
    new_content = f"{content}{delimiter}{key} {value}\n"
    return new_content, True


class BaseSSHRule(CISRule):
    """Common base implementation for sshd_config CIS rules."""

    section = CISSection.SSH.value
    target_directive: str
    compliant_value: str
    target_file = SSH_CONFIG_FILE

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
                details=f"SSH config file not found or inaccessible at {file_path}",
                current_value="MISSING",
                expected_value=f"{self.target_directive} {self.compliant_value}",
                remediation_available=self.remediation_supported,
            )

        directives = parse_ssh_directives(content)
        current = directives.get(self.target_directive.lower())

        is_compliant = self._is_value_compliant(current)
        status = RuleStatus.PASSED if is_compliant else RuleStatus.FAILED

        return AuditResult(
            rule_id=self.rule_id,
            name=self.title,
            section=self.section,
            status=status,
            severity=self.severity,
            details=f"Directive '{self.target_directive}' is set to '{current}' (expected '{self.compliant_value}')",
            current_value=current if current is not None else "UNSET",
            expected_value=self.compliant_value,
            remediation_available=self.remediation_supported,
        )

    def _is_value_compliant(self, current: Optional[str]) -> bool:
        if current is None:
            return False
        return current.strip().lower() == self.compliant_value.strip().lower()

    def remediate(
        self,
        root_prefix: str = "",
        dry_run: bool = False,
        backup_manager: Any = None,
    ) -> RemediationResult:
        file_path = self._get_target_file_path(root_prefix)
        content = safe_read_file(file_path)
        if content is None:
            content = "# CIS Hardened sshd_config\n"

        directives = parse_ssh_directives(content)
        current = directives.get(self.target_directive.lower())
        if self._is_value_compliant(current):
            return RemediationResult(
                rule_id=self.rule_id,
                name=self.title,
                changed=False,
                backup_path=None,
                details=f"Directive '{self.target_directive}' is already compliant ({self.compliant_value})",
            )

        new_content, changed = update_ssh_directive(content, self.target_directive, self.compliant_value)
        if not changed:
            return RemediationResult(
                rule_id=self.rule_id,
                name=self.title,
                changed=False,
                details="No changes required",
            )

        if dry_run:
            return RemediationResult(
                rule_id=self.rule_id,
                name=self.title,
                changed=True,
                details=f"[DRY-RUN] Would set '{self.target_directive}' to '{self.compliant_value}' in {file_path}",
            )

        backup_entry = None
        if backup_manager is not None:
            backup_entry = backup_manager.backup_file(file_path)

        success = safe_write_file(file_path, new_content, mode=0o600)
        if not success:
            return RemediationResult(
                rule_id=self.rule_id,
                name=self.title,
                changed=False,
                details="Failed to write updated SSH config",
                error_message=f"Write error on {file_path}",
            )

        return RemediationResult(
            rule_id=self.rule_id,
            name=self.title,
            changed=True,
            backup_path=backup_entry.backup_path if backup_entry else None,
            details=f"Successfully configured '{self.target_directive} {self.compliant_value}' in {file_path}",
        )

    def rollback(self, backup_manager: Any, root_prefix: str = "") -> RollbackResult:
        file_path = self._get_target_file_path(root_prefix)
        if backup_manager is None:
            return RollbackResult(
                rule_id=self.rule_id,
                name=self.title,
                restored=False,
                details="No backup manager provided for rollback",
                error_message="Missing backup manager",
            )
        success = backup_manager.restore_file(file_path)
        return RollbackResult(
            rule_id=self.rule_id,
            name=self.title,
            restored=success,
            details=f"Restored original config for {file_path}" if success else f"Failed to restore {file_path}",
        )


class SSHPermitRootLogin(BaseSSHRule):
    """CIS 5.2.4: Ensure SSH PermitRootLogin is set to 'no'."""

    rule_id = "CIS-SSH-001"
    title = "Disable SSH Root Login"
    description = "Disallow direct root login over SSH to prevent brute force root compromise."
    severity = Severity.CRITICAL
    target_directive = "PermitRootLogin"
    compliant_value = "no"


class SSHPasswordAuthentication(BaseSSHRule):
    """CIS 5.2.8: Ensure SSH PasswordAuthentication is set to 'no'."""

    rule_id = "CIS-SSH-002"
    title = "Disable SSH Password Authentication"
    description = "Enforce public key authentication and disable password-based logins."
    severity = Severity.HIGH
    target_directive = "PasswordAuthentication"
    compliant_value = "no"


class SSHMaxAuthTries(BaseSSHRule):
    """CIS 5.2.5: Ensure SSH MaxAuthTries is set to 4 or less."""

    rule_id = "CIS-SSH-003"
    title = "Set SSH MaxAuthTries to 4"
    description = "Limit maximum authentication attempts per connection to mitigate brute-force attacks."
    severity = Severity.MEDIUM
    target_directive = "MaxAuthTries"
    compliant_value = "4"

    def _is_value_compliant(self, current: Optional[str]) -> bool:
        if current is None:
            return False
        try:
            val = int(current.strip())
            return 1 <= val <= 4
        except ValueError:
            return False


class SSHX11Forwarding(BaseSSHRule):
    """CIS 5.2.6: Ensure SSH X11Forwarding is set to 'no'."""

    rule_id = "CIS-SSH-004"
    title = "Disable SSH X11 Forwarding"
    description = "Disable GUI X11 forwarding over SSH to mitigate X11 protocol vulnerabilities."
    severity = Severity.HIGH
    target_directive = "X11Forwarding"
    compliant_value = "no"


class SSHClientAliveInterval(BaseSSHRule):
    """CIS 5.2.11: Ensure SSH ClientAliveInterval is configured (300)."""

    rule_id = "CIS-SSH-005"
    title = "Set SSH ClientAliveInterval"
    description = "Set inactivity timeout for SSH sessions to prevent abandoned sessions from remaining open."
    severity = Severity.LOW
    target_directive = "ClientAliveInterval"
    compliant_value = "300"

    def _is_value_compliant(self, current: Optional[str]) -> bool:
        if current is None:
            return False
        try:
            val = int(current.strip())
            return 1 <= val <= 300
        except ValueError:
            return False


class SSHLoginGraceTime(BaseSSHRule):
    """CIS 5.2.10: Ensure SSH LoginGraceTime is set to 60 or less."""

    rule_id = "CIS-SSH-006"
    title = "Set SSH LoginGraceTime to 60"
    description = "Limit time unauthenticated clients can remain connected to reduce denial of service risk."
    severity = Severity.MEDIUM
    target_directive = "LoginGraceTime"
    compliant_value = "60"

    def _is_value_compliant(self, current: Optional[str]) -> bool:
        if current is None:
            return False
        try:
            val = int(current.strip())
            return 1 <= val <= 60
        except ValueError:
            return False
