"""CIS Benchmark Level 1 rules for Linux Host Firewall (nftables / iptables)."""

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

NFTABLES_CONF = "/etc/nftables.conf"

RECOMMENDED_NFTABLES_TEMPLATE = """#!/usr/sbin/nft -f
# CIS Benchmark Level 1 Base Firewall Configuration
flush ruleset

table inet filter {
    chain input {
        type filter hook input priority 0; policy drop;
        iif "lo" accept
        ct state established,related accept
        ct state invalid drop
        tcp dport 22 accept comment "Allow SSH"
    }
    chain forward {
        type filter hook forward priority 0; policy drop;
    }
    chain output {
        type filter hook output priority 0; policy accept;
    }
}
"""


class FirewallInstalled(CISRule):
    """CIS 3.5.1.1: Ensure a host firewall service (nftables) configuration is present."""

    rule_id = "CIS-FW-001"
    title = "Ensure Firewall Configuration is Present"
    description = "A host-based firewall protects against unauthorized network connections and reconnaissance."
    severity = Severity.HIGH
    section = CISSection.FIREWALL.value
    target_file = NFTABLES_CONF

    def _get_target_file_path(self, root_prefix: str) -> str:
        return resolve_target_path(root_prefix, self.target_file)

    def audit(self, root_prefix: str = "") -> AuditResult:
        file_path = self._get_target_file_path(root_prefix)
        content = safe_read_file(file_path)
        if content is None or not content.strip():
            return AuditResult(
                rule_id=self.rule_id,
                name=self.title,
                section=self.section,
                status=RuleStatus.FAILED,
                severity=self.severity,
                details=f"Firewall configuration file missing at {file_path}",
                current_value="MISSING",
                expected_value="PRESENT",
                remediation_available=self.remediation_supported,
            )

        return AuditResult(
            rule_id=self.rule_id,
            name=self.title,
            section=self.section,
            status=RuleStatus.PASSED,
            severity=self.severity,
            details=f"Firewall configuration found at {file_path}",
            current_value="PRESENT",
            expected_value="PRESENT",
            remediation_available=self.remediation_supported,
        )

    def remediate(
        self,
        root_prefix: str = "",
        dry_run: bool = False,
        backup_manager: Any = None,
    ) -> RemediationResult:
        file_path = self._get_target_file_path(root_prefix)
        content = safe_read_file(file_path)
        if content and content.strip():
            return RemediationResult(
                rule_id=self.rule_id,
                name=self.title,
                changed=False,
                details=f"Firewall config already exists at {file_path}",
            )

        if dry_run:
            return RemediationResult(
                rule_id=self.rule_id,
                name=self.title,
                changed=True,
                details=f"[DRY-RUN] Would create default CIS nftables config at {file_path}",
            )

        backup_entry = None
        if backup_manager is not None:
            backup_entry = backup_manager.backup_file(file_path)

        success = safe_write_file(file_path, RECOMMENDED_NFTABLES_TEMPLATE, mode=0o600)
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
            details=f"Created baseline CIS firewall configuration at {file_path}",
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
            details=f"Restored firewall configuration from backup" if success else f"Failed rollback on {file_path}",
        )


class FirewallDefaultDrop(CISRule):
    """CIS 3.5.1.2: Ensure nftables input and forward chains have default policy DROP."""

    rule_id = "CIS-FW-002"
    title = "Ensure Firewall Default Policy is DROP"
    description = "Default DROP policy ensures all unapproved network traffic is blocked by default."
    severity = Severity.HIGH
    section = CISSection.FIREWALL.value
    target_file = NFTABLES_CONF

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
                details=f"Firewall config file missing at {file_path}",
                current_value="MISSING",
                expected_value="hook input ... policy drop; hook forward ... policy drop;",
                remediation_available=self.remediation_supported,
            )

        # Match input chain with policy drop
        has_input_drop = bool(re.search(r"chain\s+input\s*\{[^}]*policy\s+drop", content, re.IGNORECASE))
        has_forward_drop = bool(re.search(r"chain\s+forward\s*\{[^}]*policy\s+drop", content, re.IGNORECASE))

        is_compliant = has_input_drop and has_forward_drop
        status = RuleStatus.PASSED if is_compliant else RuleStatus.FAILED

        current_val = f"input_drop={has_input_drop}, forward_drop={has_forward_drop}"
        return AuditResult(
            rule_id=self.rule_id,
            name=self.title,
            section=self.section,
            status=status,
            severity=self.severity,
            details=f"Firewall drop policies: {current_val}",
            current_value=current_val,
            expected_value="input_drop=True, forward_drop=True",
            remediation_available=self.remediation_supported,
        )

    def remediate(
        self,
        root_prefix: str = "",
        dry_run: bool = False,
        backup_manager: Any = None,
    ) -> RemediationResult:
        file_path = self._get_target_file_path(root_prefix)
        audit_res = self.audit(root_prefix=root_prefix)
        if audit_res.status == RuleStatus.PASSED:
            return RemediationResult(
                rule_id=self.rule_id,
                name=self.title,
                changed=False,
                details="Firewall default DROP policies are already configured",
            )

        if dry_run:
            return RemediationResult(
                rule_id=self.rule_id,
                name=self.title,
                changed=True,
                details=f"[DRY-RUN] Would apply default DROP policy in {file_path}",
            )

        backup_entry = None
        if backup_manager is not None:
            backup_entry = backup_manager.backup_file(file_path)

        success = safe_write_file(file_path, RECOMMENDED_NFTABLES_TEMPLATE, mode=0o600)
        if not success:
            return RemediationResult(
                rule_id=self.rule_id,
                name=self.title,
                changed=False,
                details="Failed to update firewall configuration",
                error_message=f"Write error on {file_path}",
            )

        return RemediationResult(
            rule_id=self.rule_id,
            name=self.title,
            changed=True,
            backup_path=backup_entry.backup_path if backup_entry else None,
            details=f"Applied CIS firewall default DROP policy in {file_path}",
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
            details=f"Restored firewall configuration from backup" if success else f"Failed rollback on {file_path}",
        )


class FirewallLoopback(CISRule):
    """CIS 3.5.1.4: Ensure loopback traffic is accepted."""

    rule_id = "CIS-FW-003"
    title = "Ensure Loopback Traffic is Configured"
    description = "Loopback interface traffic must be permitted for internal inter-process communications."
    severity = Severity.MEDIUM
    section = CISSection.FIREWALL.value
    target_file = NFTABLES_CONF

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
                details=f"Firewall config file missing at {file_path}",
                current_value="MISSING",
                expected_value='iif "lo" accept',
                remediation_available=self.remediation_supported,
            )

        has_loopback = bool(re.search(r'iif\s+"lo"\s+accept|iifname\s+"lo"\s+accept', content, re.IGNORECASE))
        status = RuleStatus.PASSED if has_loopback else RuleStatus.FAILED

        return AuditResult(
            rule_id=self.rule_id,
            name=self.title,
            section=self.section,
            status=status,
            severity=self.severity,
            details="Loopback accept rule configured" if has_loopback else "Loopback accept rule missing",
            current_value="PRESENT" if has_loopback else "MISSING",
            expected_value="PRESENT",
            remediation_available=self.remediation_supported,
        )

    def remediate(
        self,
        root_prefix: str = "",
        dry_run: bool = False,
        backup_manager: Any = None,
    ) -> RemediationResult:
        file_path = self._get_target_file_path(root_prefix)
        audit_res = self.audit(root_prefix=root_prefix)
        if audit_res.status == RuleStatus.PASSED:
            return RemediationResult(
                rule_id=self.rule_id,
                name=self.title,
                changed=False,
                details="Loopback accept rule already configured",
            )

        if dry_run:
            return RemediationResult(
                rule_id=self.rule_id,
                name=self.title,
                changed=True,
                details=f"[DRY-RUN] Would configure loopback accept in {file_path}",
            )

        backup_entry = None
        if backup_manager is not None:
            backup_entry = backup_manager.backup_file(file_path)

        success = safe_write_file(file_path, RECOMMENDED_NFTABLES_TEMPLATE, mode=0o600)
        if not success:
            return RemediationResult(
                rule_id=self.rule_id,
                name=self.title,
                changed=False,
                details="Failed to update firewall configuration",
                error_message=f"Write error on {file_path}",
            )

        return RemediationResult(
            rule_id=self.rule_id,
            name=self.title,
            changed=True,
            backup_path=backup_entry.backup_path if backup_entry else None,
            details=f"Configured loopback rule in {file_path}",
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
            details=f"Restored firewall configuration from backup" if success else f"Failed rollback on {file_path}",
        )
