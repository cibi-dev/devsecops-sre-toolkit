"""Idempotent remediation engine for CIS Benchmark Level 1 security rules with privilege separation."""

from __future__ import annotations

import os
from typing import Optional

from pydantic import BaseModel, Field

from cis.backup_manager import BackupManager
from cis.rules import get_all_rules
from cis.rules.base import (
    CISRule,
    RemediationResult,
    RuleStatus,
)


class RemediationSummary(BaseModel):
    """Aggregate summary of executed CIS remediation actions."""

    model_config = {"extra": "forbid"}

    session_id: Optional[str] = Field(None, description="Active backup session ID if changes were made")
    dry_run: bool = Field(..., description="Whether actions were simulated without disk changes")
    total_evaluated: int = Field(..., description="Total rules evaluated for remediation")
    remediated_count: int = Field(..., description="Rules modified to achieve compliance")
    already_compliant_count: int = Field(..., description="Rules already adhering to CIS standard")
    failed_count: int = Field(..., description="Rules where remediation failed")
    results: list[RemediationResult] = Field(default_factory=list, description="Individual rule remediation results")


class CISRemediator:
    """Remediation engine executing idempotent fixes with automatic backups and strict privilege enforcement."""

    def __init__(
        self,
        backup_manager: Optional[BackupManager] = None,
        enforce_root: bool = True,
        root_prefix: str = "",
        rules: Optional[list[CISRule]] = None,
    ):
        self.root_prefix = root_prefix
        self.rules = rules if rules is not None else get_all_rules()

        # CWE-250 & CWE-269: Privilege Verification
        # When targeting the live system (root_prefix==""), root privileges are strictly required.
        if enforce_root and not root_prefix and os.geteuid() != 0:
            raise PermissionError(
                "CIS Remediation requires root privileges (os.geteuid() == 0). "
                "Execute with sudo or specify an unprivileged test prefix."
            )

        self.backup_manager = backup_manager or BackupManager(root_prefix=root_prefix)

    def remediate(
        self,
        rule_ids: Optional[list[str]] = None,
        sections: Optional[list[str]] = None,
        dry_run: bool = False,
    ) -> RemediationSummary:
        """Remediate target rules idempotently, creating backups prior to any modifications."""
        target_rules = self.rules

        if rule_ids:
            rule_ids_lower = {r.lower() for r in rule_ids}
            target_rules = [r for r in target_rules if r.rule_id.lower() in rule_ids_lower]

        if sections:
            sections_lower = {s.lower() for s in sections}
            target_rules = [r for r in target_rules if any(sec in r.section.lower() for sec in sections_lower)]

        session_id: Optional[str] = None
        if not dry_run and target_rules:
            session_id = self.backup_manager.start_session()

        results: list[RemediationResult] = []
        remediated_count = 0
        already_compliant_count = 0
        failed_count = 0

        for rule in target_rules:
            # Idempotency check: audit rule first
            try:
                audit_res = rule.audit(root_prefix=self.root_prefix)
                if audit_res.status == RuleStatus.PASSED:
                    already_compliant_count += 1
                    results.append(
                        RemediationResult(
                            rule_id=rule.rule_id,
                            name=rule.title,
                            changed=False,
                            backup_path=None,
                            details=f"Already compliant with {rule.rule_id}",
                        )
                    )
                    continue

                # Not compliant: execute remediation
                rem_res = rule.remediate(
                    root_prefix=self.root_prefix,
                    dry_run=dry_run,
                    backup_manager=self.backup_manager if not dry_run else None,
                )
                results.append(rem_res)

                if rem_res.changed:
                    remediated_count += 1
                elif rem_res.error_message:
                    failed_count += 1
                else:
                    already_compliant_count += 1

            except Exception as e:  # CWE-209 sanitization
                failed_count += 1
                results.append(
                    RemediationResult(
                        rule_id=rule.rule_id,
                        name=rule.title,
                        changed=False,
                        details=f"Remediation exception: {e}",
                        error_message=str(e),
                    )
                )

        return RemediationSummary(
            session_id=session_id,
            dry_run=dry_run,
            total_evaluated=len(target_rules),
            remediated_count=remediated_count,
            already_compliant_count=already_compliant_count,
            failed_count=failed_count,
            results=results,
        )
