"""CIS Benchmark Level 1 Audit Scanner with weighted scoring and non-privileged execution."""

from __future__ import annotations

import datetime
import os
import platform
import sys
from typing import Optional

from pydantic import BaseModel, Field

from cis.rules import get_all_rules
from cis.rules.base import (
    AuditResult,
    CISRule,
    RuleStatus,
    SEVERITY_WEIGHTS,
    Severity,
)


class ScanReport(BaseModel):
    """Structured report generated from a CIS benchmark audit."""

    model_config = {"extra": "forbid"}

    timestamp: str = Field(..., description="ISO 8601 audit timestamp")
    host: str = Field(..., description="Target hostname or system ID")
    root_prefix: str = Field("", description="Target root directory prefix")
    score: float = Field(..., description="Weighted CIS compliance score (0.0 - 100.0%)")
    total_rules: int = Field(..., description="Total number of evaluated rules")
    passed_rules: int = Field(..., description="Count of compliant rules")
    failed_rules: int = Field(..., description="Count of non-compliant rules")
    skipped_rules: int = Field(0, description="Count of skipped rules")
    error_rules: int = Field(0, description="Count of rules encountering execution errors")
    section_scores: dict[str, float] = Field(default_factory=dict, description="Compliance score per section")
    summary_by_severity: dict[str, dict[str, int]] = Field(
        default_factory=dict, description="Breakdown of status counts by severity level"
    )
    results: list[AuditResult] = Field(default_factory=list, description="Individual rule audit outcomes")


class CISScanner:
    """Read-only audit scanner evaluating CIS Benchmark Level 1 rules."""

    def __init__(
        self,
        rules: Optional[list[CISRule]] = None,
        root_prefix: str = "",
        suppress_root_warning: bool = False,
    ):
        self.root_prefix = root_prefix
        self.rules: list[CISRule] = rules if rules is not None else get_all_rules()

        # CWE-250: Privilege Separation guardrail
        if not root_prefix and os.geteuid() == 0 and not suppress_root_warning:
            print(
                "SECURITY WARNING (CWE-250): CIS Audit Scanner is running with root privileges. "
                "Read-only auditing does not require elevated privileges.",
                file=sys.stderr,
            )

    def audit(
        self,
        rule_ids: Optional[list[str]] = None,
        sections: Optional[list[str]] = None,
    ) -> ScanReport:
        """Run audit across all registered or filtered CIS rules and calculate compliance score."""
        target_rules = self.rules

        if rule_ids:
            rule_ids_lower = {r.lower() for r in rule_ids}
            target_rules = [r for r in target_rules if r.rule_id.lower() in rule_ids_lower]

        if sections:
            sections_lower = {s.lower() for s in sections}
            target_rules = [r for r in target_rules if any(sec in r.section.lower() for sec in sections_lower)]

        results: list[AuditResult] = []
        for rule in target_rules:
            try:
                res = rule.audit(root_prefix=self.root_prefix)
                results.append(res)
            except Exception as e:  # Defensive catch for unexpected system errors
                results.append(
                    AuditResult(
                        rule_id=rule.rule_id,
                        name=rule.title,
                        section=rule.section,
                        status=RuleStatus.ERROR,
                        severity=rule.severity,
                        details=f"Unexpected exception during audit: {e}",
                        current_value="ERROR",
                        expected_value="N/A",
                        remediation_available=rule.remediation_supported,
                        error_message=str(e),
                    )
                )

        return self._build_report(results)

    def _build_report(self, results: list[AuditResult]) -> ScanReport:
        """Calculate weighted scores and aggregate results into a ScanReport."""
        total_rules = len(results)
        passed_count = sum(1 for r in results if r.status == RuleStatus.PASSED)
        failed_count = sum(1 for r in results if r.status == RuleStatus.FAILED)
        skipped_count = sum(1 for r in results if r.status == RuleStatus.SKIPPED)
        error_count = sum(1 for r in results if r.status == RuleStatus.ERROR)

        # Calculate overall weighted score
        total_weight = sum(SEVERITY_WEIGHTS.get(r.severity, 1) for r in results)
        passed_weight = sum(
            SEVERITY_WEIGHTS.get(r.severity, 1) for r in results if r.status == RuleStatus.PASSED
        )

        overall_score = round((passed_weight / total_weight) * 100.0, 1) if total_weight > 0 else 100.0

        # Calculate score per section
        sections: dict[str, list[AuditResult]] = {}
        for r in results:
            sections.setdefault(r.section, []).append(r)

        section_scores: dict[str, float] = {}
        for sec_name, sec_results in sections.items():
            sec_total_w = sum(SEVERITY_WEIGHTS.get(r.severity, 1) for r in sec_results)
            sec_passed_w = sum(
                SEVERITY_WEIGHTS.get(r.severity, 1) for r in sec_results if r.status == RuleStatus.PASSED
            )
            section_scores[sec_name] = (
                round((sec_passed_w / sec_total_w) * 100.0, 1) if sec_total_w > 0 else 100.0
            )

        # Summary by severity breakdown
        summary_by_severity: dict[str, dict[str, int]] = {}
        for sev in Severity:
            sev_key = sev.value
            summary_by_severity[sev_key] = {
                "PASSED": sum(1 for r in results if r.severity == sev and r.status == RuleStatus.PASSED),
                "FAILED": sum(1 for r in results if r.severity == sev and r.status == RuleStatus.FAILED),
                "ERROR": sum(1 for r in results if r.severity == sev and r.status == RuleStatus.ERROR),
                "SKIPPED": sum(1 for r in results if r.severity == sev and r.status == RuleStatus.SKIPPED),
            }

        return ScanReport(
            timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),
            host=platform.node() or "localhost",
            root_prefix=self.root_prefix,
            score=overall_score,
            total_rules=total_rules,
            passed_rules=passed_count,
            failed_rules=failed_count,
            skipped_rules=skipped_count,
            error_rules=error_count,
            section_scores=section_scores,
            summary_by_severity=summary_by_severity,
            results=results,
        )
