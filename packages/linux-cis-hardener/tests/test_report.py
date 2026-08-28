"""Unit tests for the ReportGenerator formatting outputs."""

import json
import pytest

from cis.remediator import RemediationResult, RemediationSummary
from cis.report import ReportGenerator
from cis.rules.base import AuditResult, RuleStatus, Severity
from cis.scanner import ScanReport


@pytest.fixture
def sample_scan_report():
    return ScanReport(
        timestamp="2026-08-27T20:00:00Z",
        host="test-security-node",
        root_prefix="",
        score=75.0,
        total_rules=4,
        passed_rules=3,
        failed_rules=1,
        skipped_rules=0,
        error_rules=0,
        section_scores={"5.2 SSH Server": 100.0, "3.2 Sysctl": 50.0},
        summary_by_severity={
            "CRITICAL": {"PASSED": 1, "FAILED": 0, "ERROR": 0, "SKIPPED": 0},
            "HIGH": {"PASSED": 1, "FAILED": 1, "ERROR": 0, "SKIPPED": 0},
            "MEDIUM": {"PASSED": 1, "FAILED": 0, "ERROR": 0, "SKIPPED": 0},
            "LOW": {"PASSED": 0, "FAILED": 0, "ERROR": 0, "SKIPPED": 0},
        },
        results=[
            AuditResult(
                rule_id="CIS-SSH-001",
                name="Disable Root Login",
                section="5.2 SSH Server",
                status=RuleStatus.PASSED,
                severity=Severity.CRITICAL,
                details="Compliant",
                current_value="no",
                expected_value="no",
            ),
            AuditResult(
                rule_id="CIS-SYSCTL-001",
                name="Disable IP Forwarding",
                section="3.2 Sysctl",
                status=RuleStatus.FAILED,
                severity=Severity.HIGH,
                details="Non-compliant",
                current_value="1",
                expected_value="0",
            ),
        ],
    )


def test_report_generator_json(sample_scan_report):
    json_out = ReportGenerator.to_json(sample_scan_report)
    data = json.loads(json_out)
    assert data["host"] == "test-security-node"
    assert data["score"] == 75.0
    assert len(data["results"]) == 2


def test_report_generator_markdown(sample_scan_report):
    md_out = ReportGenerator.to_markdown(sample_scan_report)
    assert "# 🛡️ CIS Benchmark Level 1 Audit Report" in md_out
    assert "**`75.0%`**" in md_out
    assert "CIS-SSH-001" in md_out
    assert "CIS-SYSCTL-001" in md_out
    assert "Executive Summary" in md_out


def test_report_generator_console(sample_scan_report):
    console_colored = ReportGenerator.to_console(sample_scan_report, color=True)
    assert "CIS BENCHMARK LEVEL 1" in console_colored
    assert "\033[" in console_colored

    console_plain = ReportGenerator.to_console(sample_scan_report, color=False)
    assert "\033[" not in console_plain
    assert "test-security-node" in console_plain


def test_remediation_summary_console():
    summary = RemediationSummary(
        session_id="sess_12345",
        dry_run=False,
        total_evaluated=2,
        remediated_count=1,
        already_compliant_count=1,
        failed_count=0,
        results=[
            RemediationResult(
                rule_id="CIS-SSH-001",
                name="Disable Root Login",
                changed=True,
                backup_path="/var/backups/test.bak",
                details="Updated directive",
            ),
            RemediationResult(
                rule_id="CIS-SYSCTL-001",
                name="Disable IP Forward",
                changed=False,
                details="Already compliant",
            ),
        ],
    )
    console_out = ReportGenerator.remediation_to_console(summary, color=False)
    assert "CIS BENCHMARK REMEDIATION SUMMARY" in console_out
    assert "sess_12345" in console_out
    assert "[CHANGED] CIS-SSH-001" in console_out
    assert "[OK] CIS-SYSCTL-001" in console_out
