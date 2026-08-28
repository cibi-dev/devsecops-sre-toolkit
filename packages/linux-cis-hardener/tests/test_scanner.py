"""Unit tests for the CIS Benchmark Audit Scanner and score calculation."""

import os
import pytest
from unittest.mock import MagicMock

from cis.rules import get_all_rules
from cis.rules.base import AuditResult, CISRule, RuleStatus, Severity
from cis.scanner import CISScanner, ScanReport


@pytest.fixture
def sandbox_root(tmp_path):
    root = tmp_path / "scanner_sandbox"
    root.mkdir()
    (root / "etc").mkdir()
    (root / "etc" / "ssh").mkdir()
    (root / "etc" / "sysctl.d").mkdir()
    return str(root)


def test_scanner_empty_sandbox_low_score(sandbox_root):
    scanner = CISScanner(root_prefix=sandbox_root)
    report = scanner.audit()

    assert isinstance(report, ScanReport)
    assert report.total_rules >= 15
    assert report.score == 0.0
    assert report.passed_rules == 0
    assert report.failed_rules == report.total_rules
    assert report.root_prefix == sandbox_root


def test_scanner_rule_filtering(sandbox_root):
    scanner = CISScanner(root_prefix=sandbox_root)

    # Filter by rule IDs
    report = scanner.audit(rule_ids=["CIS-SSH-001", "CIS-SSH-002"])
    assert report.total_rules == 2
    assert {r.rule_id for r in report.results} == {"CIS-SSH-001", "CIS-SSH-002"}

    # Filter by section
    report_sec = scanner.audit(sections=["SSH"])
    assert report_sec.total_rules >= 5
    for r in report_sec.results:
        assert "SSH" in r.section


def test_scanner_weighted_score_calculation():
    # Mock rules with known severities
    rule1 = MagicMock(spec=CISRule)
    rule1.rule_id = "R1"
    rule1.title = "Rule 1"
    rule1.section = "Sec A"
    rule1.severity = Severity.CRITICAL  # Weight 4
    rule1.remediation_supported = True
    rule1.audit.return_value = AuditResult(
        rule_id="R1", name="Rule 1", section="Sec A",
        status=RuleStatus.PASSED, severity=Severity.CRITICAL, details="OK"
    )

    rule2 = MagicMock(spec=CISRule)
    rule2.rule_id = "R2"
    rule2.title = "Rule 2"
    rule2.section = "Sec A"
    rule2.severity = Severity.HIGH  # Weight 3
    rule2.remediation_supported = True
    rule2.audit.return_value = AuditResult(
        rule_id="R2", name="Rule 2", section="Sec A",
        status=RuleStatus.FAILED, severity=Severity.HIGH, details="Bad"
    )

    rule3 = MagicMock(spec=CISRule)
    rule3.rule_id = "R3"
    rule3.title = "Rule 3"
    rule3.section = "Sec B"
    rule3.severity = Severity.LOW  # Weight 1
    rule3.remediation_supported = True
    rule3.audit.return_value = AuditResult(
        rule_id="R3", name="Rule 3", section="Sec B",
        status=RuleStatus.PASSED, severity=Severity.LOW, details="OK"
    )

    # Total weight: 4 + 3 + 1 = 8. Passed weight: 4 + 1 = 5.
    # Score = (5 / 8) * 100 = 62.5%
    scanner = CISScanner(rules=[rule1, rule2, rule3])
    report = scanner.audit()

    assert report.total_rules == 3
    assert report.passed_rules == 2
    assert report.failed_rules == 1
    assert report.score == 62.5
    assert report.section_scores["Sec A"] == round((4 / 7) * 100, 1)  # 57.1%
    assert report.section_scores["Sec B"] == 100.0


def test_scanner_handles_unexpected_exception():
    rule = MagicMock(spec=CISRule)
    rule.rule_id = "ERR-01"
    rule.title = "Crashing Rule"
    rule.section = "Test"
    rule.severity = Severity.HIGH
    rule.remediation_supported = False
    rule.audit.side_effect = RuntimeError("Disk I/O failure")

    scanner = CISScanner(rules=[rule])
    report = scanner.audit()

    assert report.total_rules == 1
    assert report.error_rules == 1
    assert report.results[0].status == RuleStatus.ERROR
    assert "Disk I/O failure" in report.results[0].details
