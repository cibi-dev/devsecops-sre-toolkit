"""Unit tests for the CIS Remediator engine verifying idempotency, dry-run, and privilege enforcement."""

import os
import pytest
from unittest.mock import MagicMock, patch

from cis.backup_manager import BackupManager
from cis.remediator import CISRemediator, RemediationSummary
from cis.rules import get_all_rules
from cis.rules.base import (
    AuditResult,
    CISRule,
    RemediationResult,
    RuleStatus,
    Severity,
    safe_read_file,
    safe_write_file,
)
from cis.scanner import CISScanner


@pytest.fixture
def sandbox_root(tmp_path):
    root = tmp_path / "remediator_sandbox"
    root.mkdir()
    (root / "etc").mkdir()
    (root / "etc" / "ssh").mkdir()
    (root / "etc" / "sysctl.d").mkdir()
    return str(root)


def test_remediator_privilege_enforcement():
    # If root_prefix is empty and enforce_root is True and euid != 0 -> raises PermissionError
    with patch("os.geteuid", return_value=1000):
        with pytest.raises(PermissionError, match="CIS Remediation requires root privileges"):
            CISRemediator(enforce_root=True, root_prefix="")

    # If running with sandbox root_prefix or enforce_root=False -> allowed
    with patch("os.geteuid", return_value=1000):
        rem = CISRemediator(enforce_root=False, root_prefix="")
        assert rem is not None


def test_remediator_full_workflow_and_idempotency(sandbox_root):
    # Setup initial non-compliant state
    ssh_file = os.path.join(sandbox_root, "etc/ssh/sshd_config")
    safe_write_file(ssh_file, "PermitRootLogin yes\nPasswordAuthentication yes\n")

    bm = BackupManager(root_prefix=sandbox_root)
    remediator = CISRemediator(backup_manager=bm, root_prefix=sandbox_root)

    # Initial scan score: low
    scanner = CISScanner(root_prefix=sandbox_root)
    report_initial = scanner.audit()
    assert report_initial.score < 50.0

    # 1. First Remediation Pass
    summary1 = remediator.remediate(dry_run=False)
    assert isinstance(summary1, RemediationSummary)
    assert summary1.remediated_count > 0
    assert summary1.session_id is not None

    # Post-remediation scan score: 100%
    report_post = scanner.audit()
    assert report_post.score == 100.0
    assert report_post.failed_rules == 0

    # 2. Second Remediation Pass (IDEMPOTENCE CHECK)
    summary2 = remediator.remediate(dry_run=False)
    assert summary2.remediated_count == 0
    assert summary2.already_compliant_count == summary2.total_evaluated
    assert summary2.failed_count == 0


def test_remediator_dry_run_mode(sandbox_root):
    ssh_file = os.path.join(sandbox_root, "etc/ssh/sshd_config")
    safe_write_file(ssh_file, "PermitRootLogin yes\n")

    bm = BackupManager(root_prefix=sandbox_root)
    remediator = CISRemediator(backup_manager=bm, root_prefix=sandbox_root)

    summary = remediator.remediate(rule_ids=["CIS-SSH-001"], dry_run=True)
    assert summary.dry_run is True
    assert summary.remediated_count == 1
    assert summary.session_id is None

    # Verify file was NOT modified
    content = safe_read_file(ssh_file)
    assert "PermitRootLogin yes" in content


def test_remediator_handles_rule_exception(tmp_path):
    rule = MagicMock(spec=CISRule)
    rule.rule_id = "FAIL-01"
    rule.title = "Failing Rule"
    rule.section = "Test"
    rule.severity = Severity.HIGH
    rule.audit.return_value = AuditResult(
        rule_id="FAIL-01", name="Failing Rule", section="Test",
        status=RuleStatus.FAILED, severity=Severity.HIGH, details="Audit Fail"
    )
    rule.remediate.side_effect = RuntimeError("Disk full")

    test_root = str(tmp_path / "test_root")
    remediator = CISRemediator(rules=[rule], enforce_root=False, root_prefix=test_root)
    summary = remediator.remediate()

    assert summary.total_evaluated == 1
    assert summary.failed_count == 1
    assert summary.results[0].changed is False
    assert "Disk full" in summary.results[0].details


def test_remediator_with_section_and_rule_filters(sandbox_root):
    bm = BackupManager(root_prefix=sandbox_root)
    remediator = CISRemediator(backup_manager=bm, root_prefix=sandbox_root)

    # Filter by section
    summary_sec = remediator.remediate(sections=["SSH"], dry_run=True)
    assert summary_sec.total_evaluated >= 5
    for r in summary_sec.results:
        assert "SSH" in r.rule_id or "SSH" in r.name

    # Filter by rule_ids
    summary_rule = remediator.remediate(rule_ids=["CIS-SSH-001"], dry_run=True)
    assert summary_rule.total_evaluated == 1
    assert summary_rule.results[0].rule_id == "CIS-SSH-001"
