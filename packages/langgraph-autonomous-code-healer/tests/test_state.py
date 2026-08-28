"""Unit tests for healer.state Pydantic v2 immutable models and TypedDict schemas."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from healer.state import (
    BanditFinding,
    BanditReport,
    CodePatchState,
    CweInfo,
    HealerExecutionMetrics,
    PatchProposal,
)


def test_cwe_info_creation_and_immutability():
    """Test CweInfo model creation and frozen immutability."""
    cwe = CweInfo(id=78, link="https://cwe.mitre.org/data/definitions/78.html")
    assert cwe.id == 78
    assert cwe.link == "https://cwe.mitre.org/data/definitions/78.html"

    with pytest.raises(ValidationError):
        # Frozen models prohibit mutation
        cwe.id = 502  # type: ignore

    with pytest.raises(ValidationError):
        # Extra fields forbidden
        CweInfo(id=78, extra_field="forbidden")  # type: ignore


def test_bandit_finding_model_and_cwe_extraction():
    """Test BanditFinding model creation, validation, and CWE extraction."""
    finding = BanditFinding(
        filename="app.py",
        test_name="subprocess_popen_with_shell_equals_true",
        test_id="B602",
        issue_severity="HIGH",
        issue_confidence="HIGH",
        issue_text="subprocess call with shell=True",
        issue_cwe={"id": 78, "link": "https://cwe.mitre.org/data/definitions/78.html"},
        line_number=10,
        line_range=[10, 11],
        code="subprocess.call('ls', shell=True)",
    )

    assert finding.filename == "app.py"
    assert finding.test_id == "B602"
    assert finding.cwe_id == 78
    assert finding.is_actionable is True

    # Test CWE ID extraction from CweInfo
    f2 = BanditFinding(
        filename="app.py",
        test_name="pickle",
        test_id="B301",
        issue_severity="MEDIUM",
        issue_confidence="HIGH",
        issue_text="Pickle unsafe",
        issue_cwe=CweInfo(id="502"),
        line_number=5,
    )
    assert f2.cwe_id == 502
    assert f2.is_actionable is True

    # Test CWE ID extraction from int
    f3 = BanditFinding(
        filename="app.py",
        test_name="md5",
        test_id="B303",
        issue_severity="LOW",
        issue_confidence="HIGH",
        issue_text="MD5 hash",
        issue_cwe=327,
        line_number=2,
    )
    assert f3.cwe_id == 327
    assert f3.is_actionable is False

    # Test CWE ID extraction from string 'CWE-22'
    f4 = BanditFinding(
        filename="app.py",
        test_name="tmp",
        test_id="B108",
        issue_severity="LOW",
        issue_confidence="HIGH",
        issue_text="tmp dir",
        issue_cwe="CWE-22",
        line_number=3,
    )
    assert f4.cwe_id == 22


def test_bandit_finding_validation_errors():
    """Test validation errors on invalid line_number or extra fields."""
    with pytest.raises(ValidationError):
        # Line number must be >= 1
        BanditFinding(
            filename="a.py",
            test_name="t",
            test_id="B101",
            issue_text="msg",
            line_number=0,
        )

    with pytest.raises(ValidationError):
        # Extra fields forbidden
        BanditFinding(
            filename="a.py",
            test_name="t",
            test_id="B101",
            issue_text="msg",
            line_number=1,
            malicious_payload="injected",  # type: ignore
        )


def test_bandit_report_model():
    """Test BanditReport aggregation and filtering."""
    f1 = BanditFinding(
        filename="a.py",
        test_name="t1",
        test_id="B602",
        issue_severity="HIGH",
        issue_text="High severity issue",
        line_number=1,
    )
    f2 = BanditFinding(
        filename="a.py",
        test_name="t2",
        test_id="B108",
        issue_severity="LOW",
        issue_text="Low severity issue",
        line_number=2,
    )

    report = BanditReport(
        generated_at="2026-08-27T12:00:00Z",
        results=[f1, f2],
        metrics={"loc": 100},
    )

    assert report.has_findings is True
    assert len(report.results) == 2
    assert len(report.actionable_findings) == 1
    assert report.actionable_findings[0].test_id == "B602"

    empty_report = BanditReport()
    assert empty_report.has_findings is False
    assert len(empty_report.actionable_findings) == 0


def test_patch_proposal_model():
    """Test PatchProposal validation and confidence bounds."""
    proposal = PatchProposal(
        finding_id="B602",
        cwe_id=78,
        target_file="script.py",
        original_snippet="subprocess.call(cmd, shell=True)",
        replacement_snippet="subprocess.run(cmd, shell=False)",
        explanation="Replaced shell=True with shell=False",
        confidence_score=0.95,
        ast_validated=True,
    )

    assert proposal.confidence_score == 0.95
    assert proposal.ast_validated is True

    with pytest.raises(ValidationError):
        # Confidence score must be <= 1.0
        PatchProposal(
            target_file="script.py",
            original_snippet="a",
            replacement_snippet="b",
            explanation="c",
            confidence_score=1.5,
        )


def test_healer_execution_metrics():
    """Test HealerExecutionMetrics container."""
    metrics = HealerExecutionMetrics(
        total_iterations=2,
        patches_applied=3,
        initial_findings_count=3,
        remaining_findings_count=0,
        syntax_errors_caught=0,
        start_time=100.0,
        end_time=102.5,
        duration_seconds=2.5,
    )
    assert metrics.total_iterations == 2
    assert metrics.duration_seconds == 2.5
