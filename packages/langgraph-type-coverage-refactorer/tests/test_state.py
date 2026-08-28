"""Unit tests for Pydantic v2 state models.

Verifies immutability, extra field forbidding, and validation constraints.
Adheres to SECURITY.md Standard #7 and #15.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from refactorer.state import (
    MissingCoverageBranch,
    RefactorProposal,
    RefactorState,
    TypeIssue,
    VerificationResult,
)


def test_type_issue_valid_instantiation():
    issue = TypeIssue(
        file_path="src/sample.py",
        function_name="calc_total",
        param_name="amount",
        issue_type="missing_param_type",
        line_number=12,
        suggested_type="float",
        description="Missing float type for amount",
    )
    assert issue.file_path == "src/sample.py"
    assert issue.function_name == "calc_total"
    assert issue.param_name == "amount"
    assert issue.line_number == 12
    assert issue.suggested_type == "float"


def test_type_issue_immutability_frozen():
    issue = TypeIssue(
        file_path="src/sample.py",
        function_name="calc_total",
        param_name=None,
        issue_type="missing_return_type",
        line_number=1,
        suggested_type="int",
        description="Missing return type",
    )
    with pytest.raises(ValidationError):
        issue.function_name = "mutated_func"  # type: ignore


def test_type_issue_extra_forbidden():
    with pytest.raises(ValidationError):
        TypeIssue(
            file_path="src/sample.py",
            function_name="calc_total",
            issue_type="missing_return_type",
            line_number=1,
            suggested_type="int",
            description="Missing return type",
            unexpected_field="disallowed",  # type: ignore
        )


def test_type_issue_invalid_line_number():
    with pytest.raises(ValidationError):
        TypeIssue(
            file_path="src/sample.py",
            function_name="calc_total",
            issue_type="missing_return_type",
            line_number=0,  # ge=1 required
            suggested_type="int",
            description="Invalid line",
        )


def test_missing_coverage_branch_valid():
    branch = MissingCoverageBranch(
        file_path="src/sample.py",
        function_name="process_item",
        branch_id="process_item:25:if_true",
        branch_type="if_true",
        line_number=25,
        condition_code="if count > 10",
        description="True branch for count > 10",
    )
    assert branch.branch_id == "process_item:25:if_true"
    assert branch.branch_type == "if_true"


def test_missing_coverage_branch_frozen_and_extra_forbid():
    branch = MissingCoverageBranch(
        file_path="src/sample.py",
        function_name="process_item",
        branch_id="process_item:25:if_true",
        branch_type="if_true",
        line_number=25,
        condition_code="if count > 10",
        description="True branch",
    )
    with pytest.raises(ValidationError):
        branch.line_number = 50  # type: ignore

    with pytest.raises(ValidationError):
        MissingCoverageBranch(
            file_path="src/sample.py",
            function_name="process_item",
            branch_id="b1",
            branch_type="if_true",
            line_number=1,
            condition_code="if True",
            description="test",
            injected_key="malicious",  # type: ignore
        )


def test_verification_result_constraints():
    res = VerificationResult(
        mypy_passed=True,
        mypy_output="Success: no issues found",
        pytest_passed=True,
        pytest_output="10 passed in 0.05s",
        coverage_pct=94.5,
        execution_time_ms=120.3,
        error_message=None,
    )
    assert res.mypy_passed is True
    assert res.coverage_pct == 94.5

    # Coverage out of bounds (<0 or >100)
    with pytest.raises(ValidationError):
        VerificationResult(
            mypy_passed=True,
            pytest_passed=True,
            coverage_pct=105.0,  # Invalid: > 100
        )

    with pytest.raises(ValidationError):
        VerificationResult(
            mypy_passed=True,
            pytest_passed=True,
            coverage_pct=-5.0,  # Invalid: < 0
        )


def test_refactor_proposal_lifecycle_statuses():
    for valid_status in ("PENDING", "ACCEPTED", "REJECTED", "FAILED"):
        prop = RefactorProposal(
            file_path="test.py",
            original_code="def f(): pass",
            refactored_code="def f() -> None: pass",
            generated_tests="def test_f(): pass",
            status=valid_status,
        )
        assert prop.status == valid_status

    with pytest.raises(ValidationError):
        RefactorProposal(
            file_path="test.py",
            original_code="def f(): pass",
            refactored_code="def f() -> None: pass",
            generated_tests="def test_f(): pass",
            status="UNKNOWN_STATUS",  # Disallowed regex pattern
        )


def test_refactor_state_defaults_and_json():
    state = RefactorState(
        target_path="main.py",
        source_code="def add(a, b): return a + b",
    )
    assert state.iterations == 0
    assert state.max_iterations == 3
    assert state.target_coverage == 90.0
    assert state.strict_mode is True
    assert state.is_complete is False
    assert state.error is None

    json_str = state.model_dump_json()
    assert "target_path" in json_str
    assert "main.py" in json_str
