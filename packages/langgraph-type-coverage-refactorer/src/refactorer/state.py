"""State models for langgraph-type-coverage-refactorer.

Strict immutable Pydantic v2 schemas conforming to SECURITY.md Standard #7 and #15.
"""

from __future__ import annotations

from typing import Any, List, Optional
from typing_extensions import TypedDict
from pydantic import BaseModel, ConfigDict, Field


class TypeIssue(BaseModel):
    """Represents a type annotation deficiency identified in AST analysis."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    file_path: str = Field(..., description="Target file path")
    function_name: str = Field(..., description="Function or method name")
    param_name: Optional[str] = Field(
        default=None, description="Parameter name if issue is parameter-level"
    )
    issue_type: str = Field(
        ...,
        description="Type of issue (e.g. missing_param_type, missing_return_type, untyped_def)",
    )
    line_number: int = Field(..., ge=1, description="1-indexed source line number")
    suggested_type: str = Field(
        ..., description="Suggested PEP 484/585/604 compliant type annotation"
    )
    description: str = Field(..., description="Human-readable explanation of the issue")


class MissingCoverageBranch(BaseModel):
    """Represents an uncovered execution branch in the AST."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    file_path: str = Field(..., description="Target file path")
    function_name: str = Field(..., description="Function or method enclosing the branch")
    branch_id: str = Field(
        ..., description="Deterministic branch identifier (e.g. func:line:if_true)"
    )
    branch_type: str = Field(
        ...,
        description="Branch construct (if_true, if_false, try_except, for_body, while_body, match_case)",
    )
    line_number: int = Field(..., ge=1, description="1-indexed source line number")
    condition_code: str = Field(..., description="Source code snippet of the branch condition")
    description: str = Field(..., description="Description of the target execution path")


class VerificationResult(BaseModel):
    """Result of sandbox verification running MyPy and Pytest coverage."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    mypy_passed: bool = Field(..., description="Whether MyPy strict mode passed")
    mypy_output: str = Field(default="", description="Captured stdout/stderr from MyPy")
    pytest_passed: bool = Field(..., description="Whether Pytest suite passed")
    pytest_output: str = Field(default="", description="Captured stdout/stderr from Pytest")
    coverage_pct: float = Field(
        default=0.0, ge=0.0, le=100.0, description="Branch and statement coverage percentage"
    )
    execution_time_ms: float = Field(
        default=0.0, ge=0.0, description="Total sandbox verification time in milliseconds"
    )
    error_message: Optional[str] = Field(
        default=None, description="Error diagnostics if verification crashed or timed out"
    )


class RefactorProposal(BaseModel):
    """Structured proposal containing refactored code and synthesized tests."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    file_path: str = Field(..., description="Target file path")
    original_code: str = Field(..., description="Original unmodified source code")
    refactored_code: str = Field(..., description="Refactored code with strict type hints")
    generated_tests: str = Field(
        ..., description="Synthesized pytest suite targeting uncovered branches"
    )
    type_issues_fixed: List[TypeIssue] = Field(
        default_factory=list, description="List of type issues addressed"
    )
    branches_covered: List[MissingCoverageBranch] = Field(
        default_factory=list, description="List of branches targeted"
    )
    status: str = Field(
        default="PENDING",
        pattern=r"^(PENDING|ACCEPTED|REJECTED|FAILED)$",
        description="Lifecycle status of proposal",
    )
    iterations: int = Field(default=0, ge=0, description="Refactoring iteration count")


class RefactorState(BaseModel):
    """Immutable global state model for the refactorer multi-agent workflow."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    target_path: str = Field(..., description="File path of target Python module")
    source_code: str = Field(default="", description="Original source code under refactor")
    type_issues: List[TypeIssue] = Field(
        default_factory=list, description="Identified type issues"
    )
    missing_branches: List[MissingCoverageBranch] = Field(
        default_factory=list, description="Identified uncovered branches"
    )
    current_code: str = Field(default="", description="Current candidate refactored code")
    current_tests: str = Field(default="", description="Current candidate pytest suite")
    verification_history: List[VerificationResult] = Field(
        default_factory=list, description="Historical verification results"
    )
    iterations: int = Field(default=0, ge=0, description="Current iteration index")
    max_iterations: int = Field(default=3, ge=1, le=10, description="Maximum bounded iterations")
    target_coverage: float = Field(
        default=90.0, ge=0.0, le=100.0, description="Target coverage threshold percentage"
    )
    strict_mode: bool = Field(default=True, description="Enforce strict MyPy conformance")
    is_complete: bool = Field(
        default=False, description="Whether refactoring achieved all quality gates"
    )
    error: Optional[str] = Field(
        default=None, description="Fatal error message if workflow encountered unrecoverable issue"
    )


class RefactorGraphState(TypedDict, total=False):
    """TypedDict state representation used directly in LangGraph StateGraph nodes."""

    target_path: str
    source_code: str
    type_issues: List[dict[str, Any]]
    missing_branches: List[dict[str, Any]]
    current_code: str
    current_tests: str
    verification_history: List[dict[str, Any]]
    iterations: int
    max_iterations: int
    target_coverage: float
    strict_mode: bool
    is_complete: bool
    error: Optional[str]
