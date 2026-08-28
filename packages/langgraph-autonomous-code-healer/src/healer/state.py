"""State definitions and immutable Pydantic v2 data models for the Autonomous Code Healer."""

from __future__ import annotations

import operator
from typing import Annotated, Any, TypedDict
from pydantic import BaseModel, ConfigDict, Field


class CweInfo(BaseModel):
    """CWE taxonomy classification."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    id: int | str
    link: str | None = None


class BanditFinding(BaseModel):
    """Immutable model representing a single Bandit SAST security finding."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    filename: str = Field(..., description="Path or identifier of the audited file")
    test_name: str = Field(..., description="Identifier of the Bandit plugin test")
    test_id: str = Field(..., description="Bandit test ID (e.g. B602, B301, B108)")
    issue_severity: str = Field(default="LOW", description="Severity level: LOW, MEDIUM, HIGH, UNDEFINED")
    issue_confidence: str = Field(default="HIGH", description="Confidence level: LOW, MEDIUM, HIGH, UNDEFINED")
    issue_text: str = Field(..., description="Human-readable description of the security issue")
    issue_cwe: CweInfo | dict[str, Any] | int | str | None = Field(
        default=None, description="Associated CWE identifier or metadata"
    )
    line_number: int = Field(..., ge=1, description="Primary source line number of the finding")
    line_range: list[int] = Field(default_factory=list, description="Covered line numbers")
    code: str = Field(default="", description="Code snippet flagged by the SAST scanner")
    col_offset: int | None = Field(default=None, description="Starting column offset")
    end_col_offset: int | None = Field(default=None, description="Ending column offset")
    more_info: str | None = Field(default=None, description="URL or reference for additional info")

    @property
    def cwe_id(self) -> int | None:
        """Extract the numeric CWE identifier if present."""
        if isinstance(self.issue_cwe, CweInfo):
            cid = str(self.issue_cwe.id)
            digits = "".join(filter(str.isdigit, cid))
            return int(digits) if digits else None
        if isinstance(self.issue_cwe, dict):
            cid_val = self.issue_cwe.get("id")
            if cid_val is not None:
                digits = "".join(filter(str.isdigit, str(cid_val)))
                return int(digits) if digits else None
        if isinstance(self.issue_cwe, int):
            return self.issue_cwe
        if isinstance(self.issue_cwe, str):
            digits = "".join(filter(str.isdigit, self.issue_cwe))
            return int(digits) if digits else None
        return None

    @property
    def is_actionable(self) -> bool:
        """Determines if finding severity warrants automated remediation (MEDIUM or HIGH)."""
        return self.issue_severity.upper() in {"MEDIUM", "HIGH"}


class BanditReport(BaseModel):
    """Immutable model representing an entire Bandit execution report."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    generated_at: str = Field(default="", description="Timestamp when report was produced")
    errors: list[dict[str, Any]] = Field(default_factory=list, description="Parsing or scanner errors")
    results: list[BanditFinding] = Field(default_factory=list, description="List of detected security findings")
    metrics: dict[str, Any] = Field(default_factory=dict, description="Execution and aggregate metrics")

    @property
    def has_findings(self) -> bool:
        """Check if any findings exist."""
        return len(self.results) > 0

    @property
    def actionable_findings(self) -> list[BanditFinding]:
        """Filter findings that are MEDIUM or HIGH severity."""
        return [f for f in self.results if f.is_actionable]


class PatchProposal(BaseModel):
    """Immutable model representing a deterministic code remediation patch."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    finding_id: str | None = Field(default=None, description="ID of the addressed finding")
    cwe_id: int | str | None = Field(default=None, description="CWE category addressed")
    target_file: str = Field(..., description="Target file path")
    original_snippet: str = Field(..., description="Original code snippet")
    replacement_snippet: str = Field(..., description="Remediated replacement snippet")
    explanation: str = Field(..., description="Pedagogical rationale for the patch")
    confidence_score: float = Field(default=1.0, ge=0.0, le=1.0, description="Confidence in the patch validity")
    ast_validated: bool = Field(default=True, description="Whether patch passed AST syntax validation")


class HealerExecutionMetrics(BaseModel):
    """Immutable metrics container for healing loop performance."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    total_iterations: int = Field(default=0, ge=0)
    patches_applied: int = Field(default=0, ge=0)
    initial_findings_count: int = Field(default=0, ge=0)
    remaining_findings_count: int = Field(default=0, ge=0)
    syntax_errors_caught: int = Field(default=0, ge=0)
    start_time: float = Field(default=0.0)
    end_time: float = Field(default=0.0)
    duration_seconds: float = Field(default=0.0, ge=0.0)


class CodePatchState(TypedDict):
    """State schema for the LangGraph StateGraph cyclic workflow."""

    source_file: str
    original_code: str
    current_code: str
    bandit_report: dict[str, Any]
    findings: list[dict[str, Any]]
    proposed_patch: str
    patch_history: list[dict[str, Any]]
    test_output: str
    test_passed: bool
    is_clean: bool
    iterations: Annotated[int, operator.add]
    max_iterations: int
    error_message: str | None
    dry_run: bool
    diff: str
