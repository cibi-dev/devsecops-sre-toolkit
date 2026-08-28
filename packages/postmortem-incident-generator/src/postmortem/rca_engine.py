"""Root Cause Analysis (RCA) Engine for Blameless Post-Mortems.

Implements structured 5-Whys analysis, contributing factor taxonomy,
action item prioritization, and automated blameless language heuristic evaluation.
"""

from __future__ import annotations

import re
from enum import Enum
from typing import Any, Dict, List, Optional, Union

from pydantic import BaseModel, Field, field_validator

from postmortem.sanitizer import sanitize_data, sanitize_text


class ContributingFactorCategory(str, Enum):
    """Categories of contributing systemic factors."""

    INFRASTRUCTURE = "INFRASTRUCTURE"
    CODE = "CODE"
    CONFIGURATION = "CONFIGURATION"
    PROCESS = "PROCESS"
    MONITORING = "MONITORING"
    HUMAN_FACTOR = "HUMAN_FACTOR"
    THIRD_PARTY = "THIRD_PARTY"


class ActionItemPriority(str, Enum):
    """Priority levels for corrective and preventative action items."""

    P0 = "P0"  # Critical: Prevents immediate recurrence of outage
    P1 = "P1"  # High: Substantial risk reduction or observability enhancement
    P2 = "P2"  # Medium: Process improvements or debt cleanup
    P3 = "P3"  # Low: Long-term optimization


class ActionItemType(str, Enum):
    """Taxonomy of remediation actions."""

    PREVENTATIVE = "PREVENTATIVE"  # Stops root failure from occurring
    DETECTIVE = "DETECTIVE"        # Decreases TTD / alerts faster
    CORRECTIVE = "CORRECTIVE"      # Decreases MTTR / improves recovery
    PROCESS = "PROCESS"            # Runbook, training, or organizational guardrail


class FiveWhys(BaseModel):
    """Structured 5-Whys causal progression."""

    problem_statement: str
    why_chain: List[str] = Field(default_factory=list)
    root_cause: str

    @field_validator("problem_statement", "root_cause", mode="before")
    @classmethod
    def sanitize_statements(cls, v: Any) -> str:
        return sanitize_text(str(v)) if v else ""

    @field_validator("why_chain", mode="before")
    @classmethod
    def sanitize_chain(cls, v: Any) -> List[str]:
        if isinstance(v, list):
            return [sanitize_text(str(item)) for item in v]
        return []


class ContributingFactor(BaseModel):
    """Specific systemic or environmental contributing factor."""

    category: str = ContributingFactorCategory.INFRASTRUCTURE.value
    description: str
    impact: str = "MODERATE"

    @field_validator("description", "impact", mode="before")
    @classmethod
    def sanitize_fields(cls, v: Any) -> str:
        return sanitize_text(str(v)) if v else ""


class ActionItem(BaseModel):
    """Trackable remediation item with owner and SLA priority."""

    id: str
    description: str
    item_type: str = ActionItemType.PREVENTATIVE.value
    owner: str = "TBD"
    priority: str = ActionItemPriority.P1.value
    target_date: Optional[str] = None
    status: str = "OPEN"

    @field_validator("description", "owner", mode="before")
    @classmethod
    def sanitize_strings(cls, v: Any) -> str:
        return sanitize_text(str(v)) if v else ""


class RCAResult(BaseModel):
    """Consolidated Root Cause Analysis outcome."""

    trigger_event: str
    root_cause_summary: str
    five_whys: Optional[FiveWhys] = None
    contributing_factors: List[ContributingFactor] = Field(default_factory=list)
    action_items: List[ActionItem] = Field(default_factory=list)
    what_went_well: List[str] = Field(default_factory=list)
    what_went_poorly: List[str] = Field(default_factory=list)
    where_we_got_lucky: List[str] = Field(default_factory=list)


class RCAEngine:
    """Engine for building root cause models and enforcing blameless post-mortem standards."""

    BLAME_INDICATORS = [
        (re.compile(r"(?i)\b(?:human error|user error|operator error)\b"), "latently error-prone workflow / missing automated guardrails"),
        (re.compile(r"(?i)\b(?:careless|negligent|incompetent|stupid)\b"), "unclear interface constraints or inadequate tooling safeguards"),
        (re.compile(r"(?i)\b(?:he forgot|she forgot|they forgot|forgot to)\b"), "manual step omitted due to lack of automated checklist/runbook validation"),
        (re.compile(r"(?i)\b(?:should have known|should have checked)\b"), "missing automated pre-flight validation"),
        (re.compile(r"(?i)\b(?:bad developer|bad engineer|fault of)\b"), "systemic failure under specific operational stress conditions"),
    ]

    def __init__(self, sanitize: bool = True) -> None:
        self.sanitize = sanitize
        self.contributing_factors: List[ContributingFactor] = []
        self.action_items: List[ActionItem] = []
        self.what_went_well: List[str] = []
        self.what_went_poorly: List[str] = []
        self.where_we_got_lucky: List[str] = []
        self.five_whys: Optional[FiveWhys] = None
        self._action_counter = 1

    def build_5_whys(self, problem: str, why_answers: List[str], root_cause: Optional[str] = None) -> FiveWhys:
        """Construct a structured 5-Whys causal sequence."""
        clean_problem = sanitize_text(problem) if self.sanitize else problem
        clean_whys = [sanitize_text(w) if self.sanitize else w for w in why_answers]
        derived_root = root_cause or (clean_whys[-1] if clean_whys else clean_problem)
        clean_root = sanitize_text(derived_root) if self.sanitize else derived_root

        self.five_whys = FiveWhys(
            problem_statement=clean_problem,
            why_chain=clean_whys,
            root_cause=clean_root,
        )
        return self.five_whys

    def add_contributing_factor(
        self,
        category: Union[ContributingFactorCategory, str],
        description: str,
        impact: str = "HIGH",
    ) -> ContributingFactor:
        """Add a contributing factor."""
        cat_str = category.value if isinstance(category, ContributingFactorCategory) else str(category).upper()
        factor = ContributingFactor(
            category=cat_str,
            description=sanitize_text(description) if self.sanitize else description,
            impact=impact.upper(),
        )
        self.contributing_factors.append(factor)
        return factor

    def add_action_item(
        self,
        description: str,
        item_type: Union[ActionItemType, str] = ActionItemType.PREVENTATIVE,
        owner: str = "TBD",
        priority: Union[ActionItemPriority, str] = ActionItemPriority.P1,
        target_date: Optional[str] = None,
        status: str = "OPEN",
    ) -> ActionItem:
        """Register a new remediation action item."""
        type_str = item_type.value if isinstance(item_type, ActionItemType) else str(item_type).upper()
        prio_str = priority.value if isinstance(priority, ActionItemPriority) else str(priority).upper()
        item_id = f"ACT-{self._action_counter:03d}"
        self._action_counter += 1

        item = ActionItem(
            id=item_id,
            description=sanitize_text(description) if self.sanitize else description,
            item_type=type_str,
            owner=sanitize_text(owner) if self.sanitize else owner,
            priority=prio_str,
            target_date=target_date,
            status=status.upper(),
        )
        self.action_items.append(item)
        return item

    def add_reflection(
        self,
        well: Optional[List[str]] = None,
        poorly: Optional[List[str]] = None,
        lucky: Optional[List[str]] = None,
    ) -> None:
        """Record reflections on team performance and systemic response."""
        if well:
            self.what_went_well.extend([sanitize_text(w) for w in well])
        if poorly:
            self.what_went_poorly.extend([sanitize_text(p) for p in poorly])
        if lucky:
            self.where_we_got_lucky.extend([sanitize_text(l) for l in lucky])

    def evaluate_blamelessness(self, text: str) -> Dict[str, Any]:
        """Audit text for blame-oriented phrasing and suggest blameless SRE phrasing."""
        if not text:
            return {"is_blameless": True, "score": 100.0, "flagged_terms": [], "recommendations": []}

        flagged: List[str] = []
        recommendations: List[str] = []

        for pattern, suggestion in self.BLAME_INDICATORS:
            matches = pattern.findall(text)
            if matches:
                flagged.extend(matches)
                recommendations.append(
                    f"Replace blame phrasing '{matches[0]}' with systemic perspective: '{suggestion}'"
                )

        score = max(0.0, 100.0 - (len(flagged) * 25.0))
        return {
            "is_blameless": len(flagged) == 0,
            "score": score,
            "flagged_terms": flagged,
            "recommendations": recommendations,
        }

    def generate_rca_result(self, trigger_event: str, root_cause_summary: str) -> RCAResult:
        """Synthesize the full RCA result model."""
        return RCAResult(
            trigger_event=sanitize_text(trigger_event) if self.sanitize else trigger_event,
            root_cause_summary=sanitize_text(root_cause_summary) if self.sanitize else root_cause_summary,
            five_whys=self.five_whys,
            contributing_factors=list(self.contributing_factors),
            action_items=list(self.action_items),
            what_went_well=list(self.what_went_well),
            what_went_poorly=list(self.what_went_poorly),
            where_we_got_lucky=list(self.where_we_got_lucky),
        )
