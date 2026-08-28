"""Alert rule evaluator with YAML configuration, debounce timing, and state transitions.

Supports metric threshold comparisons (>, <, ==, >=, <=, !=) and Prometheus-like
PENDING -> FIRING -> RESOLVED state lifecycles.
"""

from __future__ import annotations

import enum
import logging
import re
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

import yaml
from pydantic import BaseModel, Field, field_validator

from .metrics_collector import MetricFamily

logger = logging.getLogger(__name__)

# Security constant: Maximum allowed alert config file size (1 MB) to prevent CWE-400 / YAML bombs
MAX_CONFIG_FILE_SIZE_BYTES = 1024 * 1024


class AlertState(str, enum.Enum):
    """Lifecycle states of an alert rule evaluation."""
    INACTIVE = "inactive"
    PENDING = "pending"
    FIRING = "firing"
    RESOLVED = "resolved"


class AlertSeverity(str, enum.Enum):
    """Standard severity levels."""
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"


def parse_duration_seconds(duration_str: Union[str, int, float]) -> float:
    """Parses duration strings like '30s', '5m', '1h', '500ms' into float seconds."""
    if isinstance(duration_str, (int, float)):
        return float(duration_str)

    s = str(duration_str).strip().lower()
    if not s:
        return 0.0

    if s.endswith("ms"):
        return float(s[:-2]) / 1000.0
    elif s.endswith("s"):
        return float(s[:-1])
    elif s.endswith("m"):
        return float(s[:-1]) * 60.0
    elif s.endswith("h"):
        return float(s[:-1]) * 3600.0
    elif s.endswith("d"):
        return float(s[:-1]) * 86400.0

    try:
        return float(s)
    except ValueError as err:
        raise ValueError(f"Invalid duration format: '{duration_str}'") from err


class AlertRuleModel(BaseModel):
    """Pydantic v2 validation model for a single alert rule."""
    alert: str = Field(..., description="Alert rule identifier name", min_length=1)
    expr: str = Field(..., description="Expression, e.g. 'node_cpu_usage_percent > 85'")
    for_duration: Union[str, int, float] = Field(
        default="0s",
        alias="for",
        description="Duration the condition must hold before firing (debounce)",
    )
    severity: str = Field(default="warning")
    labels: Dict[str, str] = Field(default_factory=dict)
    annotations: Dict[str, str] = Field(default_factory=dict)

    model_config = {
        "populate_by_name": True,
        "extra": "ignore",
    }

    @field_validator("expr")
    @classmethod
    def validate_expr_syntax(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("Alert expression cannot be empty")
        # Check that it contains a valid operator
        operators = [">=", "<=", "!=", "==", ">", "<"]
        if not any(op in v for op in operators):
            raise ValueError(f"Expression '{v}' must contain one of {operators}")
        return v


class AlertGroupModel(BaseModel):
    """Pydantic v2 validation model for a group of alert rules."""
    name: str = Field(..., min_length=1)
    rules: List[AlertRuleModel] = Field(default_factory=list)


class AlertConfigModel(BaseModel):
    """Pydantic v2 validation model for the full alert configuration."""
    groups: List[AlertGroupModel] = Field(default_factory=list)


class AlertInstance:
    """Represents the runtime state and history of an evaluated alert rule."""

    def __init__(self, rule: AlertRuleModel, group_name: str = "default") -> None:
        self.rule = rule
        self.group_name = group_name
        self.state: AlertState = AlertState.INACTIVE
        self.active_since: Optional[float] = None
        self.firing_since: Optional[float] = None
        self.resolved_at: Optional[float] = None
        self.last_evaluated: float = 0.0
        self.current_value: Optional[float] = None
        self.threshold: float = 0.0
        self.operator: str = ">"
        self.metric_name: str = ""

        # Parse rule expression components
        self._parse_expression()

    def _parse_expression(self) -> None:
        expr = self.rule.expr.strip()
        operators = [">=", "<=", "!=", "==", ">", "<"]
        matched_op = None
        for op in operators:
            if op in expr:
                matched_op = op
                break

        if not matched_op:
            raise ValueError(f"No valid comparison operator found in expression: '{expr}'")

        parts = expr.split(matched_op, 1)
        self.metric_name = parts[0].strip()
        self.operator = matched_op
        self.threshold = float(parts[1].strip())

    @property
    def for_seconds(self) -> float:
        return parse_duration_seconds(self.rule.for_duration)

    def evaluate_condition(self, value: Optional[float]) -> bool:
        """Evaluates whether the metric value breaches the rule threshold."""
        if value is None:
            return False

        op = self.operator
        thresh = self.threshold

        if op == ">":
            return value > thresh
        elif op == "<":
            return value < thresh
        elif op == ">=":
            return value >= thresh
        elif op == "<=":
            return value <= thresh
        elif op == "==":
            return abs(value - thresh) < 1e-7
        elif op == "!=":
            return abs(value - thresh) >= 1e-7
        return False

    def update_state(self, is_breaching: bool, value: Optional[float], current_time: float) -> AlertState:
        """Applies state machine transition based on condition truth and duration."""
        self.last_evaluated = current_time
        self.current_value = value

        if is_breaching:
            if self.state == AlertState.INACTIVE or self.state == AlertState.RESOLVED:
                self.state = AlertState.PENDING
                self.active_since = current_time
                self.resolved_at = None

            if self.state == AlertState.PENDING:
                elapsed = current_time - (self.active_since or current_time)
                if elapsed >= self.for_seconds:
                    self.state = AlertState.FIRING
                    self.firing_since = current_time

            # If already FIRING, remains FIRING
        else:
            # Condition is false
            if self.state == AlertState.FIRING:
                self.state = AlertState.RESOLVED
                self.resolved_at = current_time
            elif self.state == AlertState.PENDING:
                self.state = AlertState.INACTIVE
                self.active_since = None
            elif self.state == AlertState.RESOLVED:
                # After one cycle in RESOLVED state, revert to INACTIVE
                self.state = AlertState.INACTIVE
                self.active_since = None
                self.firing_since = None

        return self.state

    def render_annotations(self) -> Dict[str, str]:
        """Interpolates dynamic template variables like {{ $value }} and {{ $labels.* }}."""
        val_str = f"{self.current_value:.4g}" if self.current_value is not None else "unknown"
        rendered: Dict[str, str] = {}

        for k, v in self.rule.annotations.items():
            text = v.replace("{{ $value }}", val_str).replace("{{$value}}", val_str)
            for lk, lv in self.rule.labels.items():
                text = text.replace(f"{{{{ $labels.{lk} }}}}", lv)
                text = text.replace(f"{{{{$labels.{lk}}}}}", lv)
            rendered[k] = text

        return rendered

    def to_dict(self) -> Dict[str, Any]:
        """Returns dictionary representation of current alert instance."""
        return {
            "alert": self.rule.alert,
            "group": self.group_name,
            "state": self.state.value,
            "severity": self.rule.severity,
            "expr": self.rule.expr,
            "metric_name": self.metric_name,
            "threshold": self.threshold,
            "operator": self.operator,
            "current_value": self.current_value,
            "for_seconds": self.for_seconds,
            "active_since": self.active_since,
            "firing_since": self.firing_since,
            "resolved_at": self.resolved_at,
            "labels": self.rule.labels,
            "annotations": self.render_annotations(),
        }


class AlertEvaluator:
    """Loads alert rules from YAML, validates schemas, and evaluates metrics with debounce."""

    def __init__(self, config_path_or_content: Optional[Union[str, Path, Dict[str, Any]]] = None) -> None:
        self.alert_instances: List[AlertInstance] = []
        if config_path_or_content is not None:
            self.load_config(config_path_or_content)

    def load_config(self, config_input: Union[str, Path, Dict[str, Any]]) -> None:
        """Safely loads YAML alert configuration with CWE-400 and CWE-502 guardrails."""
        raw_dict: Dict[str, Any]

        if isinstance(config_input, dict):
            raw_dict = config_input
        elif isinstance(config_input, (str, Path)):
            path = Path(config_input)
            if path.exists() and path.is_file():
                # Guardrail: Check file size to avoid DoS (CWE-400)
                file_size = path.stat().st_size
                if file_size > MAX_CONFIG_FILE_SIZE_BYTES:
                    raise ValueError(
                        f"Alert configuration file exceeds 1 MB limit ({file_size} bytes). Rejected for safety."
                    )
                content = path.read_text(encoding="utf-8")
                # Guardrail: safe_load only (CWE-502)
                loaded = yaml.safe_load(content)
                raw_dict = loaded if isinstance(loaded, dict) else {}
            else:
                # Treat as raw YAML string
                if len(str(config_input)) > MAX_CONFIG_FILE_SIZE_BYTES:
                    raise ValueError("Alert configuration string exceeds 1 MB limit.")
                loaded = yaml.safe_load(str(config_input))
                raw_dict = loaded if isinstance(loaded, dict) else {}
        else:
            raise TypeError(f"Unsupported config type: {type(config_input)}")

        parsed_config = AlertConfigModel.model_validate(raw_dict)
        self.alert_instances = []

        for group in parsed_config.groups:
            for rule in group.rules:
                instance = AlertInstance(rule=rule, group_name=group.name)
                self.alert_instances.append(instance)

    def add_rule(self, rule: AlertRuleModel, group_name: str = "default") -> None:
        """Directly adds a validated alert rule."""
        self.alert_instances.append(AlertInstance(rule=rule, group_name=group_name))

    def evaluate(
        self,
        metrics: Union[Dict[str, float], List[MetricFamily]],
        current_time: Optional[float] = None,
    ) -> List[AlertInstance]:
        """Evaluates all rules against current metric values.

        Returns list of all alert instances with updated states.
        """
        now = current_time if current_time is not None else time.time()

        # Convert MetricFamily list to dict if needed
        metrics_dict: Dict[str, float] = {}
        if isinstance(metrics, list):
            for fam in metrics:
                for s in fam.samples:
                    metrics_dict[s.name] = s.value
                    if s.labels:
                        lbl_str = ",".join(f'{k}="{v}"' for k, v in sorted(s.labels.items()))
                        metrics_dict[f"{s.name}{{{lbl_str}}}"] = s.value
        else:
            metrics_dict = metrics

        for instance in self.alert_instances:
            # Match metric by exact name or base name
            val: Optional[float] = None
            if instance.metric_name in metrics_dict:
                val = metrics_dict[instance.metric_name]
            else:
                # Look for matching base name in metrics
                for k, v in metrics_dict.items():
                    if k.startswith(instance.metric_name):
                        val = v
                        break

            breaching = instance.evaluate_condition(val)
            instance.update_state(is_breaching=breaching, value=val, current_time=now)

        return self.alert_instances

    def get_firing_alerts(self) -> List[AlertInstance]:
        """Returns currently firing alerts."""
        return [inst for inst in self.alert_instances if inst.state == AlertState.FIRING]

    def get_pending_alerts(self) -> List[AlertInstance]:
        """Returns currently pending alerts."""
        return [inst for inst in self.alert_instances if inst.state == AlertState.PENDING]

    def get_resolved_alerts(self) -> List[AlertInstance]:
        """Returns alerts that transitioned to resolved in the last cycle."""
        return [inst for inst in self.alert_instances if inst.state == AlertState.RESOLVED]
