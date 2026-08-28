"""Reporting and metrics export module for SLO and Burn Rate results.

Provides Executive Markdown reports, OpenMetrics/Prometheus format exports,
and structured JSON payloads with strict CWE-209 attribute sanitization.
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from typing import Any
from pydantic import BaseModel

from slo.burn_rate import BurnRateResult
from slo.error_budget import ErrorBudgetResult
from slo.multi_window import MultiWindowAlertResult


# Specific patterns for sensitive credentials masking (CWE-209)
SENSITIVE_PATTERNS = [
    (re.compile(r"ghp_[a-zA-Z0-9]{36}"), "[REDACTED_GH_TOKEN]"),
    (re.compile(r"AKIA[0-9A-Z]{16}"), "[REDACTED_AWS_KEY]"),
    (re.compile(r"(?i)bearer\s+[a-zA-Z0-9_\-\.]{20,}"), "Bearer [REDACTED]"),
    (re.compile(r"(?i)([a-z0-9_-]*(?:api[_-]?key|secret[_-]?key|secret|token|password|auth|credential|bearer)[a-z0-9_-]*)\s*[:=]\s*['\"]?(?!\[REDACTED)([^'\"\s,;]+)['\"]?"), r"\1=[REDACTED]"),
]


def redact_sensitive_text(text: str) -> str:
    """Sanitize and mask sensitive tokens, credentials, or keys in strings (CWE-209)."""
    if not isinstance(text, str):
        return text

    sanitized = text
    for pattern, replacement in SENSITIVE_PATTERNS:
        sanitized = pattern.sub(replacement, sanitized)
    return sanitized


def redact_data_structures(obj: Any) -> Any:
    """Recursively mask sensitive values in dictionaries and lists."""
    if isinstance(obj, dict):
        cleaned: dict[str, Any] = {}
        for k, v in obj.items():
            k_lower = str(k).lower()
            if any(s in k_lower for s in ("token", "secret", "password", "key", "auth", "credential")):
                cleaned[k] = "[REDACTED]"
            else:
                cleaned[k] = redact_data_structures(v)
        return cleaned
    elif isinstance(obj, (list, tuple)):
        return [redact_data_structures(item) for item in obj]
    elif isinstance(obj, str):
        return redact_sensitive_text(obj)
    return obj


class SLOReporter:
    """Enterprise Report Generator for SLO, Error Budget, and Alert Evaluations."""

    def __init__(
        self,
        error_budget: ErrorBudgetResult,
        burn_rates: list[BurnRateResult] | None = None,
        alerts: MultiWindowAlertResult | None = None,
    ) -> None:
        self.error_budget = error_budget
        self.burn_rates = burn_rates or []
        self.alerts = alerts

    def to_markdown(self) -> str:
        """Generate executive Markdown summary report."""
        eb = self.error_budget
        service_name = redact_sensitive_text(eb.service)
        slo_name = redact_sensitive_text(eb.slo_name)

        if eb.is_exhausted:
            status_badge = "🔴 **EXHAUSTED (0.0% Remaining)**"
            rec_action = "🚨 **CRITICAL**: Error budget exhausted. Freeze non-critical production deployments; initiate reliability sprint."
        elif eb.remaining_budget_percent < 20.0:
            status_badge = f"🟡 **AT RISK ({eb.remaining_budget_percent:.2f}% Remaining)**"
            rec_action = "⚠️ **WARNING**: Budget below 20%. Prioritize stability improvements and review recent releases."
        else:
            status_badge = f"🟢 **HEALTHY ({eb.remaining_budget_percent:.2f}% Remaining)**"
            rec_action = "✅ **NORMAL**: Service operating well within reliability target. Deployments normal."

        lines = [
            f"# 📊 SRE Reliability & SLO Report: `{service_name}`",
            "",
            f"- **SLO Identifier:** `{slo_name}`",
            f"- **Target Reliability:** `{eb.slo_target_percent:.4f}%` (Allowed Error Rate: `{eb.allowed_error_rate * 100:.4f}%`)",
            f"- **Rolling Compliance Period:** `{eb.period_days} Days`",
            f"- **Budget Status:** {status_badge}",
            f"- **Generated At:** `{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}`",
            "",
            "## 📈 Quantitative Error Budget Health",
            "",
            "| Metric | Value | Reference / Formula |",
            "|---|---|---|",
            f"| **Observed Total Events** | `{eb.total_events:,}` | Total requests/events evaluated |",
            f"| **Compliant (Good) Events** | `{eb.good_events:,}` | Successful events meeting SLI criteria |",
            f"| **Non-Compliant (Bad) Events** | `{eb.bad_events:,}` | Events failing SLI criteria |",
            f"| **Current SLI Compliance** | `{((eb.good_events / eb.total_events) * 100 if eb.total_events > 0 else 100.0):.4f}%` | $(Good / Total) \\times 100$ |",
            f"| **Allowed Error Budget Events** | `{eb.total_budget_events:,.1f}` | $Total \\times (1 - Target)$ |",
            f"| **Consumed Budget %** | `{eb.consumed_budget_percent:.2f}%` | $(Bad / Budget_{{Total}}) \\times 100$ |",
            f"| **Remaining Budget %** | `{eb.remaining_budget_percent:.2f}%` | $100\\% - Consumed\\%$ |",
            "",
        ]

        if self.burn_rates:
            lines.extend([
                "## ⏱️ Burn Rate & Time-to-Exhaustion Projections",
                "",
                "| Window | Burn Rate | % Consumed in Window | Time-to-Exhaustion | Status |",
                "|---|---|---|---|---|",
            ])
            for br in self.burn_rates:
                tte_str = (
                    f"`{br.time_to_exhaustion_hours:.1f} hrs` (`{br.time_to_exhaustion_days:.2f} days`)"
                    if br.time_to_exhaustion_hours is not None
                    else "`Infinite (0 errors)`"
                )
                br_status = "🔴 Critical" if br.burn_rate >= 14.4 else ("🟡 High" if br.burn_rate >= 3.0 else "🟢 Normal")
                lines.append(
                    f"| `{br.window_label}` | `{br.burn_rate:.2f}x` | `{br.budget_consumed_in_window_percent:.3f}%` | {tte_str} | {br_status} |"
                )
            lines.append("")

        if self.alerts:
            lines.extend([
                "## 🚨 Google SRE Multi-Window Multi-Burn-Rate Alerts",
                "",
                f"**Overall Status:** `{self.alerts.summary_message}`",
                "",
                "| Tier / Policy | Long Window | Short Window | Threshold | Firing? | Severity | Target Channel |",
                "|---|---|---|---|:---:|---|---|",
            ])
            for eval_item in self.alerts.evaluations:
                fire_badge = "🔥 **FIRING**" if eval_item.is_firing else "✅ OK"
                long_hrs = f"{eval_item.long_window_seconds / 3600:.1f}h ({eval_item.long_window_burn_rate:.2f}x)"
                short_mins = f"{eval_item.short_window_seconds / 60:.0f}m ({eval_item.short_window_burn_rate:.2f}x)"
                lines.append(
                    f"| `{eval_item.tier_name}` | `{long_hrs}` | `{short_mins}` | `{eval_item.burn_rate_threshold:.1f}x` | {fire_badge} | `{eval_item.severity.value.upper()}` | `{eval_item.channel}` |"
                )
            lines.append("")

        lines.extend([
            "## 🎯 Google SRE Recommendation",
            "",
            rec_action,
            "",
            "---",
            "*Report automatically generated by `slo-burnrate-engine` conforming to Google SRE Workbook Chapter 5 specifications.*",
        ])

        return "\n".join(lines)

    def to_openmetrics(self) -> str:
        """Generate OpenMetrics / Prometheus exposition text format."""
        eb = self.error_budget
        service = redact_sensitive_text(eb.service).replace('"', '\\"')
        slo = redact_sensitive_text(eb.slo_name).replace('"', '\\"')

        observed_sli = (
            float(eb.good_events / eb.total_events) if eb.total_events > 0 else 1.0
        )

        lines = [
            "# HELP slo_target_ratio Target reliability objective ratio (0.0 to 1.0)",
            "# TYPE slo_target_ratio gauge",
            f'slo_target_ratio{{service="{service}",slo="{slo}"}} {eb.slo_target:.6f}',
            "",
            "# HELP sli_current_ratio Current observed Service Level Indicator ratio (0.0 to 1.0)",
            "# TYPE sli_current_ratio gauge",
            f'sli_current_ratio{{service="{service}",slo="{slo}"}} {observed_sli:.6f}',
            "",
            "# HELP slo_error_budget_total_events Maximum allowed bad events for the SLO window",
            "# TYPE slo_error_budget_total_events gauge",
            f'slo_error_budget_total_events{{service="{service}",slo="{slo}"}} {eb.total_budget_events:.2f}',
            "",
            "# HELP slo_error_budget_consumed_events Number of bad events observed",
            "# TYPE slo_error_budget_consumed_events counter",
            f'slo_error_budget_consumed_events{{service="{service}",slo="{slo}"}} {eb.consumed_budget_events}',
            "",
            "# HELP slo_error_budget_consumed_percent Percentage of error budget consumed (0 to 100+)",
            "# TYPE slo_error_budget_consumed_percent gauge",
            f'slo_error_budget_consumed_percent{{service="{service}",slo="{slo}"}} {eb.consumed_budget_percent:.4f}',
            "",
            "# HELP slo_error_budget_remaining_ratio Fraction of error budget remaining",
            "# TYPE slo_error_budget_remaining_ratio gauge",
            f'slo_error_budget_remaining_ratio{{service="{service}",slo="{slo}"}} {eb.remaining_budget_ratio:.6f}',
            "",
            "# HELP slo_error_budget_is_exhausted Boolean indicator if error budget is <= 0 (1=exhausted, 0=available)",
            "# TYPE slo_error_budget_is_exhausted gauge",
            f'slo_error_budget_is_exhausted{{service="{service}",slo="{slo}"}} {1 if eb.is_exhausted else 0}',
        ]

        if self.burn_rates:
            lines.extend([
                "",
                "# HELP slo_burn_rate Current burn rate multiplier for specified window",
                "# TYPE slo_burn_rate gauge",
            ])
            for br in self.burn_rates:
                win_label = br.window_label.replace('"', '\\"')
                lines.append(
                    f'slo_burn_rate{{service="{service}",slo="{slo}",window="{win_label}"}} {br.burn_rate:.4f}'
                )

            primary_br = self.burn_rates[0]
            if primary_br.time_to_exhaustion_seconds is not None:
                lines.extend([
                    "",
                    "# HELP slo_time_to_exhaustion_seconds Estimated seconds until error budget reaches 0",
                    "# TYPE slo_time_to_exhaustion_seconds gauge",
                    f'slo_time_to_exhaustion_seconds{{service="{service}",slo="{slo}"}} {primary_br.time_to_exhaustion_seconds:.2f}',
                ])

        if self.alerts:
            lines.extend([
                "",
                "# HELP slo_alert_firing Boolean gauge indicating active Multi-Window Multi-Burn-Rate alerts (1=firing, 0=ok)",
                "# TYPE slo_alert_firing gauge",
            ])
            for eval_item in self.alerts.evaluations:
                tier_label = eval_item.tier_name.replace('"', '\\"')
                sev_label = eval_item.severity.value.replace('"', '\\"')
                val = 1 if eval_item.is_firing else 0
                lines.append(
                    f'slo_alert_firing{{service="{service}",slo="{slo}",tier="{tier_label}",severity="{sev_label}"}} {val}'
                )

        lines.append("# EOF\n")
        return "\n".join(lines)

    def to_json(self, indent: int = 2) -> str:
        """Generate structured JSON report payload with sanitized attributes."""
        payload: dict[str, Any] = {
            "error_budget": self.error_budget.model_dump(),
            "burn_rates": [br.model_dump() for br in self.burn_rates],
            "alerts": self.alerts.model_dump() if self.alerts else None,
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }
        sanitized = redact_data_structures(payload)
        return json.dumps(sanitized, indent=indent, default=str)


def generate_markdown_report(
    error_budget: ErrorBudgetResult,
    burn_rates: list[BurnRateResult] | None = None,
    alerts: MultiWindowAlertResult | None = None,
) -> str:
    """Helper function to generate Markdown report."""
    return SLOReporter(error_budget, burn_rates, alerts).to_markdown()


def generate_openmetrics_metrics(
    error_budget: ErrorBudgetResult,
    burn_rates: list[BurnRateResult] | None = None,
    alerts: MultiWindowAlertResult | None = None,
) -> str:
    """Helper function to generate OpenMetrics text."""
    return SLOReporter(error_budget, burn_rates, alerts).to_openmetrics()


def generate_json_report(
    error_budget: ErrorBudgetResult,
    burn_rates: list[BurnRateResult] | None = None,
    alerts: MultiWindowAlertResult | None = None,
) -> str:
    """Helper function to generate sanitized JSON report."""
    return SLOReporter(error_budget, burn_rates, alerts).to_json()
