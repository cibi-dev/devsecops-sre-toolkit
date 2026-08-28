"""slo-burnrate-engine

Enterprise-grade quantitative SRE engine implementing Google SRE
Multi-Window Multi-Burn-Rate alerting, rolling error budgets, and
time-to-exhaustion forecasting.
"""

from __future__ import annotations

from slo.burn_rate import (
    BurnRateCalculator,
    BurnRateResult,
    calculate_burn_rate,
    calculate_time_to_exhaustion,
    parse_window_seconds,
)
from slo.error_budget import (
    ErrorBudgetManager,
    ErrorBudgetResult,
    SLODefinition,
)
from slo.multi_window import (
    AlertConditionEvaluation,
    AlertSeverity,
    AlertTier,
    MultiWindowAlertEngine,
    MultiWindowAlertResult,
    get_standard_google_sre_tiers,
)
from slo.reporter import (
    SLOReporter,
    generate_json_report,
    generate_markdown_report,
    generate_openmetrics_metrics,
    redact_data_structures,
    redact_sensitive_text,
)
from slo.sli_calculator import (
    SLICalculator,
    SLIDataPoint,
    SLIResult,
    calculate_event_sli,
    calculate_timeseries_sli,
    calculate_windowed_sli,
)

__version__ = "0.1.0"

__all__ = [
    "__version__",
    # SLI
    "SLIDataPoint",
    "SLIResult",
    "calculate_event_sli",
    "calculate_timeseries_sli",
    "calculate_windowed_sli",
    "SLICalculator",
    # Error Budget
    "SLODefinition",
    "ErrorBudgetResult",
    "ErrorBudgetManager",
    # Burn Rate
    "BurnRateResult",
    "BurnRateCalculator",
    "calculate_burn_rate",
    "calculate_time_to_exhaustion",
    "parse_window_seconds",
    # Multi-Window Alerting
    "AlertSeverity",
    "AlertTier",
    "AlertConditionEvaluation",
    "MultiWindowAlertResult",
    "MultiWindowAlertEngine",
    "get_standard_google_sre_tiers",
    # Reporter
    "SLOReporter",
    "generate_markdown_report",
    "generate_openmetrics_metrics",
    "generate_json_report",
    "redact_sensitive_text",
    "redact_data_structures",
]
