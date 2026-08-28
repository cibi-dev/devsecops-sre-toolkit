"""Burn Rate quantitative calculation and Time-to-Exhaustion (TTE) forecasting.

Implements Google SRE Workbook formulations for instantaneous and windowed
budget consumption rates and exact remaining time projections.
"""

from __future__ import annotations

import re
from typing import Any, Sequence
from pydantic import BaseModel, ConfigDict, Field, field_validator


def parse_window_seconds(window: str | int | float) -> float:
    """Parse time window descriptor string (e.g. '5m', '1h', '6h', '24h', '30d') into seconds."""
    if isinstance(window, (int, float)):
        if window <= 0:
            raise ValueError(f"Window duration must be positive, got {window}")
        return float(window)

    cleaned = str(window).strip().lower()
    match = re.fullmatch(r"^(\d+(?:\.\d+)?)\s*([smhdw])$", cleaned)
    if not match:
        raise ValueError(
            f"Invalid window format: '{window}'. Expected format like '5m', '1h', '6h', '24h', '30d'."
        )

    val = float(match.group(1))
    unit = match.group(2)
    multipliers = {
        "s": 1.0,
        "m": 60.0,
        "h": 3600.0,
        "d": 86400.0,
        "w": 604800.0,
    }
    return val * multipliers[unit]


class BurnRateResult(BaseModel):
    """Quantitative Burn Rate result and projection metrics."""
    model_config = ConfigDict(extra="forbid")

    burn_rate: float = Field(ge=0.0, description="Normalized burn rate multiplier (1.0 = standard 30d consumption)")
    observed_error_rate: float = Field(ge=0.0, le=1.0)
    allowed_error_rate: float = Field(gt=0.0, lt=1.0)
    window_seconds: float = Field(gt=0.0)
    window_label: str
    budget_consumed_in_window_percent: float = Field(ge=0.0)
    time_to_exhaustion_seconds: float | None = None
    time_to_exhaustion_hours: float | None = None
    time_to_exhaustion_days: float | None = None
    remaining_budget_ratio_used: float = Field(ge=0.0, le=1.0)
    period_days: int = Field(gt=0)
    metadata: dict[str, Any] = Field(default_factory=dict)


def calculate_time_to_exhaustion(
    burn_rate: float,
    remaining_budget_ratio: float = 1.0,
    period_days: int = 30,
) -> tuple[float | None, float | None, float | None]:
    """Calculate Time-to-Exhaustion (TTE) in seconds, hours, and days.

    Formula:
        TTE = (Remaining Budget Ratio * Period Seconds) / Burn Rate

    Args:
        burn_rate: Current burn rate multiplier.
        remaining_budget_ratio: Fraction of budget remaining [0.0, 1.0].
        period_days: Rolling SLO period in days (standard: 30).

    Returns:
        Tuple of (tte_seconds, tte_hours, tte_days), or (None, None, None) if burn_rate <= 0.
    """
    if remaining_budget_ratio <= 0.0:
        return 0.0, 0.0, 0.0

    if burn_rate <= 0.0:
        return None, None, None

    period_seconds = float(period_days * 86400.0)
    tte_seconds = float((remaining_budget_ratio * period_seconds) / burn_rate)
    tte_hours = float(tte_seconds / 3600.0)
    tte_days = float(tte_seconds / 86400.0)

    return (
        round(tte_seconds, 2),
        round(tte_hours, 4),
        round(tte_days, 4),
    )


def calculate_burn_rate(
    good_events: int,
    total_events: int,
    target_slo: float,
    window: str | int | float = "1h",
    period_days: int = 30,
    remaining_budget_ratio: float = 1.0,
    metadata: dict[str, Any] | None = None,
) -> BurnRateResult:
    """Calculate instantaneous/windowed Burn Rate and projected Time-to-Exhaustion.

    Mathematical formulation:
        Allowed Error Rate = 1.0 - Target SLO
        Observed Error Rate = Bad Events / Total Events
        Burn Rate = Observed Error Rate / Allowed Error Rate
        Budget Consumed in Window % = Burn Rate * (Window Duration / Period Duration) * 100

    Args:
        good_events: Good event count in window.
        total_events: Total event count in window.
        target_slo: SLO target (e.g. 0.999 for 99.9%).
        window: Window specification string (e.g. '1h', '5m', 3600).
        period_days: SLO compliance window (default 30 days).
        remaining_budget_ratio: Current remaining budget ratio (default 1.0).
        metadata: Optional metadata.

    Returns:
        BurnRateResult with complete metrics.
    """
    if target_slo <= 0.0 or target_slo >= 1.0:
        raise ValueError(f"target_slo must be strictly between 0.0 and 1.0, got {target_slo}")

    if good_events < 0 or total_events < 0:
        raise ValueError("Event counts must be non-negative")

    if good_events > total_events:
        raise ValueError(f"good_events ({good_events}) cannot exceed total_events ({total_events})")

    window_sec = parse_window_seconds(window)
    window_label = str(window) if isinstance(window, str) else f"{window_sec:.0f}s"
    period_seconds = float(period_days * 86400.0)
    allowed_error_rate = float(1.0 - target_slo)

    if total_events == 0:
        observed_error_rate = 0.0
        burn_rate = 0.0
    else:
        bad_events = total_events - good_events
        observed_error_rate = float(bad_events / total_events)
        burn_rate = float(observed_error_rate / allowed_error_rate)

    # Budget consumed in this specific window duration
    # E.g. at 14.4x over 1 hour in 30 days (720h): 14.4 * (1/720) * 100 = 2.0%
    budget_consumed_in_win_pct = float(
        burn_rate * (window_sec / period_seconds) * 100.0
    )

    clamped_remaining = max(0.0, min(1.0, remaining_budget_ratio))
    tte_sec, tte_hrs, tte_days = calculate_time_to_exhaustion(
        burn_rate=burn_rate,
        remaining_budget_ratio=clamped_remaining,
        period_days=period_days,
    )

    return BurnRateResult(
        burn_rate=round(burn_rate, 4),
        observed_error_rate=round(observed_error_rate, 8),
        allowed_error_rate=round(allowed_error_rate, 8),
        window_seconds=window_sec,
        window_label=window_label,
        budget_consumed_in_window_percent=round(budget_consumed_in_win_pct, 4),
        time_to_exhaustion_seconds=tte_sec,
        time_to_exhaustion_hours=tte_hrs,
        time_to_exhaustion_days=tte_days,
        remaining_budget_ratio_used=round(clamped_remaining, 6),
        period_days=period_days,
        metadata=metadata or {},
    )


class BurnRateCalculator:
    """Quantitative Burn Rate Calculator instance."""

    def __init__(self, target_slo: float = 0.999, period_days: int = 30) -> None:
        if target_slo <= 0.0 or target_slo >= 1.0:
            raise ValueError(f"target_slo must be strictly between 0.0 and 1.0, got {target_slo}")
        self.target_slo = target_slo
        self.period_days = period_days

    @property
    def allowed_error_rate(self) -> float:
        return float(1.0 - self.target_slo)

    def calculate(
        self,
        good_events: int,
        total_events: int,
        window: str | int | float = "1h",
        remaining_budget_ratio: float = 1.0,
    ) -> BurnRateResult:
        """Calculate burn rate for given events in a window."""
        return calculate_burn_rate(
            good_events=good_events,
            total_events=total_events,
            target_slo=self.target_slo,
            window=window,
            period_days=self.period_days,
            remaining_budget_ratio=remaining_budget_ratio,
        )

    def calculate_from_error_rate(
        self,
        error_rate: float,
        window: str | int | float = "1h",
        remaining_budget_ratio: float = 1.0,
    ) -> BurnRateResult:
        """Calculate burn rate from an observed error rate directly."""
        if error_rate < 0.0 or error_rate > 1.0:
            raise ValueError(f"error_rate must be between 0.0 and 1.0, got {error_rate}")

        total_sim = 1_000_000
        bad_sim = int(round(error_rate * total_sim))
        good_sim = total_sim - bad_sim

        return calculate_burn_rate(
            good_events=good_sim,
            total_events=total_sim,
            target_slo=self.target_slo,
            window=window,
            period_days=self.period_days,
            remaining_budget_ratio=remaining_budget_ratio,
        )

    def calculate_weighted_burn_rate(
        self,
        results: Sequence[BurnRateResult],
        weights: Sequence[float] | None = None,
    ) -> float:
        """Calculate weighted average burn rate across multiple windows."""
        if not results:
            return 0.0

        if weights is None:
            # Default weights proportional to window duration
            w = [r.window_seconds for r in results]
        else:
            if len(weights) != len(results):
                raise ValueError("Length of weights must match length of results")
            w = list(weights)

        total_w = sum(w)
        if total_w <= 0:
            raise ValueError("Sum of weights must be positive")

        weighted_br = sum(r.burn_rate * weight for r, weight in zip(results, w)) / total_w
        return round(float(weighted_br), 4)
