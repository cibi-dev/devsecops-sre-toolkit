"""Error Budget computation and management module.

Calculates total, consumed, and remaining error budgets over rolling periods
(e.g., standard 30-day compliance windows) with mathematical precision.
"""

from __future__ import annotations

from typing import Any
import numpy as np
import pandas as pd
from pydantic import BaseModel, ConfigDict, Field, field_validator

from slo.sli_calculator import SLIResult, calculate_event_sli, calculate_timeseries_sli


class SLODefinition(BaseModel):
    """Formal Service Level Objective (SLO) definition specification."""
    model_config = ConfigDict(extra="forbid", strict=True)

    name: str = Field(min_length=1, max_length=128, description="SLO identifier or name")
    service: str = Field(min_length=1, max_length=128, description="Target service name")
    target: float = Field(
        gt=0.0,
        lt=1.0,
        description="Target reliability ratio, e.g., 0.999 for 99.9% availability",
    )
    window_days: int = Field(
        default=30,
        gt=0,
        le=365,
        description="Rolling compliance period in calendar days (standard: 30)",
    )
    description: str = Field(default="", max_length=512)
    tags: dict[str, str] = Field(default_factory=dict)

    @field_validator("target")
    @classmethod
    def validate_target_slo(cls, v: float) -> float:
        if v <= 0.0 or v >= 1.0:
            raise ValueError(f"SLO target must be strictly between 0.0 and 1.0, got {v}")
        return float(v)


class ErrorBudgetResult(BaseModel):
    """Calculated Error Budget status and health indicators."""
    model_config = ConfigDict(extra="forbid")

    slo_name: str
    service: str
    slo_target: float
    slo_target_percent: float
    allowed_error_rate: float
    total_events: int
    good_events: int
    bad_events: int
    total_budget_events: float
    consumed_budget_events: int
    consumed_budget_percent: float
    remaining_budget_percent: float
    remaining_budget_ratio: float
    is_exhausted: bool
    period_days: int
    metadata: dict[str, Any] = Field(default_factory=dict)


class ErrorBudgetManager:
    """Quantitative Error Budget Manager for a specific SLO."""

    def __init__(self, slo: SLODefinition) -> None:
        self.slo = slo

    @property
    def allowed_error_rate(self) -> float:
        """Allowed error rate: (1.0 - target) with floating-point precision stabilization."""
        return float(round(1.0 - self.slo.target, 10))

    def calculate_from_events(
        self,
        good_events: int,
        total_events: int,
        metadata: dict[str, Any] | None = None,
    ) -> ErrorBudgetResult:
        """Calculate error budget consumption from raw event counts."""
        sli_res = calculate_event_sli(good_events, total_events)
        return self.calculate_from_sli(sli_res, metadata=metadata)

    def calculate_from_sli(
        self,
        sli_result: SLIResult,
        metadata: dict[str, Any] | None = None,
    ) -> ErrorBudgetResult:
        """Calculate error budget metrics from an SLIResult."""
        total = sli_result.total_events
        good = sli_result.good_events
        bad = sli_result.bad_events
        allowed_rate = self.allowed_error_rate

        total_budget_events = float(total * allowed_rate)

        if total == 0 or total_budget_events <= 0.0:
            consumed_percent = 0.0 if bad == 0 else 100.0
            remaining_percent = 100.0 if bad == 0 else 0.0
            remaining_ratio = 1.0 if bad == 0 else 0.0
            is_exhausted = False if bad == 0 else True
        else:
            consumed_percent = float((bad / total_budget_events) * 100.0)
            remaining_percent = float(100.0 - consumed_percent)
            remaining_ratio = float(1.0 - (consumed_percent / 100.0))
            is_exhausted = bool(round(remaining_percent, 4) <= 0.0 or bad >= total_budget_events - 1e-9)

        merged_meta = dict(sli_result.metadata)
        if metadata:
            merged_meta.update(metadata)

        return ErrorBudgetResult(
            slo_name=self.slo.name,
            service=self.slo.service,
            slo_target=self.slo.target,
            slo_target_percent=round(self.slo.target * 100.0, 4),
            allowed_error_rate=round(allowed_rate, 8),
            total_events=total,
            good_events=good,
            bad_events=bad,
            total_budget_events=round(total_budget_events, 4),
            consumed_budget_events=bad,
            consumed_budget_percent=round(consumed_percent, 4),
            remaining_budget_percent=round(remaining_percent, 4),
            remaining_budget_ratio=round(remaining_ratio, 6),
            is_exhausted=is_exhausted,
            period_days=self.slo.window_days,
            metadata=merged_meta,
        )

    def calculate_rolling_budget(
        self,
        df: pd.DataFrame,
        timestamp_col: str = "timestamp",
        good_col: str = "good_events",
        total_col: str = "total_events",
        bad_col: str | None = None,
        rolling_days: int | None = None,
        max_memory_mb: float = 512.0,
    ) -> ErrorBudgetResult:
        """Calculate rolling error budget from time-series DataFrame for the last N days."""
        days = rolling_days if rolling_days is not None else self.slo.window_days

        if df.empty:
            return self.calculate_from_events(0, 0)

        data = df.copy()
        if timestamp_col in data.columns:
            data[timestamp_col] = pd.to_datetime(data[timestamp_col])
            max_time = data[timestamp_col].max()
            min_time = max_time - pd.Timedelta(days, unit="D")
            data = data[data[timestamp_col] >= min_time]

        sli_res = calculate_timeseries_sli(
            data=data,
            timestamp_col=timestamp_col,
            good_col=good_col,
            total_col=total_col,
            bad_col=bad_col,
            max_memory_mb=max_memory_mb,
            window=f"{days}d",
        )
        return self.calculate_from_sli(sli_res, metadata={"rolling_days": days})

    def get_rolling_trend(
        self,
        df: pd.DataFrame,
        timestamp_col: str = "timestamp",
        good_col: str = "good_events",
        total_col: str = "total_events",
        window: str = "30D",
        step: str = "1D",
    ) -> pd.DataFrame:
        """Calculate a rolling daily trend of Error Budget consumption over time."""
        if df.empty:
            return pd.DataFrame(
                columns=["timestamp", "consumed_percent", "remaining_percent", "is_exhausted"]
            )

        data = df.copy()
        if not isinstance(data.index, pd.DatetimeIndex):
            if timestamp_col not in data.columns:
                raise KeyError(f"Timestamp column '{timestamp_col}' not found")
            data[timestamp_col] = pd.to_datetime(data[timestamp_col])
            data = data.set_index(timestamp_col)

        data[good_col] = pd.to_numeric(data[good_col], errors="coerce").fillna(0).astype(np.int64)
        data[total_col] = pd.to_numeric(data[total_col], errors="coerce").fillna(0).astype(np.int64)

        # Resample by step first
        resampled = data[[good_col, total_col]].resample(step).sum()
        resampled["bad_events"] = resampled[total_col] - resampled[good_col]

        # Rolling window aggregation
        rolling_tot = resampled[total_col].rolling(window, min_periods=1).sum()
        rolling_bad = resampled["bad_events"].rolling(window, min_periods=1).sum()

        allowed_rate = self.allowed_error_rate
        total_budget = rolling_tot * allowed_rate

        with np.errstate(divide="ignore", invalid="ignore"):
            consumed_pct = np.where(total_budget > 0, (rolling_bad / total_budget) * 100.0, 0.0)
            remaining_pct = 100.0 - consumed_pct

        trend_df = pd.DataFrame(
            {
                "good_events": resampled[good_col].rolling(window, min_periods=1).sum(),
                "total_events": rolling_tot,
                "bad_events": rolling_bad,
                "consumed_percent": np.round(consumed_pct, 4),
                "remaining_percent": np.round(remaining_pct, 4),
                "is_exhausted": consumed_pct >= 100.0,
            },
            index=resampled.index,
        )
        return trend_df
