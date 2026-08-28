"""Service Level Indicator (SLI) computation module.

Provides high-performance event-based and time-series SLI calculations
with strict memory boundaries (CWE-400) and robust input validation (CWE-20).
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Sequence, Union
import numpy as np
import pandas as pd
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class SLIDataPoint(BaseModel):
    """Data point representing events in a discrete time bucket."""
    model_config = ConfigDict(extra="forbid", strict=True)

    timestamp: Union[datetime, float, int, str]
    good_events: int = Field(ge=0, description="Count of successful/compliant events")
    total_events: int = Field(ge=0, description="Count of total observed events")
    bad_events: int | None = Field(default=None, ge=0, description="Count of non-compliant events")

    @model_validator(mode="after")
    def validate_event_counts(self) -> SLIDataPoint:
        if self.bad_events is not None:
            if self.good_events + self.bad_events != self.total_events:
                raise ValueError(
                    f"Inconsistent event counts: good ({self.good_events}) + "
                    f"bad ({self.bad_events}) != total ({self.total_events})"
                )
        elif self.good_events > self.total_events:
            raise ValueError(
                f"good_events ({self.good_events}) cannot exceed total_events ({self.total_events})"
            )
        return self


class SLIResult(BaseModel):
    """Quantitative result of an SLI calculation."""
    model_config = ConfigDict(extra="forbid")

    good_events: int = Field(ge=0)
    total_events: int = Field(ge=0)
    bad_events: int = Field(ge=0)
    sli_ratio: float = Field(ge=0.0, le=1.0)
    sli_percent: float = Field(ge=0.0, le=100.0)
    error_rate: float = Field(ge=0.0, le=1.0)
    window: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


def calculate_event_sli(
    good_events: int,
    total_events: int,
    validate: bool = True,
    window: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> SLIResult:
    """Calculate SLI ratio and error rate from good and total event counts.

    Formula:
        SLI = good_events / total_events
        Error Rate = (total_events - good_events) / total_events = 1.0 - SLI

    Args:
        good_events: Number of valid/good requests or events.
        total_events: Total number of requests or events.
        validate: Whether to perform strict bounds validation.
        window: Optional window description (e.g., '1h', '30d').
        metadata: Optional metadata dictionary.

    Returns:
        SLIResult with exact quantitative metrics.

    Raises:
        ValueError: If good_events < 0, total_events < 0, or good_events > total_events.
    """
    if validate:
        if good_events < 0:
            raise ValueError(f"good_events must be non-negative, got {good_events}")
        if total_events < 0:
            raise ValueError(f"total_events must be non-negative, got {total_events}")
        if good_events > total_events:
            raise ValueError(
                f"good_events ({good_events}) cannot exceed total_events ({total_events})"
            )

    if total_events == 0:
        return SLIResult(
            good_events=0,
            total_events=0,
            bad_events=0,
            sli_ratio=1.0,
            sli_percent=100.0,
            error_rate=0.0,
            window=window,
            metadata=metadata or {},
        )

    bad_events = total_events - good_events
    sli_ratio = float(good_events / total_events)
    # Clip numerical precision artifacts to [0.0, 1.0]
    sli_ratio = max(0.0, min(1.0, sli_ratio))
    error_rate = float(bad_events / total_events)
    error_rate = max(0.0, min(1.0, error_rate))

    return SLIResult(
        good_events=good_events,
        total_events=total_events,
        bad_events=bad_events,
        sli_ratio=sli_ratio,
        sli_percent=round(sli_ratio * 100.0, 6),
        error_rate=error_rate,
        window=window,
        metadata=metadata or {},
    )


def calculate_timeseries_sli(
    data: pd.DataFrame | Sequence[dict[str, Any]] | Sequence[SLIDataPoint],
    timestamp_col: str = "timestamp",
    good_col: str = "good_events",
    total_col: str = "total_events",
    bad_col: str | None = None,
    max_memory_mb: float = 512.0,
    window: str | None = None,
) -> SLIResult:
    """Calculate aggregated SLI over time-series data with memory guard (CWE-400).

    Args:
        data: DataFrame or collection of data points.
        timestamp_col: Name of timestamp column.
        good_col: Name of good events column.
        total_col: Name of total events column.
        bad_col: Optional name of bad events column.
        max_memory_mb: Maximum memory threshold in megabytes to prevent DoS.
        window: Optional window string descriptor.

    Returns:
        Aggregated SLIResult.
    """
    if isinstance(data, pd.DataFrame):
        df = data
    elif isinstance(data, (list, tuple)):
        if not data:
            return calculate_event_sli(0, 0, window=window)
        if isinstance(data[0], SLIDataPoint):
            df = pd.DataFrame([dp.model_dump() for dp in data])
        else:
            df = pd.DataFrame(data)
    else:
        raise TypeError(f"Unsupported data type: {type(data)}")

    if df.empty:
        return calculate_event_sli(0, 0, window=window)

    # CWE-400: Resource and memory quota verification
    mem_mb = df.memory_usage(deep=True).sum() / (1024.0 * 1024.0)
    if mem_mb > max_memory_mb:
        raise ValueError(
            f"Input DataFrame exceeds memory quota: {mem_mb:.2f} MB > limit of {max_memory_mb:.2f} MB"
        )

    if total_col not in df.columns:
        raise KeyError(f"Missing required total column '{total_col}' in dataset")

    total_series = pd.to_numeric(df[total_col], errors="coerce").fillna(0).astype(np.int64)
    total_sum = int(np.sum(total_series.values))

    if good_col in df.columns:
        good_series = pd.to_numeric(df[good_col], errors="coerce").fillna(0).astype(np.int64)
        good_sum = int(np.sum(good_series.values))
    elif bad_col is not None and bad_col in df.columns:
        bad_series = pd.to_numeric(df[bad_col], errors="coerce").fillna(0).astype(np.int64)
        bad_sum = int(np.sum(bad_series.values))
        good_sum = max(0, total_sum - bad_sum)
    else:
        raise KeyError(f"Dataset must provide either good column '{good_col}' or bad column '{bad_col}'")

    if good_sum > total_sum:
        raise ValueError(f"Sum of good events ({good_sum}) exceeds total events ({total_sum})")

    return calculate_event_sli(good_events=good_sum, total_events=total_sum, window=window)


def calculate_windowed_sli(
    df: pd.DataFrame,
    window: str,
    timestamp_col: str = "timestamp",
    good_col: str = "good_events",
    total_col: str = "total_events",
) -> pd.DataFrame:
    """Resample time-series data and calculate SLI for each rolling/resampled window.

    Args:
        df: Input DataFrame with timestamp index or timestamp column.
        window: Resampling window string (e.g., '1h', '5min', '1D').
        timestamp_col: Name of column containing datetime timestamps.
        good_col: Name of good events column.
        total_col: Name of total events column.

    Returns:
        DataFrame indexed by window timestamp with good_events, total_events,
        bad_events, sli_ratio, and error_rate columns.
    """
    if df.empty:
        return pd.DataFrame(
            columns=[good_col, total_col, "bad_events", "sli_ratio", "error_rate"]
        )

    data = df.copy()
    if not isinstance(data.index, pd.DatetimeIndex):
        if timestamp_col not in data.columns:
            raise KeyError(f"Timestamp column '{timestamp_col}' not found")
        data[timestamp_col] = pd.to_datetime(data[timestamp_col])
        data = data.set_index(timestamp_col)

    data[good_col] = pd.to_numeric(data[good_col], errors="coerce").fillna(0).astype(np.int64)
    data[total_col] = pd.to_numeric(data[total_col], errors="coerce").fillna(0).astype(np.int64)

    resampled = data[[good_col, total_col]].resample(window).sum()
    resampled["bad_events"] = np.maximum(0, resampled[total_col] - resampled[good_col])
    
    # Vectorized safe division
    totals = resampled[total_col].values
    goods = resampled[good_col].values
    bads = resampled["bad_events"].values

    with np.errstate(divide="ignore", invalid="ignore"):
        sli_ratios = np.where(totals > 0, goods / totals, 1.0)
        error_rates = np.where(totals > 0, bads / totals, 0.0)

    resampled["sli_ratio"] = np.clip(sli_ratios, 0.0, 1.0)
    resampled["error_rate"] = np.clip(error_rates, 0.0, 1.0)

    return resampled


class SLICalculator:
    """Enterprise SLI Calculator with support for latency thresholds and event streams."""

    def __init__(self, default_window: str = "30D", max_memory_mb: float = 512.0) -> None:
        self.default_window = default_window
        self.max_memory_mb = max_memory_mb

    def from_events(self, good: int, total: int, window: str | None = None) -> SLIResult:
        """Calculate SLI from raw event counts."""
        return calculate_event_sli(good, total, window=window or self.default_window)

    def from_dataframe(
        self,
        df: pd.DataFrame,
        timestamp_col: str = "timestamp",
        good_col: str = "good_events",
        total_col: str = "total_events",
        bad_col: str | None = None,
        window: str | None = None,
    ) -> SLIResult:
        """Calculate SLI from pandas DataFrame with memory quotas."""
        return calculate_timeseries_sli(
            data=df,
            timestamp_col=timestamp_col,
            good_col=good_col,
            total_col=total_col,
            bad_col=bad_col,
            max_memory_mb=self.max_memory_mb,
            window=window or self.default_window,
        )

    def from_latencies(
        self,
        latencies_ms: Sequence[float] | np.ndarray,
        threshold_ms: float,
        window: str | None = None,
    ) -> SLIResult:
        """Calculate SLI based on latency threshold criterion (e.g. latency <= 200ms)."""
        if len(latencies_ms) == 0:
            return calculate_event_sli(0, 0, window=window)

        arr = np.asarray(latencies_ms, dtype=np.float64)
        total = int(arr.size)
        good = int(np.sum(arr <= threshold_ms))
        return calculate_event_sli(
            good_events=good,
            total_events=total,
            window=window or self.default_window,
            metadata={"threshold_ms": threshold_ms},
        )
