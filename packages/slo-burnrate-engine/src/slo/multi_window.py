"""Multi-Window Multi-Burn-Rate (MWMBR) Alerting Engine.

Implements the Google SRE Workbook (Chapter 5) multi-window alerting algorithm
to eliminate false positives while achieving near-zero alert reset delays.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Sequence
import numpy as np
import pandas as pd
from pydantic import BaseModel, ConfigDict, Field

from slo.burn_rate import calculate_burn_rate, parse_window_seconds
from slo.error_budget import SLODefinition


class AlertSeverity(str, Enum):
    """Alert severity levels adhering to Google SRE alerting standards."""
    PAGE = "page"
    CRITICAL = "critical"
    TICKET = "ticket"
    WARNING = "warning"
    INFO = "info"


class AlertTier(BaseModel):
    """Multi-Window Alert Tier configuration."""
    model_config = ConfigDict(extra="forbid", strict=True)

    name: str = Field(min_length=1, max_length=64)
    long_window_seconds: float = Field(gt=0.0)
    short_window_seconds: float = Field(gt=0.0)
    burn_rate_threshold: float = Field(gt=0.0)
    budget_consumed_percent: float = Field(gt=0.0, le=100.0)
    severity: AlertSeverity
    channel: str = Field(default="pagerduty")
    description: str = Field(default="")

    @classmethod
    def create(
        cls,
        name: str,
        long_window: str | int | float,
        short_window: str | int | float,
        burn_rate_threshold: float,
        budget_consumed_percent: float,
        severity: AlertSeverity | str,
        channel: str = "pagerduty",
        description: str = "",
    ) -> AlertTier:
        """Helper constructor accepting string windows like '1h', '5m'."""
        sev = AlertSeverity(severity) if isinstance(severity, str) else severity
        return cls(
            name=name,
            long_window_seconds=parse_window_seconds(long_window),
            short_window_seconds=parse_window_seconds(short_window),
            burn_rate_threshold=float(burn_rate_threshold),
            budget_consumed_percent=float(budget_consumed_percent),
            severity=sev,
            channel=channel,
            description=description,
        )


def get_standard_google_sre_tiers() -> list[AlertTier]:
    """Return standard 30-day Google SRE Workbook Table 5-8 alert tiers.

    1. Page: 1h long window, 5m short window @ 14.4x burn rate (2% budget consumed)
    2. Page: 6h long window, 30m short window @ 6.0x burn rate (5% budget consumed)
    3. Ticket / Warning: 24h long window, 2h short window @ 3.0x burn rate (10% budget consumed)
    4. Ticket / Info: 72h (3d) long window, 6h short window @ 1.0x burn rate (10% budget consumed)
    """
    return [
        AlertTier.create(
            name="1h-5m-14.4x-page",
            long_window="1h",
            short_window="5m",
            burn_rate_threshold=14.4,
            budget_consumed_percent=2.0,
            severity=AlertSeverity.PAGE,
            channel="pagerduty",
            description="Consuming 2% error budget in 1 hour; urgent page required",
        ),
        AlertTier.create(
            name="6h-30m-6x-page",
            long_window="6h",
            short_window="30m",
            burn_rate_threshold=6.0,
            budget_consumed_percent=5.0,
            severity=AlertSeverity.PAGE,
            channel="pagerduty",
            description="Consuming 5% error budget in 6 hours; urgent page required",
        ),
        AlertTier.create(
            name="24h-2h-3x-ticket",
            long_window="24h",
            short_window="2h",
            burn_rate_threshold=3.0,
            budget_consumed_percent=10.0,
            severity=AlertSeverity.TICKET,
            channel="jira-ticket",
            description="Consuming 10% error budget in 24 hours; ticket/investigation required",
        ),
        AlertTier.create(
            name="72h-6h-1x-info",
            long_window="72h",
            short_window="6h",
            burn_rate_threshold=1.0,
            budget_consumed_percent=10.0,
            severity=AlertSeverity.INFO,
            channel="slack",
            description="Consuming 10% error budget in 3 days; informational notification",
        ),
    ]


class AlertConditionEvaluation(BaseModel):
    """Detailed evaluation result for a specific alert tier."""
    model_config = ConfigDict(extra="forbid")

    tier_name: str
    severity: AlertSeverity
    long_window_seconds: float
    short_window_seconds: float
    burn_rate_threshold: float
    long_window_burn_rate: float
    short_window_burn_rate: float
    long_window_triggered: bool
    short_window_triggered: bool
    is_firing: bool
    channel: str
    message: str


class MultiWindowAlertResult(BaseModel):
    """Overall multi-window alerting evaluation status."""
    model_config = ConfigDict(extra="forbid")

    slo_name: str
    service: str
    target_slo: float
    timestamp: datetime
    evaluations: list[AlertConditionEvaluation]
    firing_alerts: list[AlertConditionEvaluation]
    has_active_alerts: bool
    highest_severity: AlertSeverity | None = None
    summary_message: str


class MultiWindowAlertEngine:
    """Core Google SRE Multi-Window Multi-Burn-Rate Alerting Engine."""

    def __init__(
        self,
        slo: SLODefinition,
        tiers: Sequence[AlertTier] | None = None,
    ) -> None:
        self.slo = slo
        self.tiers = list(tiers) if tiers is not None else get_standard_google_sre_tiers()

    def evaluate_from_burn_rates(
        self,
        burn_rates: dict[str | float, float],
        timestamp: datetime | None = None,
    ) -> MultiWindowAlertResult:
        """Evaluate alert tiers from a dictionary of window durations to burn rates."""
        ts = timestamp or datetime.now(timezone.utc)
        evaluations: list[AlertConditionEvaluation] = []
        firing_alerts: list[AlertConditionEvaluation] = []

        def get_rate(sec: float) -> float:
            for k, v in burn_rates.items():
                if isinstance(k, (int, float)) and float(k) == sec:
                    return float(v)
                if isinstance(k, str):
                    try:
                        if parse_window_seconds(k) == sec:
                            return float(v)
                    except ValueError:
                        pass
            return 0.0

        for tier in self.tiers:
            long_br = get_rate(tier.long_window_seconds)
            short_br = get_rate(tier.short_window_seconds)

            long_trig = bool(long_br >= tier.burn_rate_threshold)
            short_trig = bool(short_br >= tier.burn_rate_threshold)
            is_firing = bool(long_trig and short_trig)

            if is_firing:
                msg = (
                    f"CRITICAL ALERT [{tier.severity.value.upper()}]: Tier '{tier.name}' FIRING! "
                    f"Long window ({tier.long_window_seconds / 3600:.1f}h) burn rate {long_br:.2f}x >= {tier.burn_rate_threshold:.2f}x AND "
                    f"Short window ({tier.short_window_seconds / 60:.1f}m) burn rate {short_br:.2f}x >= {tier.burn_rate_threshold:.2f}x"
                )
            elif long_trig and not short_trig:
                msg = (
                    f"Tier '{tier.name}' OK (Reset): Long window {long_br:.2f}x >= {tier.burn_rate_threshold:.2f}x "
                    f"but Short window dropped to {short_br:.2f}x < {tier.burn_rate_threshold:.2f}x (cleared)"
                )
            else:
                msg = (
                    f"Tier '{tier.name}' OK: Long window {long_br:.2f}x, "
                    f"Short window {short_br:.2f}x < {tier.burn_rate_threshold:.2f}x"
                )

            evaluation = AlertConditionEvaluation(
                tier_name=tier.name,
                severity=tier.severity,
                long_window_seconds=tier.long_window_seconds,
                short_window_seconds=tier.short_window_seconds,
                burn_rate_threshold=tier.burn_rate_threshold,
                long_window_burn_rate=round(long_br, 4),
                short_window_burn_rate=round(short_br, 4),
                long_window_triggered=long_trig,
                short_window_triggered=short_trig,
                is_firing=is_firing,
                channel=tier.channel,
                message=msg,
            )
            evaluations.append(evaluation)
            if is_firing:
                firing_alerts.append(evaluation)

        severity_rank = {
            AlertSeverity.CRITICAL: 5,
            AlertSeverity.PAGE: 4,
            AlertSeverity.WARNING: 3,
            AlertSeverity.TICKET: 2,
            AlertSeverity.INFO: 1,
        }
        highest_sev: AlertSeverity | None = None
        if firing_alerts:
            highest_sev = max(firing_alerts, key=lambda a: severity_rank.get(a.severity, 0)).severity

        has_active = len(firing_alerts) > 0
        summary = (
            f"Alert status: {len(firing_alerts)} firing alerts out of {len(evaluations)} tiers evaluated."
            if has_active
            else "All SLO alert tiers normal; zero active alerts."
        )

        return MultiWindowAlertResult(
            slo_name=self.slo.name,
            service=self.slo.service,
            target_slo=self.slo.target,
            timestamp=ts,
            evaluations=evaluations,
            firing_alerts=firing_alerts,
            has_active_alerts=has_active,
            highest_severity=highest_sev,
            summary_message=summary,
        )

    def evaluate_from_events(
        self,
        events: dict[str | float, tuple[int, int]],
        timestamp: datetime | None = None,
    ) -> MultiWindowAlertResult:
        """Evaluate alert tiers from a dictionary of window -> (good_events, total_events)."""
        burn_rates: dict[str | float, float] = {}
        for win, (good, total) in events.items():
            sec = parse_window_seconds(win)
            br_res = calculate_burn_rate(
                good_events=good,
                total_events=total,
                target_slo=self.slo.target,
                window=sec,
                period_days=self.slo.window_days,
            )
            burn_rates[win] = br_res.burn_rate
            burn_rates[sec] = br_res.burn_rate

        return self.evaluate_from_burn_rates(burn_rates, timestamp=timestamp)

    def evaluate_timeseries(
        self,
        df: pd.DataFrame,
        timestamp_col: str = "timestamp",
        good_col: str = "good_events",
        total_col: str = "total_events",
        current_time: datetime | None = None,
    ) -> MultiWindowAlertResult:
        """Evaluate multi-window alerts from a raw event time-series DataFrame."""
        if df.empty:
            return self.evaluate_from_burn_rates({}, timestamp=current_time)

        data = df.copy()
        if not isinstance(data.index, pd.DatetimeIndex):
            data[timestamp_col] = pd.to_datetime(data[timestamp_col])
            data = data.sort_values(timestamp_col)
            data = data.set_index(timestamp_col)
        else:
            data = data.sort_index()

        end_time = current_time or data.index.max()
        events: dict[str | float, tuple[int, int]] = {}

        unique_windows: set[float] = set()
        for tier in self.tiers:
            unique_windows.add(tier.long_window_seconds)
            unique_windows.add(tier.short_window_seconds)

        for win_sec in unique_windows:
            start_time = end_time - pd.Timedelta(float(win_sec), unit="s")
            window_slice = data.loc[start_time:end_time]
            if window_slice.empty:
                events[win_sec] = (0, 0)
            else:
                good = int(pd.to_numeric(window_slice[good_col], errors="coerce").fillna(0).sum())
                total = int(pd.to_numeric(window_slice[total_col], errors="coerce").fillna(0).sum())
                events[win_sec] = (good, total)

        return self.evaluate_from_events(events, timestamp=end_time)
