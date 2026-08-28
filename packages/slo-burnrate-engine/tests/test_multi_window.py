"""Tests for Multi-Window Multi-Burn-Rate (MWMBR) alerting engine."""

from datetime import datetime, timedelta
import pandas as pd
import pytest

from slo.error_budget import SLODefinition
from slo.multi_window import (
    AlertConditionEvaluation,
    AlertSeverity,
    AlertTier,
    MultiWindowAlertEngine,
    MultiWindowAlertResult,
    get_standard_google_sre_tiers,
)


@pytest.fixture
def sample_slo():
    return SLODefinition(name="auth-slo", service="auth-service", target=0.999, window_days=30)


def test_standard_google_sre_tiers():
    tiers = get_standard_google_sre_tiers()
    assert len(tiers) == 4

    # Tier 1: 1h/5m @ 14.4x -> 2% budget
    t1 = tiers[0]
    assert t1.long_window_seconds == 3600.0
    assert t1.short_window_seconds == 300.0
    assert t1.burn_rate_threshold == 14.4
    assert t1.budget_consumed_percent == 2.0
    assert t1.severity == AlertSeverity.PAGE

    # Tier 2: 6h/30m @ 6x -> 5% budget
    t2 = tiers[1]
    assert t2.long_window_seconds == 21600.0
    assert t2.short_window_seconds == 1800.0
    assert t2.burn_rate_threshold == 6.0
    assert t2.budget_consumed_percent == 5.0
    assert t2.severity == AlertSeverity.PAGE

    # Tier 3: 24h/2h @ 3x -> 10% budget
    t3 = tiers[2]
    assert t3.long_window_seconds == 86400.0
    assert t3.short_window_seconds == 7200.0
    assert t3.burn_rate_threshold == 3.0
    assert t3.budget_consumed_percent == 10.0
    assert t3.severity == AlertSeverity.TICKET

    # Tier 4: 72h/6h @ 1x -> 10% budget
    t4 = tiers[3]
    assert t4.long_window_seconds == 259200.0
    assert t4.short_window_seconds == 21600.0
    assert t4.burn_rate_threshold == 1.0
    assert t4.budget_consumed_percent == 10.0
    assert t4.severity == AlertSeverity.INFO


def test_multi_window_firing_condition(sample_slo):
    engine = MultiWindowAlertEngine(sample_slo)

    # Both 1h and 5m elevated above 14.4x
    rates = {
        "1h": 15.0,
        "5m": 16.0,
        "6h": 1.0,
        "30m": 1.0,
        "24h": 0.5,
        "2h": 0.5,
        "72h": 0.2,
        "6h": 0.2,
    }
    result = engine.evaluate_from_burn_rates(rates)
    assert isinstance(result, MultiWindowAlertResult)
    assert result.has_active_alerts is True
    assert len(result.firing_alerts) >= 1

    t1_eval = next(e for e in result.evaluations if e.tier_name == "1h-5m-14.4x-page")
    assert t1_eval.is_firing is True
    assert t1_eval.long_window_triggered is True
    assert t1_eval.short_window_triggered is True
    assert result.highest_severity == AlertSeverity.PAGE


def test_multi_window_fast_reset_cleared(sample_slo):
    engine = MultiWindowAlertEngine(sample_slo)

    # 1h is still elevated (e.g. 15.0x) because outage ended 3 minutes ago,
    # but 5m window has dropped back down to 0.2x!
    # MWMBR MUST NOT FIRE because short window is clear!
    rates = {
        "1h": 15.0,
        "5m": 0.2,
        "6h": 1.0,
        "30m": 0.1,
    }
    result = engine.evaluate_from_burn_rates(rates)
    t1_eval = next(e for e in result.evaluations if e.tier_name == "1h-5m-14.4x-page")
    assert t1_eval.long_window_triggered is True
    assert t1_eval.short_window_triggered is False
    assert t1_eval.is_firing is False
    assert result.has_active_alerts is False


def test_multi_window_transient_blip_suppressed(sample_slo):
    engine = MultiWindowAlertEngine(sample_slo)

    # Short 5m window spike (20.0x), but 1h average is low (1.1x).
    # MWMBR MUST NOT FIRE to prevent false alarm on transient blip!
    rates = {
        "1h": 1.1,
        "5m": 20.0,
    }
    result = engine.evaluate_from_burn_rates(rates)
    t1_eval = next(e for e in result.evaluations if e.tier_name == "1h-5m-14.4x-page")
    assert t1_eval.long_window_triggered is False
    assert t1_eval.short_window_triggered is True
    assert t1_eval.is_firing is False
    assert result.has_active_alerts is False


def test_evaluate_from_events(sample_slo):
    engine = MultiWindowAlertEngine(sample_slo)

    # At 99.9% target SLO, allowed error = 0.001
    # 14.4x error rate = 0.0144 (e.g., 144 errors per 10,000 requests)
    events = {
        "1h": (9850, 10000),   # 150 errors -> 0.015 error rate -> 15.0x
        "5m": (9850, 10000),   # 150 errors -> 15.0x
        "6h": (9990, 10000),   # 10 errors -> 1.0x
        "30m": (9990, 10000),
        "24h": (9990, 10000),
        "2h": (9990, 10000),
        "72h": (9990, 10000),
    }
    res = engine.evaluate_from_events(events)
    assert res.has_active_alerts is True
    assert res.firing_alerts[0].tier_name == "1h-5m-14.4x-page"


def test_evaluate_timeseries_dataframe(sample_slo):
    engine = MultiWindowAlertEngine(sample_slo)

    base = datetime.now()
    dates = [base - timedelta(minutes=i) for i in range(120)]
    dates.reverse()

    # Normal traffic for first 90 minutes (99.9% good), then last 30 minutes with 2% errors
    goods = []
    totals = []
    for i in range(120):
        totals.append(1000)
        if i < 90:
            goods.append(999)  # 0.1% errors (1x BR)
        else:
            goods.append(980)  # 2.0% errors (20x BR)

    df = pd.DataFrame({"timestamp": dates, "good_events": goods, "total_events": totals})
    res = engine.evaluate_timeseries(df)
    assert isinstance(res, MultiWindowAlertResult)
    assert res.timestamp is not None

def test_multi_window_empty_dataframe(sample_slo):
    engine = MultiWindowAlertEngine(sample_slo)
    res = engine.evaluate_timeseries(pd.DataFrame())
    assert res.has_active_alerts is False
    assert len(res.firing_alerts) == 0


def test_custom_alert_tier():
    tier = AlertTier.create(
        name="custom-tier",
        long_window="12h",
        short_window="1h",
        burn_rate_threshold=4.5,
        budget_consumed_percent=7.5,
        severity="warning",
        channel="slack-devs",
        description="Custom 12h tier",
    )
    assert tier.name == "custom-tier"
    assert tier.long_window_seconds == 43200.0
    assert tier.short_window_seconds == 3600.0
    assert tier.burn_rate_threshold == 4.5
    assert tier.severity == AlertSeverity.WARNING
