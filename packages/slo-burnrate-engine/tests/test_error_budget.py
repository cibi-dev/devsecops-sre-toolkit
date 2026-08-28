"""Tests for Error Budget calculation and rolling tracking module."""

from datetime import datetime, timedelta
import pandas as pd
import pytest
from pydantic import ValidationError

from slo.error_budget import ErrorBudgetManager, ErrorBudgetResult, SLODefinition
from slo.sli_calculator import calculate_event_sli


def test_slo_definition_validation():
    # Valid
    slo = SLODefinition(name="api-availability", service="api-service", target=0.999, window_days=30)
    assert slo.target == 0.999
    assert slo.window_days == 30

    # Invalid targets
    with pytest.raises(ValidationError):
        SLODefinition(name="invalid", service="srv", target=1.0)

    with pytest.raises(ValidationError):
        SLODefinition(name="invalid", service="srv", target=0.0)

    with pytest.raises(ValidationError):
        SLODefinition(name="invalid", service="srv", target=1.5)

    with pytest.raises(ValidationError):
        SLODefinition(name="invalid", service="srv", target=-0.1)

    # Invalid window days
    with pytest.raises(ValidationError):
        SLODefinition(name="invalid", service="srv", target=0.99, window_days=0)


def test_error_budget_calculation_mathematics():
    slo = SLODefinition(name="checkout-slo", service="checkout", target=0.999, window_days=30)
    mgr = ErrorBudgetManager(slo)

    assert pytest.approx(mgr.allowed_error_rate, 1e-6) == 0.001

    # 1,000,000 total events: Allowed budget = 1,000 bad events
    # If 500 bad events observed -> Consumed = 50%, Remaining = 50%
    res = mgr.calculate_from_events(good_events=999500, total_events=1000000)
    assert isinstance(res, ErrorBudgetResult)
    assert res.total_events == 1000000
    assert res.good_events == 999500
    assert res.bad_events == 500
    assert pytest.approx(res.total_budget_events, 1e-2) == 1000.0
    assert pytest.approx(res.consumed_budget_percent, 1e-2) == 50.0
    assert pytest.approx(res.remaining_budget_percent, 1e-2) == 50.0
    assert pytest.approx(res.remaining_budget_ratio, 1e-4) == 0.50
    assert res.is_exhausted is False


def test_error_budget_exhausted_scenario():
    slo = SLODefinition(name="payment-slo", service="payment", target=0.999, window_days=30)
    mgr = ErrorBudgetManager(slo)

    # 1,000,000 events -> allowed budget = 1,000 bad events.
    # 2,000 bad events observed -> 200% consumed, Remaining = -100%, is_exhausted = True
    res = mgr.calculate_from_events(good_events=998000, total_events=1000000)
    assert res.bad_events == 2000
    assert pytest.approx(res.consumed_budget_percent, 1e-2) == 200.0
    assert pytest.approx(res.remaining_budget_percent, 1e-2) == -100.0
    assert pytest.approx(res.remaining_budget_ratio, 1e-4) == -1.0
    assert res.is_exhausted is True


def test_error_budget_zero_events():
    slo = SLODefinition(name="zero-slo", service="auth", target=0.999)
    mgr = ErrorBudgetManager(slo)

    res = mgr.calculate_from_events(good_events=0, total_events=0)
    assert res.total_events == 0
    assert res.consumed_budget_percent == 0.0
    assert res.remaining_budget_percent == 100.0
    assert res.is_exhausted is False


def test_error_budget_from_sli():
    slo = SLODefinition(name="orders-slo", service="orders", target=0.99)
    mgr = ErrorBudgetManager(slo)

    sli_res = calculate_event_sli(good_events=9900, total_events=10000)
    res = mgr.calculate_from_sli(sli_res, metadata={"env": "prod"})

    # 10,000 * 0.01 = 100 allowed bad events. 100 bad events observed. 100% consumed.
    assert res.total_budget_events == 100.0
    assert res.consumed_budget_percent == 100.0
    assert res.remaining_budget_percent == 0.0
    assert res.is_exhausted is True
    assert res.metadata["env"] == "prod"


def test_error_budget_rolling_dataframe():
    slo = SLODefinition(name="search-slo", service="search", target=0.999, window_days=30)
    mgr = ErrorBudgetManager(slo)

    now = datetime.now()
    dates = [now - timedelta(days=i) for i in range(40)]
    # 9995 good events out of 10000 -> 0.05% error rate (half of 0.1% budget)
    goods = [9995] * 40
    totals = [10000] * 40

    df = pd.DataFrame({"timestamp": dates, "good_events": goods, "total_events": totals})

    # Rolling 30 days should include last 30 days
    res = mgr.calculate_rolling_budget(df, rolling_days=30)
    assert res.total_events > 0
    assert res.total_events <= 400000
    assert res.is_exhausted is False
    assert pytest.approx(res.consumed_budget_percent, 1e-2) == 50.0


def test_error_budget_rolling_trend():
    slo = SLODefinition(name="cart-slo", service="cart", target=0.999, window_days=7)
    mgr = ErrorBudgetManager(slo)

    base = pd.Timestamp("2026-08-01 00:00:00")
    dates = [base + pd.Timedelta(i, unit="D") for i in range(14)]
    goods = [999] * 14
    totals = [1000] * 14

    df = pd.DataFrame({"timestamp": dates, "good_events": goods, "total_events": totals})
    trend = mgr.get_rolling_trend(df, window="7D", step="1D")

    assert len(trend) == 14
    assert "consumed_percent" in trend.columns
    assert "remaining_percent" in trend.columns
    assert "is_exhausted" in trend.columns
    assert trend["consumed_percent"].iloc[-1] == 100.0

    # Empty df trend
    empty_trend = mgr.get_rolling_trend(pd.DataFrame())
    assert empty_trend.empty
