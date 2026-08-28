"""Tests for Burn Rate calculation and Time-to-Exhaustion (TTE) projections."""

import pytest
from pydantic import ValidationError

from slo.burn_rate import (
    BurnRateCalculator,
    BurnRateResult,
    calculate_burn_rate,
    calculate_time_to_exhaustion,
    parse_window_seconds,
)


def test_parse_window_seconds():
    assert parse_window_seconds("30s") == 30.0
    assert parse_window_seconds("5m") == 300.0
    assert parse_window_seconds("30m") == 1800.0
    assert parse_window_seconds("1h") == 3600.0
    assert parse_window_seconds("6h") == 21600.0
    assert parse_window_seconds("24h") == 86400.0
    assert parse_window_seconds("3d") == 259200.0
    assert parse_window_seconds("30d") == 2592000.0
    assert parse_window_seconds("1w") == 604800.0
    assert parse_window_seconds(120) == 120.0

    with pytest.raises(ValueError):
        parse_window_seconds("invalid_window")

    with pytest.raises(ValueError):
        parse_window_seconds(-10)


def test_calculate_burn_rate_standard_tiers():
    # SLO = 99.9% -> Allowed error rate = 0.001
    # 1. 14.4x Burn rate: Observed error rate = 1.44% (0.0144)
    # Total = 10,000, Bad = 144, Good = 9,856
    res_14_4 = calculate_burn_rate(
        good_events=9856,
        total_events=10000,
        target_slo=0.999,
        window="1h",
        period_days=30,
    )
    assert isinstance(res_14_4, BurnRateResult)
    assert pytest.approx(res_14_4.burn_rate, 1e-2) == 14.4
    assert pytest.approx(res_14_4.observed_error_rate, 1e-4) == 0.0144
    assert pytest.approx(res_14_4.allowed_error_rate, 1e-4) == 0.001
    assert res_14_4.window_seconds == 3600.0
    # In 1 hour at 14.4x: 14.4 * (1/720) * 100 = 2.0% of 30-day budget
    assert pytest.approx(res_14_4.budget_consumed_in_window_percent, 1e-2) == 2.0

    # 2. 6x Burn rate: Observed error rate = 0.6% (0.006)
    # In 6 hours at 6.0x: 6.0 * (6/720) * 100 = 5.0% of 30-day budget
    res_6 = calculate_burn_rate(
        good_events=9940,
        total_events=10000,
        target_slo=0.999,
        window="6h",
        period_days=30,
    )
    assert pytest.approx(res_6.burn_rate, 1e-2) == 6.0
    assert pytest.approx(res_6.budget_consumed_in_window_percent, 1e-2) == 5.0

    # 3. 1x Burn rate: Standard consumption (100% in 30 days)
    res_1 = calculate_burn_rate(
        good_events=9990,
        total_events=10000,
        target_slo=0.999,
        window="24h",
        period_days=30,
    )
    assert pytest.approx(res_1.burn_rate, 1e-2) == 1.0


def test_calculate_time_to_exhaustion():
    # 30 days = 720 hours
    # 1. At 14.4x burn rate with 100% budget remaining:
    # TTE = 720 / 14.4 = 50 hours
    sec, hrs, days = calculate_time_to_exhaustion(burn_rate=14.4, remaining_budget_ratio=1.0, period_days=30)
    assert pytest.approx(hrs, 1e-2) == 50.0
    assert pytest.approx(days, 1e-2) == 50.0 / 24.0

    # 2. At 6.0x burn rate with 100% budget remaining:
    # TTE = 720 / 6.0 = 120 hours = 5 days
    sec, hrs, days = calculate_time_to_exhaustion(burn_rate=6.0, remaining_budget_ratio=1.0, period_days=30)
    assert pytest.approx(hrs, 1e-2) == 120.0
    assert pytest.approx(days, 1e-2) == 5.0

    # 3. At 1.0x burn rate: TTE = 30 days
    sec, hrs, days = calculate_time_to_exhaustion(burn_rate=1.0, remaining_budget_ratio=1.0, period_days=30)
    assert pytest.approx(hrs, 1e-2) == 720.0
    assert pytest.approx(days, 1e-2) == 30.0

    # 4. At 14.4x with 50% budget remaining: TTE = 25 hours
    sec, hrs, days = calculate_time_to_exhaustion(burn_rate=14.4, remaining_budget_ratio=0.5, period_days=30)
    assert pytest.approx(hrs, 1e-2) == 25.0

    # 5. Burn rate = 0 (infinite TTE)
    sec, hrs, days = calculate_time_to_exhaustion(burn_rate=0.0, remaining_budget_ratio=1.0, period_days=30)
    assert sec is None
    assert hrs is None
    assert days is None

    # 6. Budget already exhausted (remaining ratio = 0)
    sec, hrs, days = calculate_time_to_exhaustion(burn_rate=14.4, remaining_budget_ratio=0.0, period_days=30)
    assert sec == 0.0
    assert hrs == 0.0
    assert days == 0.0


def test_burn_rate_calculator_class():
    calc = BurnRateCalculator(target_slo=0.999, period_days=30)
    assert pytest.approx(calc.allowed_error_rate, 1e-6) == 0.001

    res = calc.calculate(good_events=990, total_events=1000, window="1h")
    # Error rate = 10/1000 = 0.01. Burn rate = 0.01 / 0.001 = 10.0x
    assert pytest.approx(res.burn_rate, 1e-2) == 10.0

    # From error rate
    res_err = calc.calculate_from_error_rate(error_rate=0.0144, window="1h")
    assert pytest.approx(res_err.burn_rate, 1e-2) == 14.4

    # Weighted burn rate
    res1 = calc.calculate_from_error_rate(error_rate=0.01, window="1h")   # 10x (weight 3600)
    res2 = calc.calculate_from_error_rate(error_rate=0.005, window="5m")  # 5x (weight 300)
    weighted = calc.calculate_weighted_burn_rate([res1, res2])
    expected_w = (10.0 * 3600 + 5.0 * 300) / (3600 + 300)
    assert pytest.approx(weighted, 1e-2) == expected_w


def test_burn_rate_edge_cases():
    # Zero events
    res_zero = calculate_burn_rate(good_events=0, total_events=0, target_slo=0.999)
    assert res_zero.burn_rate == 0.0
    assert res_zero.time_to_exhaustion_seconds is None

    # Invalid target
    with pytest.raises(ValueError):
        BurnRateCalculator(target_slo=1.0)

    # Invalid error rate
    calc = BurnRateCalculator(target_slo=0.999)
    with pytest.raises(ValueError):
        calc.calculate_from_error_rate(error_rate=1.5)

def test_burn_rate_weights_validation():
    calc = BurnRateCalculator(target_slo=0.999)
    res1 = calc.calculate_from_error_rate(error_rate=0.01, window="1h")
    res2 = calc.calculate_from_error_rate(error_rate=0.02, window="6h")

    # Mismatched weights length
    with pytest.raises(ValueError, match="Length of weights must match"):
        calc.calculate_weighted_burn_rate([res1, res2], weights=[1.0])

    # Non-positive sum of weights
    with pytest.raises(ValueError, match="Sum of weights must be positive"):
        calc.calculate_weighted_burn_rate([res1, res2], weights=[0.0, 0.0])

    # Empty results
    assert calc.calculate_weighted_burn_rate([]) == 0.0


def test_burn_rate_negative_events_validation():
    with pytest.raises(ValueError):
        calculate_burn_rate(good_events=-5, total_events=100, target_slo=0.999)

    with pytest.raises(ValueError):
        calculate_burn_rate(good_events=150, total_events=100, target_slo=0.999)
