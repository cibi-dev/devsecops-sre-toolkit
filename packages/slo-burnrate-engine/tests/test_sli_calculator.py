"""Tests for SLI calculation module."""

from datetime import datetime, timedelta
import numpy as np
import pandas as pd
import pytest
from pydantic import ValidationError

from slo.sli_calculator import (
    SLICalculator,
    SLIDataPoint,
    SLIResult,
    calculate_event_sli,
    calculate_timeseries_sli,
    calculate_windowed_sli,
)


def test_calculate_event_sli_standard():
    res = calculate_event_sli(good_events=999, total_events=1000)
    assert isinstance(res, SLIResult)
    assert res.good_events == 999
    assert res.total_events == 1000
    assert res.bad_events == 1
    assert pytest.approx(res.sli_ratio, 1e-6) == 0.999
    assert pytest.approx(res.sli_percent, 1e-4) == 99.9
    assert pytest.approx(res.error_rate, 1e-6) == 0.001


def test_calculate_event_sli_zero_events():
    res = calculate_event_sli(good_events=0, total_events=0)
    assert res.sli_ratio == 1.0
    assert res.error_rate == 0.0
    assert res.good_events == 0
    assert res.total_events == 0


def test_calculate_event_sli_perfect_and_zero_good():
    # 100% compliant
    res_100 = calculate_event_sli(good_events=5000, total_events=5000)
    assert res_100.sli_ratio == 1.0
    assert res_100.error_rate == 0.0

    # 0% compliant
    res_0 = calculate_event_sli(good_events=0, total_events=5000)
    assert res_0.sli_ratio == 0.0
    assert res_0.error_rate == 1.0
    assert res_0.bad_events == 5000


def test_calculate_event_sli_invalid_inputs():
    with pytest.raises(ValueError, match="cannot exceed total_events"):
        calculate_event_sli(good_events=1001, total_events=1000)

    with pytest.raises(ValueError, match="good_events must be non-negative"):
        calculate_event_sli(good_events=-1, total_events=1000)

    with pytest.raises(ValueError, match="total_events must be non-negative"):
        calculate_event_sli(good_events=10, total_events=-5)


def test_sli_datapoint_validation():
    # Valid
    dp = SLIDataPoint(timestamp="2026-08-27T12:00:00Z", good_events=95, total_events=100)
    assert dp.good_events == 95

    # Valid with bad_events
    dp_bad = SLIDataPoint(timestamp="2026-08-27T12:00:00Z", good_events=90, total_events=100, bad_events=10)
    assert dp_bad.bad_events == 10

    # Inconsistent
    with pytest.raises(ValidationError):
        SLIDataPoint(timestamp="2026-08-27T12:00:00Z", good_events=90, total_events=100, bad_events=5)


def test_calculate_timeseries_sli_dataframe():
    now = datetime.now()
    dates = [now + timedelta(minutes=i) for i in range(10)]
    goods = [990, 995, 1000, 980, 990, 995, 1000, 985, 990, 995]
    totals = [1000] * 10

    df = pd.DataFrame({
        "timestamp": dates,
        "good_events": goods,
        "total_events": totals,
    })

    res = calculate_timeseries_sli(df)
    assert res.total_events == 10000
    assert res.good_events == sum(goods)
    assert res.bad_events == 10000 - sum(goods)
    assert pytest.approx(res.sli_ratio, 1e-5) == sum(goods) / 10000.0


def test_calculate_timeseries_sli_with_bad_col():
    df = pd.DataFrame({
        "timestamp": ["2026-08-27 10:00:00", "2026-08-27 10:01:00"],
        "bad_events": [5, 10],
        "total_events": [1000, 2000],
    })
    res = calculate_timeseries_sli(df, good_col="non_existent", bad_col="bad_events")
    assert res.total_events == 3000
    assert res.bad_events == 15
    assert res.good_events == 2985


def test_calculate_timeseries_sli_empty_and_list():
    # Empty
    empty_res = calculate_timeseries_sli(pd.DataFrame())
    assert empty_res.total_events == 0

    # List of dicts
    data = [
        {"good_events": 50, "total_events": 50},
        {"good_events": 48, "total_events": 50},
    ]
    res_list = calculate_timeseries_sli(data)
    assert res_list.total_events == 100
    assert res_list.good_events == 98

    # List of SLIDataPoint
    dps = [
        SLIDataPoint(timestamp=1, good_events=10, total_events=10),
        SLIDataPoint(timestamp=2, good_events=8, total_events=10),
    ]
    res_dp = calculate_timeseries_sli(dps)
    assert res_dp.good_events == 18
    assert res_dp.total_events == 20


def test_calculate_windowed_sli():
    base_time = pd.Timestamp("2026-08-27 00:00:00")
    times = [base_time + pd.Timedelta(i, unit="m") for i in range(120)]
    goods = [99] * 120
    totals = [100] * 120

    df = pd.DataFrame({"timestamp": times, "good_events": goods, "total_events": totals})
    resampled = calculate_windowed_sli(df, window="1h")

    assert len(resampled) == 2
    assert resampled["total_events"].iloc[0] == 6000
    assert resampled["good_events"].iloc[0] == 5940
    assert pytest.approx(resampled["sli_ratio"].iloc[0], 1e-4) == 0.99
    assert pytest.approx(resampled["error_rate"].iloc[0], 1e-4) == 0.01


def test_sli_calculator_class_and_latencies():
    calc = SLICalculator(default_window="30D")
    res_evt = calc.from_events(good=995, total=1000)
    assert res_evt.good_events == 995

    # Test latency threshold
    latencies = [50.0, 120.0, 190.0, 210.0, 350.0]  # 3 <= 200ms, 2 > 200ms
    res_lat = calc.from_latencies(latencies, threshold_ms=200.0)
    assert res_lat.total_events == 5
    assert res_lat.good_events == 3
    assert res_lat.bad_events == 2
    assert pytest.approx(res_lat.sli_ratio, 1e-4) == 0.60
    assert res_lat.metadata["threshold_ms"] == 200.0

    # Empty latency list
    res_empty_lat = calc.from_latencies([], threshold_ms=200.0)
    assert res_empty_lat.total_events == 0

def test_sli_unsupported_type_and_missing_columns():
    with pytest.raises(TypeError, match="Unsupported data type"):
        calculate_timeseries_sli(12345)  # type: ignore

    df_missing = pd.DataFrame({"good_events": [10, 20]})
    with pytest.raises(KeyError, match="Missing required total column"):
        calculate_timeseries_sli(df_missing)

    df_no_good = pd.DataFrame({"total_events": [10, 20]})
    with pytest.raises(KeyError, match="must provide either good column"):
        calculate_timeseries_sli(df_no_good, good_col="non_existent")

    df_invalid_sum = pd.DataFrame({"good_events": [100, 200], "total_events": [50, 50]})
    with pytest.raises(ValueError, match="exceeds total events"):
        calculate_timeseries_sli(df_invalid_sum)

    # Empty windowed SLI
    empty_win = calculate_windowed_sli(pd.DataFrame(), window="1h")
    assert empty_win.empty


def test_sli_calculator_from_dataframe():
    calc = SLICalculator(default_window="30D")
    df = pd.DataFrame({"good_events": [990], "total_events": [1000]})
    res = calc.from_dataframe(df)
    assert res.good_events == 990
    assert res.total_events == 1000
