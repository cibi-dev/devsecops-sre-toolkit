#!/usr/bin/env python3
"""High-performance quantitative benchmarking suite for slo-burnrate-engine.

Measures calculation throughput, memory footprints, and latency across
10K, 100K, 1M, and 5M synthetic SRE events/datapoints.
"""

from __future__ import annotations

import json
import os
import platform
import sys
import time
import tracemalloc
from datetime import datetime, timezone
import numpy as np
import pandas as pd

# Add src to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))

from slo.burn_rate import BurnRateCalculator, calculate_burn_rate
from slo.error_budget import ErrorBudgetManager, SLODefinition
from slo.multi_window import MultiWindowAlertEngine, get_standard_google_sre_tiers
from slo.sli_calculator import calculate_event_sli, calculate_timeseries_sli


def benchmark_event_sli(iterations: int = 100_000) -> dict[str, float]:
    """Measure single-event scalar SLI calculation speed."""
    start = time.perf_counter()
    for _ in range(iterations):
        calculate_event_sli(999, 1000)
    duration = time.perf_counter() - start
    ops_per_sec = iterations / duration
    latency_us = (duration / iterations) * 1_000_000

    return {
        "iterations": iterations,
        "duration_seconds": round(duration, 4),
        "ops_per_second": round(ops_per_sec, 2),
        "avg_latency_us": round(latency_us, 4),
    }


def benchmark_dataframe_vectorized(event_counts: list[int]) -> list[dict[str, Any]]:
    """Benchmark vectorized timeseries SLI computation across various batch sizes."""
    results = []
    slo_def = SLODefinition(name="benchmark-slo", service="bench-service", target=0.999)
    eb_mgr = ErrorBudgetManager(slo_def)

    for n_events in event_counts:
        # Generate synthetic event stream
        rng = np.random.default_rng(42)
        totals = rng.integers(100, 1000, size=n_events, dtype=np.int64)
        errors = rng.binomial(totals, 0.001)
        goods = totals - errors

        df = pd.DataFrame({"good_events": goods, "total_events": totals})

        tracemalloc.start()
        start = time.perf_counter()

        # Compute SLI and error budget
        sli_res = calculate_timeseries_sli(df)
        eb_res = eb_mgr.calculate_from_sli(sli_res)

        duration = time.perf_counter() - start
        current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        total_requests_processed = int(np.sum(totals))
        events_per_sec = total_requests_processed / duration

        results.append({
            "rows_count": n_events,
            "total_requests_evaluated": total_requests_processed,
            "duration_seconds": round(duration, 4),
            "throughput_events_per_sec": round(events_per_sec, 2),
            "peak_memory_mb": round(peak / (1024 * 1024), 2),
            "sli_ratio": round(sli_res.sli_ratio, 6),
            "budget_consumed_percent": round(eb_res.consumed_budget_percent, 2),
        })

    return results


def benchmark_multi_window_engine(iterations: int = 25_000) -> dict[str, float]:
    """Measure Multi-Window Alert Engine evaluation throughput."""
    slo_def = SLODefinition(name="bench-slo", service="bench-service", target=0.999)
    engine = MultiWindowAlertEngine(slo_def)
    rates = {"1h": 14.5, "5m": 15.0, "6h": 5.8, "30m": 5.9, "24h": 2.5, "2h": 2.6, "72h": 0.8, "6h": 0.8}

    start = time.perf_counter()
    for _ in range(iterations):
        engine.evaluate_from_burn_rates(rates)
    duration = time.perf_counter() - start
    ops_per_sec = iterations / duration
    latency_us = (duration / iterations) * 1_000_000

    return {
        "iterations": iterations,
        "duration_seconds": round(duration, 4),
        "evaluations_per_second": round(ops_per_sec, 2),
        "avg_latency_us": round(latency_us, 4),
    }


def run_all_benchmarks() -> dict[str, Any]:
    """Execute complete benchmark suite and persist results."""
    print("=" * 65)
    print("🚀 Running Quantitative Benchmarks for slo-burnrate-engine")
    print("=" * 65)

    print("1. Benchmarking Event-level SLI Calculation...")
    event_sli_metrics = benchmark_event_sli(iterations=100_000)
    print(f"   ✓ {event_sli_metrics['ops_per_second']:,.0f} ops/sec ({event_sli_metrics['avg_latency_us']:.3f} µs/op)")

    print("2. Benchmarking Vectorized Time-Series Datasets (10K -> 5M events)...")
    dataset_sizes = [10_000, 100_000, 1_000_000, 5_000_000]
    vectorized_metrics = benchmark_dataframe_vectorized(dataset_sizes)
    for m in vectorized_metrics:
        print(
            f"   ✓ Rows: {m['rows_count']:,} | Requests: {m['total_requests_evaluated']:,} | "
            f"Throughput: {m['throughput_events_per_sec']:,.0f} req/s | Time: {m['duration_seconds']:.4f}s | "
            f"Peak Mem: {m['peak_memory_mb']:.2f} MB"
        )

    print("3. Benchmarking Multi-Window Multi-Burn-Rate Alert Engine...")
    mw_metrics = benchmark_multi_window_engine(iterations=25_000)
    print(f"   ✓ {mw_metrics['evaluations_per_second']:,.0f} eval/sec ({mw_metrics['avg_latency_us']:.3f} µs/eval)")

    results: dict[str, Any] = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "platform": {
            "python_version": platform.python_version(),
            "system": platform.system(),
            "processor": platform.processor() or "x86_64",
        },
        "scalar_sli_benchmark": event_sli_metrics,
        "vectorized_timeseries_benchmark": vectorized_metrics,
        "multi_window_alert_benchmark": mw_metrics,
    }

    out_path = os.path.join(os.path.dirname(__file__), "resultados.json")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    print(f"\n✅ Benchmark results successfully recorded in: {out_path}")
    return results


if __name__ == "__main__":
    run_all_benchmarks()
