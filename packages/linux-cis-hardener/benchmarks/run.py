#!/usr/bin/env python3
"""Benchmark suite measuring execution latency, memory footprint, and rule audit throughput."""

from __future__ import annotations

import json
import os
import resource
import statistics
import sys
import time
from typing import Any

# Ensure src/ is on pythonpath
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

from cis.scanner import CISScanner


def get_memory_usage_mb() -> float:
    """Return max RSS memory in Megabytes."""
    rusage = resource.getrusage(resource.RUSAGE_SELF)
    return rusage.ru_maxrss / 1024.0


def run_benchmark(iterations: int = 50) -> dict[str, Any]:
    """Execute CIS Level 1 benchmark audit across multiple iterations."""
    scanner = CISScanner(suppress_root_warning=True)

    latencies_ms: list[float] = []
    rule_latencies_ms: list[float] = []

    # Warmup
    for _ in range(3):
        scanner.audit()

    initial_mem = get_memory_usage_mb()

    start_total = time.perf_counter()
    report = scanner.audit()
    for _ in range(iterations):
        t0 = time.perf_counter()
        report = scanner.audit()
        t1 = time.perf_counter()
        elapsed_ms = (t1 - t0) * 1000.0
        latencies_ms.append(elapsed_ms)
        rule_latencies_ms.append(elapsed_ms / max(1, report.total_rules))

    total_time_s = time.perf_counter() - start_total
    peak_mem = get_memory_usage_mb()

    sorted_latencies = sorted(latencies_ms)
    p50 = statistics.median(sorted_latencies)
    p95 = sorted_latencies[int(len(sorted_latencies) * 0.95)]
    p99 = sorted_latencies[int(len(sorted_latencies) * 0.99)]

    total_rule_evaluations = iterations * report.total_rules
    throughput_rules_per_sec = total_rule_evaluations / total_time_s

    results = {
        "benchmark_name": "linux-cis-hardener-audit-latency",
        "iterations": iterations,
        "total_rules_evaluated_per_run": report.total_rules,
        "total_rule_evaluations": total_rule_evaluations,
        "total_execution_time_seconds": round(total_time_s, 4),
        "mean_audit_latency_ms": round(statistics.mean(latencies_ms), 3),
        "std_dev_ms": round(statistics.stdev(latencies_ms), 3) if len(latencies_ms) > 1 else 0.0,
        "p50_latency_ms": round(p50, 3),
        "p95_latency_ms": round(p95, 3),
        "p99_latency_ms": round(p99, 3),
        "min_latency_ms": round(min(latencies_ms), 3),
        "max_latency_ms": round(max(latencies_ms), 3),
        "avg_latency_per_rule_ms": round(statistics.mean(rule_latencies_ms), 4),
        "throughput_rules_per_second": round(throughput_rules_per_sec, 2),
        "initial_rss_memory_mb": round(initial_mem, 2),
        "peak_rss_memory_mb": round(peak_mem, 2),
        "status": "PASSED",
    }

    return results


def main() -> None:
    print("Running CIS Hardener Audit Performance Benchmark...")
    results = run_benchmark(iterations=50)

    out_path = os.path.join(os.path.dirname(__file__), "resultados.json")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    print(f"Benchmark completed successfully! Results written to {out_path}")
    print(f" • Total Rules:       {results['total_rules_evaluated_per_run']}")
    print(f" • Mean Latency:      {results['mean_audit_latency_ms']} ms")
    print(f" • P95 Latency:       {results['p95_latency_ms']} ms")
    print(f" • Throughput:        {results['throughput_rules_per_second']} rules/sec")
    print(f" • Peak Memory:       {results['peak_rss_memory_mb']} MB")


if __name__ == "__main__":
    main()
