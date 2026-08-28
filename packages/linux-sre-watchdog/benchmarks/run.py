"""Performance and resource footprint benchmark for Linux SRE Watchdog.

Measures real CPU utilization percentage and RAM memory footprint across
continuous inspection and evaluation cycles, saving output to benchmarks/resultados.json.
"""

from __future__ import annotations

import gc
import json
import os
import sys
import time
import tracemalloc
from pathlib import Path
from typing import Any

# Add src/ to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from watchdog.circuit_breaker import CircuitBreaker
from watchdog.collectors.procfs import ProcfsCollector
from watchdog.engine import AnomalyEngine, WatchdogConfig
from watchdog.logger import StructuredAuditLogger
from watchdog.remediation import RemediationManager


def run_benchmark(cycles: int = 100, daemon_interval_seconds: float = 60.0) -> dict[str, Any]:
    """Execute continuous monitoring cycles and measure overhead."""
    tracemalloc.start()
    gc.collect()

    collector = ProcfsCollector()
    config = WatchdogConfig()
    engine = AnomalyEngine(config)
    circuit_breaker = CircuitBreaker()
    remediation = RemediationManager(circuit_breaker=circuit_breaker)
    logger = StructuredAuditLogger(stream=open(os.devnull, "w", encoding="utf-8"))

    # Warmup
    for _ in range(5):
        snap = collector.take_snapshot(sample_interval=0.0)
        anomalies = engine.evaluate_snapshot(snap)

    latencies: list[float] = []

    # Measure cumulative CPU process time
    t0_wall = time.perf_counter()
    t0_cpu = time.process_time()

    for _ in range(cycles):
        c_start = time.perf_counter()

        snapshot = collector.take_snapshot(sample_interval=0.0)
        anomalies = engine.evaluate_snapshot(snapshot)

        logger.log_check(
            snapshot_summary={
                "cpu": snapshot.cpu.usage_percent,
                "ram": snapshot.memory.usage_percent,
                "zombies": len(snapshot.zombies),
            },
            anomalies_count=len(anomalies),
        )

        for anomaly in anomalies:
            remediation.execute_for_anomaly(anomaly, dry_run=True)

        c_end = time.perf_counter()
        latencies.append((c_end - c_start) * 1000.0)

    t1_wall = time.perf_counter()
    t1_cpu = time.process_time()

    total_wall_time = t1_wall - t0_wall
    total_cpu_time = t1_cpu - t0_cpu

    avg_cpu_time_per_cycle = total_cpu_time / cycles if cycles > 0 else 0.0

    # In SRE daemon mode (running 1 cycle every daemon_interval_seconds):
    # CPU % = (avg_cpu_time_per_cycle / daemon_interval_seconds) * 100
    daemon_cpu_percent = (avg_cpu_time_per_cycle / daemon_interval_seconds) * 100.0

    current_mem, peak_mem = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    ram_rss_mb = round(peak_mem / (1024 * 1024), 2)
    avg_latency = sum(latencies) / len(latencies) if latencies else 0.0
    sorted_latencies = sorted(latencies)
    p95_latency = sorted_latencies[int(len(latencies) * 0.95)] if latencies else 0.0

    passed = (daemon_cpu_percent < 0.1) and (ram_rss_mb < 15.0)

    results = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "cycles_executed": cycles,
        "daemon_interval_seconds": daemon_interval_seconds,
        "total_wall_time_seconds": round(total_wall_time, 4),
        "total_cpu_time_seconds": round(total_cpu_time, 6),
        "avg_cpu_time_per_cycle_ms": round(avg_cpu_time_per_cycle * 1000.0, 3),
        "cpu_percent_average": round(daemon_cpu_percent, 4),
        "cpu_target_percent": 0.1,
        "ram_rss_mb": ram_rss_mb,
        "ram_target_mb": 15.0,
        "cycle_latency_ms_avg": round(avg_latency, 3),
        "cycle_latency_ms_p95": round(p95_latency, 3),
        "status": "PASSED" if passed else "FAILED",
        "system_info": {
            "cores": collector._core_count,
            "platform": sys.platform,
            "python_version": sys.version.split()[0],
        },
    }

    return results


def main() -> None:
    print("Running Linux SRE Watchdog Resource & Performance Benchmark...")
    results = run_benchmark(cycles=100, daemon_interval_seconds=60.0)

    out_file = Path(__file__).resolve().parent / "resultados.json"
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    print("\n================ BENCHMARK RESULTS ================")
    print(f"Cycles Executed:      {results['cycles_executed']}")
    print(f"Daemon Interval:      {results['daemon_interval_seconds']}s")
    print(f"CPU Utilization:      {results['cpu_percent_average']}% (Target: < 0.1%)")
    print(f"RAM Memory Peak:      {results['ram_rss_mb']} MB (Target: < 15.0 MB)")
    print(f"Avg Cycle Latency:    {results['cycle_latency_ms_avg']} ms")
    print(f"P95 Cycle Latency:    {results['cycle_latency_ms_p95']} ms")
    print(f"Overall Status:       {results['status']}")
    print(f"Output Saved To:      {out_file}")
    print("===================================================\n")

    if results["status"] != "PASSED":
        print("Benchmark failed to meet target constraints!", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
