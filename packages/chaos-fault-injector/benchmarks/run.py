"""Benchmark runner for chaos-fault-injector engine.

Measures activation latency, atomic rollback latency, CPU stress lifecycle,
dead-man switch overhead, and resilience report generation.
Outputs results to benchmarks/resultados.json.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import time
from typing import Any, Dict, List

# Ensure src is in sys.path when running script directly
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))

from chaos.cpu_stress import CpuStressConfig, CpuStressInjector

from chaos.network import NetworkFaultConfig, inject_network_fault, revert_network_fault
from chaos.reporter import (
    ExperimentPhase,
    ResilienceTracker,
    calculate_percentiles,
    generate_markdown_report,
)
from chaos.safety_guard import SafetyGuard


def measure_latencies(func: Any, iterations: int = 50) -> Dict[str, float]:
    """Execute function multiple times and compute latency stats in milliseconds."""
    durations_ms: List[float] = []
    for _ in range(iterations):
        start = time.perf_counter()
        func()
        elapsed_ms = (time.perf_counter() - start) * 1000.0
        durations_ms.append(elapsed_ms)

    p50, p95, p99 = calculate_percentiles(durations_ms)
    return {
        "avg_ms": round(sum(durations_ms) / len(durations_ms), 4),
        "min_ms": round(min(durations_ms), 4),
        "max_ms": round(max(durations_ms), 4),
        "p50_ms": p50,
        "p95_ms": p95,
        "p99_ms": p99,
        "iterations": iterations,
    }


def run_all_benchmarks() -> Dict[str, Any]:
    """Execute all benchmark suites."""
    print("=" * 60)
    print("    🚀 RUNNING CHAOS FAULT INJECTOR BENCHMARKS")
    print("=" * 60)

    results: Dict[str, Any] = {}

    # 1. Network Fault Injection Activation (Dry-Run)
    net_config = NetworkFaultConfig(
        interface="eth0",
        latency_ms=50.0,
        jitter_ms=10.0,
        loss_pct=2.0,
        dry_run=True,
    )

    def bench_net_activation() -> None:
        inject_network_fault(net_config)

    print("[*] Benchmarking Network Fault Activation (dry-run)...")
    results["network_fault_injection_activation_ms"] = measure_latencies(bench_net_activation, iterations=100)

    # 2. Network Fault Rollback (Dry-Run)
    def bench_net_rollback() -> None:
        revert_network_fault("eth0", dry_run=True)

    print("[*] Benchmarking Network Fault Rollback (dry-run)...")
    results["network_fault_rollback_ms"] = measure_latencies(bench_net_rollback, iterations=100)

    # 3. CPU Stress Activation & Stop Latency
    cpu_config = CpuStressConfig(cores=2, load_percentage=50.0, duration_seconds=1.0, dry_run=True)

    def bench_cpu_activation() -> None:
        inj = CpuStressInjector(cpu_config)
        inj.start()
        inj.stop()

    print("[*] Benchmarking CPU Stress Worker Lifecycle...")
    results["cpu_stress_lifecycle_ms"] = measure_latencies(bench_cpu_activation, iterations=50)

    # 4. Dead-Man Switch Activation & Disarm Overhead
    temp_dir = tempfile.mkdtemp()
    lock_path = os.path.join(temp_dir, "bench.lock")

    def bench_dead_man_overhead() -> None:
        with SafetyGuard(lock_file_path=lock_path, auto_lock=False) as guard:
            guard.start_dead_man(timeout_seconds=5.0)
            guard.heartbeat()
            guard.stop_dead_man()

    print("[*] Benchmarking Dead-Man Switch Guard Overhead...")
    results["dead_man_switch_overhead_ms"] = measure_latencies(bench_dead_man_overhead, iterations=50)

    # 5. Atomic Rollback Stack Execution (10 callbacks)
    def bench_atomic_rollback_stack() -> None:
        with SafetyGuard(lock_file_path=lock_path, auto_lock=False) as guard:
            for i in range(10):
                guard.register_rollback(lambda: None, f"Action {i}")
            guard.rollback_all()

    print("[*] Benchmarking Atomic Rollback Stack (10 steps)...")
    results["atomic_rollback_10_steps_ms"] = measure_latencies(bench_atomic_rollback_stack, iterations=100)

    # 6. Resilience Report Generation
    def bench_report_generation() -> None:
        tracker = ResilienceTracker("bench-exp", "network", {"loss": 5.0})
        tracker.set_phase(ExperimentPhase.PRE_FAULT)
        for lat in (10.0, 11.0, 12.0, 10.5):
            tracker.record(lat, True, 10.0, 30.0)
        tracker.set_phase(ExperimentPhase.DURING_FAULT)
        for lat in (50.0, 55.0, 60.0, 52.0):
            tracker.record(lat, True, 70.0, 35.0)
        tracker.set_phase(ExperimentPhase.POST_FAULT)
        for lat in (10.2, 10.8, 11.0, 10.4):
            tracker.record(lat, True, 11.0, 30.0)
        rep = tracker.finalize(1.0, 2.0, 1.0, 0.1)
        _ = generate_markdown_report(rep)

    print("[*] Benchmarking Resilience Report Generation...")
    results["resilience_report_generation_ms"] = measure_latencies(bench_report_generation, iterations=50)

    # Summary Display
    print("\n" + "=" * 60)
    print(f"{'Benchmark Metric':<40} | {'Avg (ms)':<10} | {'p95 (ms)':<10}")
    print("-" * 60)
    for name, data in results.items():
        print(f"{name:<40} | {data['avg_ms']:<10.4f} | {data['p95_ms']:<10.4f}")
    print("=" * 60)

    # Clean lock temp
    try:
        if os.path.exists(lock_path):
            os.unlink(lock_path)
        os.rmdir(temp_dir)
    except OSError:
        pass

    return results


def main() -> None:
    bench_dir = os.path.dirname(os.path.abspath(__file__))
    out_file = os.path.join(bench_dir, "resultados.json")

    results = run_all_benchmarks()

    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    print(f"\n[+] Benchmark results saved to {out_file}")


if __name__ == "__main__":
    main()
