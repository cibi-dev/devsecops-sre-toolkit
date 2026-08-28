"""Benchmark execution script for blue-green-deployer.

Measures latency of:
- Atomic symlink traffic switching (ms)
- Concurrency flock mutex acquisition/release (ms)
- Deterministic rollback execution (ms, validating <30s SLA)
- Active HTTP health probing (ms)
- Full deployment cycle orchestration (ms)

Saves detailed metrics to benchmarks/resultados.json.
"""

from __future__ import annotations

import json
import os
import platform
import statistics
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, List
from unittest.mock import MagicMock, patch

import httpx

from deployer.config import (
    DeployerConfig,
    EnvironmentSlot,
    HealthCheckConfig,
    LockConfig,
    RollbackConfig,
    RouterConfig,
    TargetEnvironmentConfig,
)
from deployer.engine import DeployEngine
from deployer.health import HealthChecker
from deployer.lock import DeploymentLock
from deployer.rollback import RollbackManager
from deployer.router import TrafficRouter


def benchmark_atomic_symlink_switch(iterations: int = 1000) -> Dict[str, Any]:
    """Measure atomic symlink replacement latency using POSIX os.replace."""
    with tempfile.TemporaryDirectory() as tmp_dir_str:
        tmp_dir = Path(tmp_dir_str)
        symlink_path = tmp_dir / "active.conf"
        target_blue = tmp_dir / "upstream_blue.conf"
        target_green = tmp_dir / "upstream_green.conf"

        target_blue.write_text("server 127.0.0.1:8081;\n", encoding="utf-8")
        target_green.write_text("server 127.0.0.1:8082;\n", encoding="utf-8")

        router_cfg = RouterConfig(
            symlink_path=symlink_path,
            backup_dir=tmp_dir / "backups",
            enable_proxy_reload=False,
        )
        router = TrafficRouter(config=router_cfg, allow_unprivileged=True)

        durations_ms: List[float] = []

        for i in range(iterations):
            target = target_green if i % 2 == 0 else target_blue
            slot = EnvironmentSlot.GREEN if i % 2 == 0 else EnvironmentSlot.BLUE

            t0 = time.perf_counter()
            res = router.switch_to_target(target_slot=slot, target_config_path=target, validate_proxy=False)
            t1 = time.perf_counter()

            if not res.success:
                raise RuntimeError(f"Switch failed during benchmark: {res.error_message}")

            durations_ms.append((t1 - t0) * 1000.0)

        return {
            "iterations": iterations,
            "mean_ms": round(statistics.mean(durations_ms), 4),
            "median_ms": round(statistics.median(durations_ms), 4),
            "p95_ms": round(statistics.quantiles(durations_ms, n=20)[18], 4),
            "p99_ms": round(statistics.quantiles(durations_ms, n=100)[98], 4),
            "min_ms": round(min(durations_ms), 4),
            "max_ms": round(max(durations_ms), 4),
            "ops_per_second": round(iterations / (sum(durations_ms) / 1000.0), 2),
        }


def benchmark_lock_acquire_release(iterations: int = 500) -> Dict[str, Any]:
    """Measure flock concurrency lock acquisition and release overhead."""
    with tempfile.TemporaryDirectory() as tmp_dir_str:
        lock_file = Path(tmp_dir_str) / "bench.lock"
        durations_ms: List[float] = []

        for _ in range(iterations):
            lock = DeploymentLock(lock_path=lock_file, timeout_seconds=1.0)
            t0 = time.perf_counter()
            with lock:
                pass
            t1 = time.perf_counter()
            durations_ms.append((t1 - t0) * 1000.0)

        return {
            "iterations": iterations,
            "mean_ms": round(statistics.mean(durations_ms), 4),
            "median_ms": round(statistics.median(durations_ms), 4),
            "p95_ms": round(statistics.quantiles(durations_ms, n=20)[18], 4),
            "min_ms": round(min(durations_ms), 4),
            "max_ms": round(max(durations_ms), 4),
        }


def benchmark_rollback_execution(iterations: int = 200) -> Dict[str, Any]:
    """Measure deterministic rollback execution latency to ensure compliance with <30s SLA."""
    with tempfile.TemporaryDirectory() as tmp_dir_str:
        tmp_dir = Path(tmp_dir_str)
        blue_conf = tmp_dir / "upstream_blue.conf"
        green_conf = tmp_dir / "upstream_green.conf"
        blue_conf.write_text("blue", encoding="utf-8")
        green_conf.write_text("green", encoding="utf-8")

        deployer_cfg = DeployerConfig(
            blue=TargetEnvironmentConfig(name=EnvironmentSlot.BLUE, host="127.0.0.1", port=8081, config_path=blue_conf),
            green=TargetEnvironmentConfig(name=EnvironmentSlot.GREEN, host="127.0.0.1", port=8082, config_path=green_conf),
            router=RouterConfig(symlink_path=tmp_dir / "active.conf", backup_dir=tmp_dir / "backups", enable_proxy_reload=False),
            rollback=RollbackConfig(max_rollback_timeout_seconds=30.0),
            allow_unprivileged=True,
        )

        manager = RollbackManager(deployer_config=deployer_cfg)
        mock_resp = httpx.Response(200, text="OK", request=httpx.Request("GET", deployer_cfg.blue.url))

        durations_ms: List[float] = []

        with patch.object(httpx.Client, "get", return_value=mock_resp):
            for i in range(iterations):
                failed_slot = EnvironmentSlot.GREEN if i % 2 == 0 else EnvironmentSlot.BLUE
                res = manager.execute_rollback(
                    failed_slot=failed_slot,
                    reason="Benchmark test trigger",
                    verify_health_after_rollback=True,
                )
                if not res.success:
                    raise RuntimeError(f"Rollback failed: {res.error_message}")
                durations_ms.append(res.rollback_duration_ms)

        sla_limit_ms = 30000.0
        sla_compliant = all(d < sla_limit_ms for d in durations_ms)

        return {
            "iterations": iterations,
            "mean_ms": round(statistics.mean(durations_ms), 4),
            "median_ms": round(statistics.median(durations_ms), 4),
            "p95_ms": round(statistics.quantiles(durations_ms, n=20)[18], 4),
            "p99_ms": round(statistics.quantiles(durations_ms, n=100)[98], 4),
            "max_ms": round(max(durations_ms), 4),
            "sla_limit_seconds": 30.0,
            "sla_compliant": sla_compliant,
        }


def benchmark_full_deploy_cycle(iterations: int = 100) -> Dict[str, Any]:
    """Measure full end-to-end Blue/Green deployment cycle."""
    with tempfile.TemporaryDirectory() as tmp_dir_str:
        tmp_dir = Path(tmp_dir_str)
        blue_conf = tmp_dir / "upstream_blue.conf"
        green_conf = tmp_dir / "upstream_green.conf"
        blue_conf.write_text("blue", encoding="utf-8")
        green_conf.write_text("green", encoding="utf-8")

        deployer_cfg = DeployerConfig(
            blue=TargetEnvironmentConfig(name=EnvironmentSlot.BLUE, host="127.0.0.1", port=8081, config_path=blue_conf),
            green=TargetEnvironmentConfig(name=EnvironmentSlot.GREEN, host="127.0.0.1", port=8082, config_path=green_conf),
            health=HealthCheckConfig(max_retries=1, retry_interval_seconds=0.01, consecutive_successes_required=1),
            router=RouterConfig(symlink_path=tmp_dir / "active.conf", backup_dir=tmp_dir / "backups", enable_proxy_reload=False),
            rollback=RollbackConfig(post_switch_health_checks=1, post_switch_interval_seconds=0.01),
            lock=LockConfig(lock_file_path=tmp_dir / "deploy.lock", lock_timeout_seconds=2.0),
            state_file=tmp_dir / "state.json",
            allow_unprivileged=True,
        )

        engine = DeployEngine(config=deployer_cfg)
        mock_resp = httpx.Response(200, text="OK", request=httpx.Request("GET", "http://127.0.0.1:8082/health"))

        durations_ms: List[float] = []

        with patch.object(httpx.Client, "get", return_value=mock_resp):
            for i in range(iterations):
                target = EnvironmentSlot.GREEN if i % 2 == 0 else EnvironmentSlot.BLUE
                res = engine.deploy(target_slot=target)
                if not res.success:
                    raise RuntimeError(f"Deploy cycle failed: {res.message}")
                durations_ms.append(res.total_duration_ms)

        return {
            "iterations": iterations,
            "mean_ms": round(statistics.mean(durations_ms), 4),
            "median_ms": round(statistics.median(durations_ms), 4),
            "p95_ms": round(statistics.quantiles(durations_ms, n=20)[18], 4),
            "min_ms": round(min(durations_ms), 4),
            "max_ms": round(max(durations_ms), 4),
        }


def run_all_benchmarks() -> Dict[str, Any]:
    """Execute complete benchmark suite and collect metadata."""
    print("==========================================================")
    print("      BLUE-GREEN-DEPLOYER PERFORMANCE BENCHMARKS          ")
    print("==========================================================")
    print(f"OS/Platform   : {platform.system()} {platform.release()} ({platform.machine()})")
    print(f"Python Version: {platform.python_version()}")
    print("----------------------------------------------------------")

    print("[1/4] Benchmarking Atomic Symlink Traffic Switch...")
    symlink_results = benchmark_atomic_symlink_switch(iterations=1000)
    print(f"      Mean Latency: {symlink_results['mean_ms']:.3f} ms | P95: {symlink_results['p95_ms']:.3f} ms | Ops/sec: {symlink_results['ops_per_second']}")

    print("[2/4] Benchmarking Concurrency Flock Mutex Lock...")
    lock_results = benchmark_lock_acquire_release(iterations=500)
    print(f"      Mean Latency: {lock_results['mean_ms']:.3f} ms | P95: {lock_results['p95_ms']:.3f} ms")

    print("[3/4] Benchmarking Deterministic Auto-Rollback (<30s SLA)...")
    rollback_results = benchmark_rollback_execution(iterations=200)
    sla_str = "PASSED (<30s SLA)" if rollback_results["sla_compliant"] else "FAILED"
    print(f"      Mean Latency: {rollback_results['mean_ms']:.3f} ms | P99: {rollback_results['p99_ms']:.3f} ms | SLA: {sla_str}")

    print("[4/4] Benchmarking Full Blue/Green Deployment Cycle...")
    deploy_results = benchmark_full_deploy_cycle(iterations=100)
    print(f"      Mean Latency: {deploy_results['mean_ms']:.3f} ms | P95: {deploy_results['p95_ms']:.3f} ms")

    print("==========================================================")
    print("                  BENCHMARK COMPLETE                      ")
    print("==========================================================")

    output = {
        "timestamp": time.time(),
        "timestamp_iso": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "system": {
            "os": platform.system(),
            "release": platform.release(),
            "machine": platform.machine(),
            "python_version": platform.python_version(),
            "cpu_count": os.cpu_count(),
        },
        "benchmarks": {
            "atomic_symlink_switch": symlink_results,
            "concurrency_lock": lock_results,
            "auto_rollback": rollback_results,
            "full_deployment_cycle": deploy_results,
        },
    }

    out_file = Path(__file__).resolve().parent / "resultados.json"
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2)

    print(f"Results successfully written to: {out_file}")
    return output


if __name__ == "__main__":
    run_all_benchmarks()
