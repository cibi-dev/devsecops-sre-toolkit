"""Performance and throughput benchmark suite for prometheus-metrics-exporter.

Measures:
1. Native host metrics collection latency (/proc read + parse)
2. OpenMetrics text formatting latency
3. Alert rules evaluation throughput
4. HTTP /metrics endpoint scraping throughput (requests/second)
"""

from __future__ import annotations

import json
import socket
import statistics
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, Dict, List

# Ensure src/ is in sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

import httpx

from exporter.alert_evaluator import AlertEvaluator, AlertRuleModel
from exporter.formatter import OpenMetricsFormatter
from exporter.http_server import MetricsHTTPServer
from exporter.metrics_collector import MetricsCollector


def get_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def compute_stats(latencies_ms: List[float]) -> Dict[str, float]:
    """Calculates mean, min, max, p50, p95, and p99 percentiles."""
    if not latencies_ms:
        return {"mean": 0.0, "min": 0.0, "max": 0.0, "p50": 0.0, "p95": 0.0, "p99": 0.0}

    sorted_vals = sorted(latencies_ms)
    n = len(sorted_vals)

    def percentile(p: float) -> float:
        idx = int(p * n)
        return sorted_vals[min(idx, n - 1)]

    return {
        "mean_ms": round(statistics.mean(sorted_vals), 4),
        "min_ms": round(min(sorted_vals), 4),
        "max_ms": round(max(sorted_vals), 4),
        "p50_ms": round(percentile(0.50), 4),
        "p95_ms": round(percentile(0.95), 4),
        "p99_ms": round(percentile(0.99), 4),
    }


def benchmark_collector(iterations: int = 1000) -> Dict[str, Any]:
    print(f"[*] Benchmarking host metrics collection ({iterations} iterations)...")
    collector = MetricsCollector()
    latencies: List[float] = []

    for _ in range(iterations):
        t0 = time.perf_counter()
        fams = collector.collect_all()
        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        latencies.append(elapsed_ms)

    stats = compute_stats(latencies)
    stats["iterations"] = iterations
    stats["samples_per_scrape"] = sum(len(f.samples) for f in fams)
    return stats


def benchmark_formatter(iterations: int = 1000) -> Dict[str, Any]:
    print(f"[*] Benchmarking OpenMetrics formatter ({iterations} iterations)...")
    collector = MetricsCollector()
    families = collector.collect_all()
    latencies: List[float] = []

    for _ in range(iterations):
        t0 = time.perf_counter()
        formatted = OpenMetricsFormatter.format_openmetrics(families)
        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        latencies.append(elapsed_ms)

    stats = compute_stats(latencies)
    stats["iterations"] = iterations
    stats["output_size_bytes"] = len(formatted.encode("utf-8"))
    return stats


def benchmark_alert_evaluator(iterations: int = 1000) -> Dict[str, Any]:
    print(f"[*] Benchmarking Alert Evaluator ({iterations} iterations)...")
    evaluator = AlertEvaluator()
    for i in range(20):
        evaluator.add_rule(
            AlertRuleModel(
                alert=f"Rule_{i}",
                expr=f"node_cpu_usage_percent > {80 + i % 15}",
                for_duration="10s",
                severity="warning",
            )
        )

    collector = MetricsCollector()
    metrics = collector.collect_as_dict()
    latencies: List[float] = []

    for i in range(iterations):
        t0 = time.perf_counter()
        evaluator.evaluate(metrics, current_time=1000.0 + i)
        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        latencies.append(elapsed_ms)

    stats = compute_stats(latencies)
    stats["iterations"] = iterations
    stats["rules_evaluated_count"] = len(evaluator.alert_instances)
    return stats


def benchmark_http_throughput(duration_seconds: float = 3.0, concurrency: int = 8) -> Dict[str, Any]:
    print(f"[*] Benchmarking HTTP /metrics endpoint throughput ({concurrency} workers, {duration_seconds}s)...")
    port = get_free_port()
    collector = MetricsCollector()
    server = MetricsHTTPServer(host="127.0.0.1", port=port, collector=collector)
    server.start(background=True)
    time.sleep(0.2)

    url = f"http://127.0.0.1:{port}/metrics"
    total_requests = 0
    latencies: List[float] = []

    def worker() -> List[float]:
        local_latencies: List[float] = []
        with httpx.Client(timeout=10.0) as client:
            end_time = time.time() + duration_seconds
            while time.time() < end_time:
                t0 = time.perf_counter()
                try:
                    resp = client.get(url)
                    if resp.status_code == 200:
                        elapsed_ms = (time.perf_counter() - t0) * 1000.0
                        local_latencies.append(elapsed_ms)
                except Exception:
                    pass
        return local_latencies

    with ThreadPoolExecutor(max_workers=concurrency) as executor:
        futures = [executor.submit(worker) for _ in range(concurrency)]
        for f in futures:
            latencies.extend(f.result())

    server.stop()
    total_requests = len(latencies)
    rps = total_requests / duration_seconds if duration_seconds > 0 else 0.0

    stats = compute_stats(latencies)
    stats["total_requests"] = total_requests
    stats["duration_seconds"] = duration_seconds
    stats["concurrency"] = concurrency
    stats["requests_per_second"] = round(rps, 2)
    return stats


def main() -> int:
    print("=" * 60)
    print("🚀 Prometheus Metrics Exporter — Benchmark Suite")
    print("=" * 60)

    results: Dict[str, Any] = {
        "timestamp": time.time(),
        "date_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "collector_benchmark": benchmark_collector(1000),
        "formatter_benchmark": benchmark_formatter(1000),
        "alert_evaluator_benchmark": benchmark_alert_evaluator(1000),
        "http_server_throughput": benchmark_http_throughput(duration_seconds=3.0, concurrency=8),
    }

    # Print summary table
    print("\n" + "=" * 60)
    print("📊 BENCHMARK RESULTS SUMMARY")
    print("=" * 60)
    print(f"1. Metrics Collection Latency (mean): {results['collector_benchmark']['mean_ms']:.4f} ms")
    print(f"   p50: {results['collector_benchmark']['p50_ms']} ms | p95: {results['collector_benchmark']['p95_ms']} ms | p99: {results['collector_benchmark']['p99_ms']} ms")
    print(f"2. OpenMetrics Format Latency (mean): {results['formatter_benchmark']['mean_ms']:.4f} ms")
    print(f"   p50: {results['formatter_benchmark']['p50_ms']} ms | p95: {results['formatter_benchmark']['p95_ms']} ms | p99: {results['formatter_benchmark']['p99_ms']} ms")
    print(f"3. Alert Rules Evaluation (mean):     {results['alert_evaluator_benchmark']['mean_ms']:.4f} ms (20 rules)")
    print(f"4. HTTP Scraping Throughput:          {results['http_server_throughput']['requests_per_second']} req/s")
    print(f"   p50: {results['http_server_throughput']['p50_ms']} ms | p95: {results['http_server_throughput']['p95_ms']} ms | p99: {results['http_server_throughput']['p99_ms']} ms")
    print("=" * 60)

    output_path = Path(__file__).parent / "resultados.json"
    output_path.write_text(json.dumps(results, indent=2), encoding="utf-8")
    print(f"\n[+] Results saved to {output_path.resolve()}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
