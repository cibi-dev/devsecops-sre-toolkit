#!/usr/bin/env python3
"""
High-Performance Benchmark Suite for Reverse Proxy Limiter.

Measures throughput (requests/sec >= 2000 req/s) and added latency percentiles (p50, p90, p95, p99).
Generates benchmarks/resultados.json.
"""

import asyncio
import json
import os
import platform
import sys
import time
from typing import Dict, List

import httpx

# Add src to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))

from proxy.server import ProxyConfig, ProxyServer


async def run_full_proxy_benchmark(
    total_requests: int = 10000,
    concurrency: int = 50,
) -> Dict:
    """Execute high-speed async benchmark through the complete reverse proxy pipeline."""
    cfg = ProxyConfig(
        upstreams=["http://10.0.0.1:8080", "http://10.0.0.2:8080"],
        balancer_strategy="round_robin",
        rate_limit_rate=1_000_000.0,
        rate_limit_capacity=1_000_000.0,
        max_concurrency=50000,
        upstream_timeout=5.0,
        enable_security_headers=True,
        health_check_interval=0.0,
    )
    proxy = ProxyServer(cfg)

    # Fast mock upstream response
    mock_body = b'{"status":"ok","service":"upstream-api"}'
    mock_resp = httpx.Response(
        status_code=200,
        content=mock_body,
        headers={"content-type": "application/json", "x-upstream-id": "srv-1"},
    )
    proxy._http_client = httpx.AsyncClient(
        transport=httpx.MockTransport(lambda req: mock_resp),
        timeout=5.0,
        limits=httpx.Limits(max_connections=concurrency * 2, max_keepalive_connections=concurrency),
    )

    latencies: List[float] = []
    success_count = 0
    failure_count = 0

    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "GET",
        "scheme": "http",
        "path": "/api/v1/resource",
        "raw_path": b"/api/v1/resource",
        "query_string": b"id=123",
        "root_path": "",
        "headers": [
            (b"host", b"localhost:8000"),
            (b"x-api-key", b"bench_key_test"),
            (b"user-agent", b"Benchmark/1.0"),
            (b"accept", b"application/json"),
        ],
        "client": ("127.0.0.1", 54321),
        "server": ("127.0.0.1", 8000),
    }

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    reqs_per_worker = total_requests // concurrency

    async def worker():
        nonlocal success_count, failure_count
        for _ in range(reqs_per_worker):
            res_parts = []
            async def send(message):
                res_parts.append(message)

            t0 = time.perf_counter()
            try:
                await proxy(scope, receive, send)
                t1 = time.perf_counter()
                lat_ms = (t1 - t0) * 1000.0
                latencies.append(lat_ms)
                if res_parts and res_parts[0].get("status") == 200:
                    success_count += 1
                else:
                    failure_count += 1
            except Exception:
                failure_count += 1

    # Warmup phase (300 requests)
    async def noop_send(msg):
        pass

    for _ in range(300):
        await proxy(scope, receive, noop_send)

    latencies.clear()
    start_time = time.perf_counter()
    tasks = [asyncio.create_task(worker()) for _ in range(concurrency)]
    await asyncio.gather(*tasks)
    total_duration = time.perf_counter() - start_time

    await proxy.shutdown()

    latencies.sort()
    count = len(latencies)
    p50 = latencies[int(count * 0.50)] if count else 0.0
    p90 = latencies[int(count * 0.90)] if count else 0.0
    p95 = latencies[int(count * 0.95)] if count else 0.0
    p99 = latencies[int(count * 0.99)] if count else 0.0
    mean_lat = sum(latencies) / count if count else 0.0
    min_lat = latencies[0] if count else 0.0
    max_lat = latencies[-1] if count else 0.0

    rps = success_count / total_duration if total_duration > 0 else 0.0

    return {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "environment": {
            "os": platform.system(),
            "python": platform.python_version(),
            "cpu": platform.processor() or "x86_64",
        },
        "config": {
            "total_requests": total_requests,
            "concurrency": concurrency,
            "pipeline_features": [
                "Round-Robin Load Balancing",
                "Token Bucket Rate Limiting",
                "3-State Circuit Breaker Protection",
                "Canonical Security Headers Injection",
                "OpenMetrics / Prometheus Telemetry Tracking",
                "CWE-400 Concurrency & Byte Size Enforcement",
            ],
        },
        "metrics": {
            "successful_requests": success_count,
            "failed_requests": failure_count,
            "duration_seconds": round(total_duration, 4),
            "throughput_rps": round(rps, 2),
            "target_met": rps >= 2000.0,
            "latency_ms": {
                "min": round(min_lat, 2),
                "mean": round(mean_lat, 2),
                "p50": round(p50, 2),
                "p90": round(p90, 2),
                "p95": round(p95, 2),
                "p99": round(p99, 2),
                "max": round(max_lat, 2),
            },
        },
    }


async def main_async():
    print("================================================================")
    print("🚀 REVERSE PROXY LIMITER — ENTERPRISE BENCHMARK RUNNER")
    print("================================================================")

    total_reqs = 10000
    concurrency = 50
    print(f"⚡ Executing load test: {total_reqs} requests (concurrency={concurrency})...\n")

    results = await run_full_proxy_benchmark(total_requests=total_reqs, concurrency=concurrency)

    output_path = os.path.join(os.path.dirname(__file__), "resultados.json")
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    m = results["metrics"]
    l = m["latency_ms"]

    print("----------------------------------------------------------------")
    print("📊 BENCHMARK RESULTS SUMMARY:")
    print("----------------------------------------------------------------")
    print(f"  • Total Requests    : {results['config']['total_requests']}")
    print(f"  • Concurrency       : {results['config']['concurrency']}")
    print(f"  • Successful        : {m['successful_requests']}")
    print(f"  • Failed            : {m['failed_requests']}")
    print(f"  • Duration          : {m['duration_seconds']} s")
    print(f"  • Throughput        : {m['throughput_rps']} req/s (Target: >=2000 req/s)")
    print(f"  • Latency Min       : {l['min']} ms")
    print(f"  • Latency Mean      : {l['mean']} ms")
    print(f"  • Latency p50       : {l['p50']} ms")
    print(f"  • Latency p90       : {l['p90']} ms")
    print(f"  • Latency p95       : {l['p95']} ms")
    print(f"  • Latency p99       : {l['p99']} ms")
    print(f"  • Latency Max       : {l['max']} ms")
    print(f"  • Status            : {'PASSED (>= 2000 req/s)' if m['throughput_rps'] >= 2000 else 'FAILED'}")
    print("----------------------------------------------------------------")
    print(f"💾 Results successfully written to: {output_path}\n")


if __name__ == "__main__":
    asyncio.run(main_async())
