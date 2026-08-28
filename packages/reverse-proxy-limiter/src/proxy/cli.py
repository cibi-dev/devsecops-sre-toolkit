"""
Command Line Interface (CLI) for Reverse Proxy Limiter.

Subcommands:
- start: Launch high-performance async reverse proxy ASGI server
- test-upstream: Health-check and latency test upstream URLs
- benchmark: Run embedded async load test against mock upstream
- status: Print proxy configuration summary and system capabilities
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import sys
import time
from typing import Any, Dict, List, Optional

from proxy import __version__
from proxy.balancer import LoadBalancer, UpstreamNode
from proxy.server import ProxyConfig, ProxyServer


def setup_logging(level: str = "INFO") -> None:
    """Configure basic structured logging."""
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s [%(levelname)s] [%(name)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


async def test_upstream_async(urls: List[str], timeout: float = 3.0) -> int:
    """Probe upstreams and display status."""
    import httpx

    print(f"\n🔍 Probing {len(urls)} upstream target(s) (timeout={timeout}s):")
    print("-" * 75)
    print(f"{'URL':<40} | {'STATUS':<10} | {'LATENCY (ms)':<15} | {'HEALTH':<10}")
    print("-" * 75)

    all_healthy = True
    async with httpx.AsyncClient(timeout=timeout) as client:
        for url in urls:
            clean_url = url.rstrip("/")
            start = time.monotonic()
            try:
                resp = await client.get(clean_url)
                latency_ms = (time.monotonic() - start) * 1000.0
                is_ok = 200 <= resp.status_code < 500
                status_str = f"{resp.status_code}"
                health_str = "OK" if is_ok else "FAIL"
                if not is_ok:
                    all_healthy = False
                print(f"{clean_url:<40} | {status_str:<10} | {latency_ms:<15.2f} | {health_str:<10}")
            except Exception as e:
                all_healthy = False
                err_name = type(e).__name__
                print(f"{clean_url:<40} | {'ERROR':<10} | {'-':<15} | {err_name:<10}")

    print("-" * 75)
    return 0 if all_healthy else 1


async def run_embedded_benchmark(
    requests_count: int = 2000,
    concurrency: int = 50,
) -> dict:
    """Run an in-process mock upstream + proxy benchmark."""
    import httpx

    mock_resp = httpx.Response(200, json={"status": "ok", "timestamp": time.time()})
    proxy_config = ProxyConfig(
        upstreams=["http://10.0.0.1:8080"],
        rate_limit_rate=1_000_000.0,
        rate_limit_capacity=1_000_000.0,
        max_concurrency=10000,
    )
    proxy = ProxyServer(proxy_config)
    proxy._http_client = httpx.AsyncClient(
        transport=httpx.MockTransport(lambda req: mock_resp),
        timeout=5.0,
    )

    print(f"\n🚀 Running embedded benchmark:")
    print(f"   - Requests: {requests_count}")
    print(f"   - Concurrency: {concurrency}\n")

    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "GET",
        "scheme": "http",
        "path": "/api/test",
        "raw_path": b"/api/test",
        "query_string": b"",
        "root_path": "",
        "headers": [(b"host", b"localhost:8000"), (b"x-api-key", b"bench_key")],
        "client": ("127.0.0.1", 54321),
        "server": ("127.0.0.1", 8000),
    }

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    latencies: List[float] = []
    successes = 0
    failures = 0
    reqs_per_worker = requests_count // concurrency

    async def worker():
        nonlocal successes, failures
        for _ in range(reqs_per_worker):
            res_parts = []
            async def send(msg):
                res_parts.append(msg)
            t0 = time.perf_counter()
            try:
                await proxy(scope, receive, send)
                t1 = time.perf_counter()
                latencies.append((t1 - t0) * 1000.0)
                if res_parts and res_parts[0].get("status") == 200:
                    successes += 1
                else:
                    failures += 1
            except Exception:
                failures += 1

    start_total = time.perf_counter()
    tasks = [asyncio.create_task(worker()) for _ in range(concurrency)]
    await asyncio.gather(*tasks)
    total_time = time.perf_counter() - start_total

    latencies.sort()
    p50 = latencies[int(len(latencies) * 0.50)] if latencies else 0.0
    p95 = latencies[int(len(latencies) * 0.95)] if latencies else 0.0
    p99 = latencies[int(len(latencies) * 0.99)] if latencies else 0.0
    mean_lat = sum(latencies) / len(latencies) if latencies else 0.0
    rps = successes / total_time if total_time > 0 else 0.0

    results: Dict[str, Any] = {
        "concurrency": concurrency,
        "total_requests": requests_count,
        "successful_requests": successes,
        "failed_requests": failures,
        "duration_seconds": round(total_time, 4),
        "throughput_rps": round(rps, 2),
        "latency_ms": {
            "p50": round(p50, 2),
            "p95": round(p95, 2),
            "p99": round(p99, 2),
            "mean": round(mean_lat, 2),
            "min": round(latencies[0] if latencies else 0.0, 2),
            "max": round(latencies[-1] if latencies else 0.0, 2),
        },
    }

    print(f"📊 Benchmark Results:")
    print(f"   Throughput: {results['throughput_rps']} req/s")
    print(f"   Latency p50: {results['latency_ms']['p50']} ms")
    print(f"   Latency p95: {results['latency_ms']['p95']} ms")
    print(f"   Latency p99: {results['latency_ms']['p99']} ms")
    print(f"   Success Rate: {100.0 * successes / max(1, requests_count):.2f}%\n")

    return results


def main(args: Optional[List[str]] = None) -> int:
    """Main CLI entrypoint."""
    parser = argparse.ArgumentParser(
        prog="reverse-proxy-limiter",
        description="Enterprise High-Performance Async Reverse Proxy & Rate Limiter",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")

    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")

    # Subcommand: start
    start_parser = subparsers.add_parser("start", help="Start the reverse proxy server")
    start_parser.add_argument("--host", default="127.0.0.1", help="Host to bind (default: 127.0.0.1)")
    start_parser.add_argument("--port", type=int, default=8000, help="Port to bind (default: 8000)")
    start_parser.add_argument("--upstreams", nargs="+", default=["http://127.0.0.1:8080"], help="Upstream targets")
    start_parser.add_argument("--strategy", choices=["round_robin", "least_connections", "random", "ip_hash"], default="round_robin", help="Balancing strategy")
    start_parser.add_argument("--rate-limit", type=float, default=100.0, help="Rate limit tokens/sec")
    start_parser.add_argument("--capacity", type=float, default=200.0, help="Rate limit burst capacity")
    start_parser.add_argument("--circuit-threshold", type=int, default=5, help="Circuit breaker failure threshold")
    start_parser.add_argument("--circuit-cooldown", type=float, default=10.0, help="Circuit breaker cooldown in seconds")
    start_parser.add_argument("--max-body-size", type=int, default=10485760, help="Max body size in bytes (default: 10MB)")
    start_parser.add_argument("--timeout", type=float, default=5.0, help="Upstream timeout in seconds")
    start_parser.add_argument("--log-level", default="info", help="Logging level (debug, info, warning, error)")

    # Subcommand: test-upstream
    test_parser = subparsers.add_parser("test-upstream", help="Test connectivity to upstream servers")
    test_parser.add_argument("urls", nargs="+", help="Upstream URLs to test")
    test_parser.add_argument("--timeout", type=float, default=3.0, help="Timeout in seconds")

    # Subcommand: benchmark
    bench_parser = subparsers.add_parser("benchmark", help="Run local load benchmark")
    bench_parser.add_argument("-n", "--requests", type=int, default=2000, help="Total requests (default: 2000)")
    bench_parser.add_argument("-c", "--concurrency", type=int, default=50, help="Concurrency (default: 50)")

    # Subcommand: status
    status_parser = subparsers.add_parser("status", help="Show system status and configuration")

    parsed_args = parser.parse_args(args)

    if not parsed_args.command:
        parser.print_help()
        return 0

    setup_logging(getattr(parsed_args, "log_level", "INFO"))

    if parsed_args.command == "start":
        import uvicorn
        cfg = ProxyConfig(
            upstreams=parsed_args.upstreams,
            balancer_strategy=parsed_args.strategy,
            rate_limit_rate=parsed_args.rate_limit,
            rate_limit_capacity=parsed_args.capacity,
            circuit_failure_threshold=parsed_args.circuit_threshold,
            circuit_cooldown=parsed_args.circuit_cooldown,
            max_body_size=parsed_args.max_body_size,
            upstream_timeout=parsed_args.timeout,
        )
        proxy = ProxyServer(cfg)
        print(f"⚡ Starting Reverse Proxy Limiter v{__version__} on http://{parsed_args.host}:{parsed_args.port}")
        print(f"🎯 Balancing Strategy: {cfg.balancer_strategy} across {len(cfg.upstreams)} upstream(s)")
        print(f"🛡️  Security Headers: Enabled | Max Payload: {cfg.max_body_size // (1024*1024)}MB | Timeout: {cfg.upstream_timeout}s")
        uvicorn.run(proxy.app, host=parsed_args.host, port=parsed_args.port, log_level=parsed_args.log_level.lower())
        return 0

    elif parsed_args.command == "test-upstream":
        return asyncio.run(test_upstream_async(parsed_args.urls, timeout=parsed_args.timeout))

    elif parsed_args.command == "benchmark":
        asyncio.run(run_embedded_benchmark(requests_count=parsed_args.requests, concurrency=parsed_args.concurrency))
        return 0

    elif parsed_args.command == "status":
        print(f"Package: reverse-proxy-limiter v{__version__}")
        print("Async HTTP/1.1 Reverse Proxy & Rate Limiter")
        print("DevSecOps Security Controls: CWE-400, CWE-209, CWE-330, CWE-208, CWE-502")
        print("Prometheus /metrics & OpenMetrics compliant")
        return 0

    return 0


if __name__ == "__main__":
    sys.exit(main())
