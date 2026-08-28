import asyncio
import json
from pathlib import Path
import statistics
import sys
import time
from typing import Any, Dict, List

# Ensure src/ is on sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from prober.probes.dns import DNSProbe
from prober.probes.http import HTTPProbe
from prober.probes.tcp import TCPProbe
from prober.scheduler import ProbeScheduler, ProbeTarget


async def start_benchmark_http_server():
    """Start high-throughput lightweight mock HTTP server for benchmarking."""
    resp_payload = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 13\r\n\r\nHello World!!\n"

    async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        try:
            while True:
                line = await reader.readline()
                if not line:
                    break
                if line in (b"\r\n", b"\n"):
                    writer.write(resp_payload)
                    await writer.drain()
                    break
        except Exception:
            pass
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    server = await asyncio.start_server(handle_client, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    return server, port


async def run_benchmark(num_requests: int = 500, concurrency: int = 50) -> Dict[str, Any]:
    """Execute concurrent synthetic probe benchmark."""
    server, port = await start_benchmark_http_server()
    target_url = f"http://127.0.0.1:{port}/"

    scheduler = ProbeScheduler(concurrency_limit=concurrency)
    targets = [
        ProbeTarget(name=f"bench_{i}", probe_type="http", target=target_url)
        for i in range(num_requests)
    ]

    print(f"[*] Starting benchmark: {num_requests} probes with concurrency {concurrency}...")
    t0 = time.perf_counter()
    results = await scheduler.run_batch(targets)
    total_time = time.perf_counter() - t0

    server.close()
    await server.wait_closed()

    success_count = sum(1 for r in results if getattr(r, "is_success", False))
    total_latencies = [getattr(r, "total_latency_ms", 0.0) for r in results]
    dns_latencies = [getattr(r, "dns_latency_ms", 0.0) for r in results]
    tcp_latencies = [getattr(r, "tcp_latency_ms", 0.0) for r in results]
    ttfb_latencies = [getattr(r, "ttfb_ms", 0.0) for r in results]

    sorted_latencies = sorted(total_latencies)
    p50 = sorted_latencies[int(len(sorted_latencies) * 0.50)]
    p90 = sorted_latencies[int(len(sorted_latencies) * 0.90)]
    p99 = sorted_latencies[int(len(sorted_latencies) * 0.99)]

    throughput = num_requests / total_time

    data = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%SZ", time.gmtime()),
        "total_probes": num_requests,
        "concurrency": concurrency,
        "successful_probes": success_count,
        "failed_probes": num_requests - success_count,
        "total_time_seconds": round(total_time, 4),
        "probes_per_second": round(throughput, 2),
        "latency_percentiles_ms": {
            "p50": round(p50, 3),
            "p90": round(p90, 3),
            "p99": round(p99, 3),
            "min": round(min(sorted_latencies), 3),
            "max": round(max(sorted_latencies), 3),
            "mean": round(statistics.mean(sorted_latencies), 3),
        },
        "phase_breakdown_avg_ms": {
            "dns_avg": round(statistics.mean(dns_latencies), 3),
            "tcp_avg": round(statistics.mean(tcp_latencies), 3),
            "ttfb_avg": round(statistics.mean(ttfb_latencies), 3),
        },
    }

    out_file = Path(__file__).parent / "resultados.json"
    with open(out_file, "w") as f:
        json.dump(data, f, indent=2)

    print("\n" + "=" * 50)
    print("       SYNTHETIC PROBER BENCHMARK RESULTS")
    print("=" * 50)
    print(f" Total Probes:         {num_requests}")
    print(f" Concurrency Limit:    {concurrency}")
    print(f" Elapsed Time:         {total_time:.4f} s")
    print(f" Throughput:           {throughput:.2f} probes/sec")
    print(f" Success Rate:         {(success_count / num_requests) * 100:.2f}%")
    print("-" * 50)
    print(f" Avg DNS Latency:      {data['phase_breakdown_avg_ms']['dns_avg']:.3f} ms")
    print(f" Avg TCP Latency:      {data['phase_breakdown_avg_ms']['tcp_avg']:.3f} ms")
    print(f" Avg TTFB Latency:     {data['phase_breakdown_avg_ms']['ttfb_avg']:.3f} ms")
    print(f" Latency P50:          {p50:.3f} ms")
    print(f" Latency P90:          {p90:.3f} ms")
    print(f" Latency P99:          {p99:.3f} ms")
    print("=" * 50)
    print(f"[+] Saved results to {out_file.resolve()}\n")

    return data


if __name__ == "__main__":
    asyncio.run(run_benchmark(num_requests=500, concurrency=50))
