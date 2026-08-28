#!/usr/bin/env python3
"""High-performance asynchronous benchmark suite for stream-log-aggregator."""

import asyncio
import json
import os
import sys
import time
from typing import List

# Ensure src is in python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))

from aggregator import LogEvent
from aggregator.outputs import BaseOutput
from aggregator.pipeline import LogPipeline
from aggregator.transformers.grok import GrokTransformer
from aggregator.transformers.sanitizer import PIISanitizer


class BenchmarkSink(BaseOutput):
    """High-speed in-memory sink for latency and throughput measurement."""

    def __init__(self):
        super().__init__(name="bench-sink")
        self.received_events: List[LogEvent] = []
        self.batch_latencies: List[float] = []

    async def send_batch(self, events: List[LogEvent]) -> bool:
        t_now = time.time()
        for ev in events:
            # Latency from creation to sink ingestion in ms
            lat = (t_now - ev.timestamp) * 1000.0
            self.batch_latencies.append(lat)
        self.received_events.extend(events)
        self._events_sent += len(events)
        self._batches_sent += 1
        return True


SAMPLE_EVENTS = [
    (
        "<134>Feb 15 14:02:30 db-node-1 postgres[5432]: Connection from 192.168.1.55: "
        "user=admin password=SuperSecretPassword123! token=Bearer eyJhbGciOiJIUzI1NiJ9.abc.def "
        "email=developer@company.internal query='SELECT * FROM users'"
    ),
    (
        "<165>1 2026-08-27T20:15:30.123Z api-gateway.prod auth 9876 ID42 - "
        "User user.test@example.com authenticated via 10.0.4.12 access_token=secret_tok_998877"
    ),
    (
        '172.16.20.100 - user_admin [27/Aug/2026:20:15:30 +0000] "POST /api/v1/checkout HTTP/1.1" 200 4523 '
        '"https://example.com/cart" "Mozilla/5.0 (X11; Linux x86_64)" password=checkout_pass_44'
    ),
    (
        '{"service": "payment-service", "level": "INFO", "client_ip": "10.200.1.1", '
        '"user_email": "customer@gmail.com", "card": "4111 2222 3333 4444", '
        '"message": "Payment processed successfully for 127.0.0.1"}'
    ),
]


async def run_benchmark(total_events: int = 25000, workers: int = 4, batch_size: int = 500) -> dict:
    """Run async throughput and latency benchmark."""
    print(f"[*] Initializing benchmark: {total_events} events, {workers} workers, batch size {batch_size}...")

    pipeline = LogPipeline(
        worker_count=workers,
        queue_max_size=total_events * 2,
        batch_size=batch_size,
        flush_interval=0.01,
    )
    pipeline.add_transformer(GrokTransformer())
    pipeline.add_transformer(PIISanitizer())

    sink = BenchmarkSink()
    pipeline.add_output(sink)

    await pipeline.start()

    # Pre-generate event strings
    events_payload = [SAMPLE_EVENTS[i % len(SAMPLE_EVENTS)] for i in range(total_events)]

    print(f"[*] Ingesting {total_events} multi-channel events into pipeline...")
    start_time = time.perf_counter()

    for raw_msg in events_payload:
        await pipeline.push_raw(raw_msg, source="bench")

    # Wait for all events to be processed and dispatched
    timeout = 30.0
    while len(sink.received_events) < total_events and (time.perf_counter() - start_time) < timeout:
        await asyncio.sleep(0.01)

    end_time = time.perf_counter()
    duration = end_time - start_time

    await pipeline.stop(drain=True)

    processed_count = len(sink.received_events)
    throughput = processed_count / duration if duration > 0 else 0.0

    # Calculate Latency percentiles
    latencies = sorted(sink.batch_latencies) if sink.batch_latencies else [0.0]
    p50 = latencies[int(len(latencies) * 0.50)]
    p95 = latencies[int(len(latencies) * 0.95)]
    p99 = latencies[int(len(latencies) * 0.99)]
    avg_latency = sum(latencies) / len(latencies) if latencies else 0.0

    # Verify PII Sanitization across sampled processed events
    sanitized_count = sum(1 for e in sink.received_events if "sanitized" in e.tags or "[REDACTED]" in e.message or "[REDACTED]" in str(e.metadata))
    sanitization_rate = (sanitized_count / processed_count * 100.0) if processed_count > 0 else 0.0

    results = {
        "benchmark": "stream-log-aggregator-throughput",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "target_events": total_events,
        "events_processed": processed_count,
        "duration_seconds": round(duration, 4),
        "throughput_events_per_sec": round(throughput, 2),
        "latency_ms": {
            "p50": round(p50, 3),
            "p95": round(p95, 3),
            "p99": round(p99, 3),
            "avg": round(avg_latency, 3),
        },
        "sanitization_rate_pct": round(sanitization_rate, 2),
        "target_met": bool(throughput >= 5000.0 and processed_count == total_events),
    }

    print("\n" + "=" * 60)
    print("📊 BENCHMARK RESULTS")
    print("=" * 60)
    print(f"Events Processed : {results['events_processed']} / {results['target_events']}")
    print(f"Total Duration   : {results['duration_seconds']:.4f} s")
    print(f"Throughput       : {results['throughput_events_per_sec']:.2f} events/s (Target: >= 5000)")
    print(f"Latency (p50)    : {results['latency_ms']['p50']:.3f} ms")
    print(f"Latency (p95)    : {results['latency_ms']['p95']:.3f} ms")
    print(f"Latency (p99)    : {results['latency_ms']['p99']:.3f} ms")
    print(f"Sanitization %   : {results['sanitization_rate_pct']:.1f}%")
    print(f"Target Met       : {'✅ YES' if results['target_met'] else '❌ NO'}")
    print("=" * 60 + "\n")

    return results


def main():
    results = asyncio.run(run_benchmark(total_events=25000, workers=4, batch_size=500))
    output_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "resultados.json"))
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)
    print(f"[+] Saved benchmark metrics to: {output_path}")


if __name__ == "__main__":
    main()
