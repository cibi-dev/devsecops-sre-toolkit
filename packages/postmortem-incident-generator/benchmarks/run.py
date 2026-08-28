#!/usr/bin/env python3
"""Performance and Scalability Benchmark Suite for Post-Mortem Incident Generator.

Measures evidence collection latency, sanitization throughput, timeline reconstruction speed,
Markdown report generation latency, and SQLite storage roundtrip efficiency.
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

# Add src to python path for standalone execution
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from postmortem.collector import EvidenceCollector
from postmortem.generator import IncidentReport, IncidentSeverity, IncidentStatus, PostmortemGenerator
from postmortem.rca_engine import ActionItem, ActionItemPriority, ActionItemType, ContributingFactor, FiveWhys, RCAResult
from postmortem.sanitizer import EvidenceSanitizer
from postmortem.storage import IncidentStorage
from postmortem.timeline_builder import IncidentMetrics, TimelineBuilder, TimelineEvent


def run_benchmark() -> dict:
    print("🚀 Starting postmortem-incident-generator benchmarks...")
    results = {}

    # 1. Sanitizer Throughput Benchmark
    sanitizer = EvidenceSanitizer()
    sample_log = (
        "2026-08-27 10:14:02.123 ERROR [payment-worker-42] Database query failed: "
        "password=SuperSecretPassword123! token='sk-live-9876543210' "
        "auth: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0In0.signature "
        "url=postgres://admin:secretPass@internal-db:5432/main user=ops.lead@enterprise.org\n"
    ) * 1000  # ~250KB per batch

    iterations = 20
    total_bytes = len(sample_log.encode("utf-8")) * iterations
    start_time = time.perf_counter()
    for _ in range(iterations):
        sanitizer.sanitize_text(sample_log)
    elapsed = time.perf_counter() - start_time
    mb_processed = total_bytes / (1024 * 1024)
    throughput_mb_s = mb_processed / elapsed

    results["sanitizer"] = {
        "throughput_mb_per_sec": round(throughput_mb_s, 2),
        "total_mb_processed": round(mb_processed, 2),
        "elapsed_seconds": round(elapsed, 4),
    }
    print(f"  ⚡ Sanitizer Throughput: {throughput_mb_s:.2f} MB/s")

    # 2. Evidence Collection Latency Benchmark
    collector = EvidenceCollector(sanitize=True)
    start_time = time.perf_counter()
    collector.collect_all()
    evidence_elapsed_ms = (time.perf_counter() - start_time) * 1000

    results["evidence_collection"] = {
        "latency_ms": round(evidence_elapsed_ms, 2),
    }
    print(f"  ⚡ Evidence Collection Latency: {evidence_elapsed_ms:.2f} ms")

    # 3. Timeline Reconstruction & SRE Metrics Benchmark
    tb = TimelineBuilder(sanitize=True)
    event_count = 100
    for i in range(event_count):
        tb.add_event(
            timestamp=f"2026-08-27T10:{i % 60:02d}:00Z",
            event_type="INVESTIGATION" if i > 0 else "INCIDENT_START",
            description=f"Automated system check milestone #{i}",
            source="BenchmarkRunner",
        )
    start_time = time.perf_counter()
    tb.compute_metrics()
    timeline_elapsed_ms = (time.perf_counter() - start_time) * 1000

    results["timeline_metrics"] = {
        "events_evaluated": event_count,
        "latency_ms": round(timeline_elapsed_ms, 3),
    }
    print(f"  ⚡ Timeline (100 events) Calculation: {timeline_elapsed_ms:.3f} ms")

    # 4. SRE Markdown Report Generation Benchmark
    generator = PostmortemGenerator()
    report = IncidentReport(
        incident_id="INC-BENCH-001",
        title="High Throughput Payment Processing Outage",
        severity=IncidentSeverity.SEV_1.value,
        status=IncidentStatus.RESOLVED.value,
        date="2026-08-27",
        commander="SRE On-Call",
        lead="Principal Architect",
        summary="Synthetic incident payload for deterministic generation benchmark testing.",
        user_impact="Simulated customer impact across 10,000 transactions.",
        revenue_or_slo_impact="99.9% availability budget consumed for 15 minutes.",
        timeline=tb.get_chronological_timeline()[:20],
        metrics=tb.compute_metrics(),
        rca=RCAResult(
            trigger_event="Simulated capacity spike",
            root_cause_summary="Connection pool starvation",
            five_whys=FiveWhys(
                problem_statement="Gateway returned 502 Bad Gateway",
                why_chain=[
                    "Connection pool was exhausted",
                    "Database threads hung on unindexed query",
                    "Migration omitted composite index",
                    "CI check did not validate index existence",
                ],
                root_cause="CI check did not validate index existence",
            ),
            contributing_factors=[
                ContributingFactor(category="MONITORING", description="Threshold set too high", impact="HIGH")
            ],
            action_items=[
                ActionItem(
                    id="ACT-001",
                    description="Implement automated pre-flight index checker",
                    item_type=ActionItemType.PREVENTATIVE.value,
                    priority=ActionItemPriority.P0.value,
                )
            ],
            what_went_well=["Alert fired in 1 minute"],
            what_went_poorly=["Runbook was outdated"],
            where_we_got_lucky=["Traffic was low"],
        ),
        evidences=collector.collect_all(),
    )

    gen_iterations = 50
    start_time = time.perf_counter()
    for _ in range(gen_iterations):
        generator.render_markdown(report)
    gen_elapsed = (time.perf_counter() - start_time) / gen_iterations * 1000

    results["report_generation"] = {
        "markdown_render_latency_ms": round(gen_elapsed, 3),
        "reports_per_sec": round(1000.0 / gen_elapsed, 1),
    }
    print(f"  ⚡ Markdown Generation Latency: {gen_elapsed:.3f} ms ({1000.0 / gen_elapsed:.1f} reports/sec)")

    # 5. SQLite Storage Roundtrip Benchmark
    storage = IncidentStorage(db_path=":memory:")
    storage_iterations = 50
    start_time = time.perf_counter()
    for i in range(storage_iterations):
        rep = report.model_copy(deep=True)
        rep.incident_id = f"INC-BENCH-{i:03d}"
        storage.save_incident(rep)
        storage.get_incident(rep.incident_id)
    storage_elapsed = (time.perf_counter() - start_time) / storage_iterations * 1000

    results["storage_roundtrip"] = {
        "save_and_retrieve_latency_ms": round(storage_elapsed, 3),
        "ops_per_sec": round(1000.0 / storage_elapsed, 1),
    }
    print(f"  ⚡ SQLite Roundtrip Latency: {storage_elapsed:.3f} ms ({1000.0 / storage_elapsed:.1f} ops/sec)")

    # Save to resultados.json
    out_file = Path(__file__).resolve().parent / "resultados.json"
    out_file.write_text(json.dumps(results, indent=2), encoding="utf-8")
    print(f"✅ Benchmark results written to: {out_file}")

    return results


if __name__ == "__main__":
    run_benchmark()
