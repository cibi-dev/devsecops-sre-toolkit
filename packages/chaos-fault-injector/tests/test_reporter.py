"""Tests for resilience reporter and metrics module."""

from __future__ import annotations

import json
from typing import Any
import pytest

from chaos.reporter import (
    ExperimentPhase,
    PhaseCollector,
    PhaseMetrics,
    ResilienceReport,
    ResilienceTracker,
    calculate_percentiles,
    calculate_resilience_score,
    determine_verdict,
    export_json,
    export_markdown,
    generate_markdown_report,
)


def test_calculate_percentiles() -> None:
    """Test percentile calculations across edge cases."""
    # Empty list
    assert calculate_percentiles([]) == (0.0, 0.0, 0.0)

    # Single element
    assert calculate_percentiles([42.0]) == (42.0, 42.0, 42.0)

    # 100 elements: 1..100
    latencies = [float(i) for i in range(1, 101)]
    p50, p95, p99 = calculate_percentiles(latencies)
    assert 49.0 <= p50 <= 51.5
    assert 94.0 <= p95 <= 96.0
    assert 98.0 <= p99 <= 100.0


def test_calculate_resilience_score() -> None:
    """Test resilience score calculation formula."""
    pre = PhaseMetrics(
        phase=ExperimentPhase.PRE_FAULT,
        timestamp_start="2026-08-27T00:00:00Z",
        timestamp_end="2026-08-27T00:00:05Z",
        availability_pct=100.0,
        latency_p95_ms=10.0,
    )
    during = PhaseMetrics(
        phase=ExperimentPhase.DURING_FAULT,
        timestamp_start="2026-08-27T00:00:05Z",
        timestamp_end="2026-08-27T00:00:15Z",
        availability_pct=90.0,
        latency_p95_ms=50.0,
    )
    post = PhaseMetrics(
        phase=ExperimentPhase.POST_FAULT,
        timestamp_start="2026-08-27T00:00:15Z",
        timestamp_end="2026-08-27T00:00:20Z",
        availability_pct=100.0,
        latency_p95_ms=10.0,
    )

    score = calculate_resilience_score(pre, during, post)
    assert 90.0 <= score <= 100.0
    assert determine_verdict(score, post) == "RESILIENT"


def test_calculate_resilience_score_failed() -> None:
    """Test resilience score with unrecovered post failure."""
    pre = PhaseMetrics(
        phase=ExperimentPhase.PRE_FAULT,
        timestamp_start="2026-08-27T00:00:00Z",
        timestamp_end="2026-08-27T00:00:05Z",
        availability_pct=100.0,
        latency_p95_ms=10.0,
    )
    during = PhaseMetrics(
        phase=ExperimentPhase.DURING_FAULT,
        timestamp_start="2026-08-27T00:00:05Z",
        timestamp_end="2026-08-27T00:00:15Z",
        availability_pct=10.0,
        latency_p95_ms=500.0,
    )
    post = PhaseMetrics(
        phase=ExperimentPhase.POST_FAULT,
        timestamp_start="2026-08-27T00:00:15Z",
        timestamp_end="2026-08-27T00:00:20Z",
        availability_pct=20.0,
        latency_p95_ms=400.0,
    )

    score = calculate_resilience_score(pre, during, post)
    assert score < 50.0
    assert determine_verdict(score, post) == "FAILED"


def test_phase_collector() -> None:
    """Test PhaseCollector recording requests and resource metrics."""
    collector = PhaseCollector(ExperimentPhase.PRE_FAULT)
    collector.record_request(10.0, success=True)
    collector.record_request(20.0, success=True)
    collector.record_request(30.0, success=False)
    collector.record_system_sample(25.0, 50.0)
    collector.record_system_sample(35.0, 52.0)

    metrics = collector.build_metrics(duration_seconds=5.0)
    assert metrics.total_requests == 3
    assert metrics.successful_requests == 2
    assert metrics.failed_requests == 1
    assert round(metrics.availability_pct, 1) == 66.7
    assert round(metrics.error_rate_pct, 1) == 33.3
    assert metrics.cpu_percent_avg == 30.0
    assert metrics.cpu_percent_max == 35.0
    assert metrics.memory_percent_avg == 51.0


def test_resilience_tracker_flow() -> None:
    """Test end-to-end ResilienceTracker tracking and report generation."""
    tracker = ResilienceTracker("test-experiment", "network", {"interface": "eth0"})

    # Phase 1: Pre
    tracker.set_phase(ExperimentPhase.PRE_FAULT)
    for _ in range(5):
        tracker.record(latency_ms=12.0, success=True, cpu_pct=15.0, mem_pct=40.0)

    # Phase 2: During
    tracker.set_phase(ExperimentPhase.DURING_FAULT)
    for _ in range(5):
        tracker.record(latency_ms=85.0, success=True, cpu_pct=60.0, mem_pct=45.0)

    # Phase 3: Post
    tracker.set_phase(ExperimentPhase.POST_FAULT)
    for _ in range(5):
        tracker.record(latency_ms=13.0, success=True, cpu_pct=16.0, mem_pct=40.0)

    report = tracker.finalize(
        pre_duration=1.0,
        during_duration=2.0,
        post_duration=1.0,
        recovery_time_seconds=0.1,
    )

    assert isinstance(report, ResilienceReport)
    assert report.experiment_name == "test-experiment"
    assert report.target_type == "network"
    assert report.resilience_score > 80.0
    assert report.verdict in ("RESILIENT", "DEGRADED", "FAILED")


def test_generate_and_export_reports(tmp_path: Any) -> None:
    """Test exporting reports to Markdown and JSON files."""
    tracker = ResilienceTracker("export-test", "cpu", {"cores": 2})
    tracker.set_phase(ExperimentPhase.PRE_FAULT)
    tracker.record(latency_ms=5.0, success=True, cpu_pct=10.0, mem_pct=20.0)
    tracker.set_phase(ExperimentPhase.DURING_FAULT)
    tracker.record(latency_ms=25.0, success=True, cpu_pct=80.0, mem_pct=25.0)
    tracker.set_phase(ExperimentPhase.POST_FAULT)
    tracker.record(latency_ms=5.5, success=True, cpu_pct=12.0, mem_pct=20.0)

    report = tracker.finalize()

    # Markdown export
    md_file = str(tmp_path / "report.md")
    md_content = export_markdown(report, md_file)
    assert "# 🧪 Chaos Resilience Report: export-test" in md_content
    assert "| **Availability** |" in md_content

    with open(md_file, "r", encoding="utf-8") as f:
        saved_md = f.read()
    assert saved_md == md_content

    # JSON export
    json_file = str(tmp_path / "report.json")
    json_content = export_json(report, json_file)
    data = json.loads(json_content)
    assert data["experiment_name"] == "export-test"
    assert data["target_type"] == "cpu"

    with open(json_file, "r", encoding="utf-8") as f:
        saved_json = f.read()
    assert saved_json == json_content
