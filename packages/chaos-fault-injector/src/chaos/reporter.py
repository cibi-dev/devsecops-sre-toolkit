"""Resilience reporter module comparing pre, during, and post fault experiment metrics.

Computes:
- Availability % and error rate % across phases
- Latency percentiles (p50, p95, p99)
- CPU and memory resource consumption
- Composite Resilience Score (0 - 100)
- Export to Markdown and JSON formats
"""

from __future__ import annotations

import datetime
import json
import math
import os
import uuid
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple
from pydantic import BaseModel, ConfigDict, Field


class ExperimentPhase(str, Enum):
    """Phases of a Chaos Engineering experiment."""

    PRE_FAULT = "pre_fault"
    DURING_FAULT = "during_fault"
    POST_FAULT = "post_fault"


class PhaseMetrics(BaseModel):
    """Metrics snapshot for an experiment phase."""

    model_config = ConfigDict(extra="forbid")

    phase: ExperimentPhase
    timestamp_start: str
    timestamp_end: str
    duration_seconds: float = 0.0
    cpu_percent_avg: float = 0.0
    cpu_percent_max: float = 0.0
    memory_percent_avg: float = 0.0
    total_requests: int = 0
    successful_requests: int = 0
    failed_requests: int = 0
    availability_pct: float = 100.0
    error_rate_pct: float = 0.0
    latency_p50_ms: float = 0.0
    latency_p95_ms: float = 0.0
    latency_p99_ms: float = 0.0
    custom_metrics: Dict[str, float] = Field(default_factory=dict)


class ResilienceReport(BaseModel):
    """Comprehensive Chaos Engineering Resilience Assessment Report."""

    model_config = ConfigDict(extra="forbid")

    experiment_id: str
    experiment_name: str
    target_type: str
    created_at: str
    pre_metrics: PhaseMetrics
    during_metrics: PhaseMetrics
    post_metrics: PhaseMetrics
    resilience_score: float = Field(ge=0.0, le=100.0)
    recovery_time_seconds: float = 0.0
    verdict: str  # "RESILIENT", "DEGRADED", "FAILED"
    summary: str
    fault_details: Dict[str, Any] = Field(default_factory=dict)


def calculate_percentiles(values: List[float]) -> Tuple[float, float, float]:
    """Calculate p50, p95, and p99 percentiles from a list of measurements."""
    if not values:
        return 0.0, 0.0, 0.0

    sorted_vals = sorted(values)
    n = len(sorted_vals)

    def _pct(p: float) -> float:
        k = (n - 1) * p
        f = math.floor(k)
        c = math.ceil(k)
        if f == c:
            return float(sorted_vals[int(k)])
        d0 = sorted_vals[int(f)] * (c - k)
        d1 = sorted_vals[int(c)] * (k - f)
        return float(d0 + d1)

    p50 = round(_pct(0.50), 2)
    p95 = round(_pct(0.95), 2)
    p99 = round(_pct(0.99), 2)
    return p50, p95, p99


def calculate_resilience_score(
    pre: PhaseMetrics,
    during: PhaseMetrics,
    post: PhaseMetrics,
) -> float:
    """Calculate composite resilience score (0.0 - 100.0).

    Weighted formula:
    - Post-fault availability recovery: 40% weight
    - During-fault availability retention: 30% weight
    - Latency recovery (p95 post vs pre): 30% weight
    """
    # 1. Post availability ratio (compared to pre baseline)
    baseline_avail = max(pre.availability_pct, 1.0)
    post_avail_ratio = min(1.0, post.availability_pct / baseline_avail)
    post_score = post_avail_ratio * 40.0

    # 2. During availability retention
    during_avail_ratio = min(1.0, during.availability_pct / baseline_avail)
    during_score = during_avail_ratio * 30.0

    # 3. Latency recovery
    baseline_lat = max(pre.latency_p95_ms, 1.0)
    post_lat = max(post.latency_p95_ms, 1.0)
    if post_lat <= baseline_lat:
        lat_score = 30.0
    else:
        # Penalize if post latency is significantly worse than pre
        degradation = (post_lat - baseline_lat) / baseline_lat
        lat_ratio = max(0.0, 1.0 - (degradation * 0.5))
        lat_score = lat_ratio * 30.0

    total_score = round(post_score + during_score + lat_score, 2)
    return max(0.0, min(100.0, total_score))


def determine_verdict(resilience_score: float, post: PhaseMetrics) -> str:
    """Determine verdict string based on score and post-recovery availability."""
    if resilience_score >= 85.0 and post.availability_pct >= 95.0:
        return "RESILIENT"
    elif resilience_score >= 60.0 and post.availability_pct >= 80.0:
        return "DEGRADED"
    else:
        return "FAILED"


def generate_markdown_report(report: ResilienceReport) -> str:
    """Format ResilienceReport as a readable Markdown document."""
    pre = report.pre_metrics
    during = report.during_metrics
    post = report.post_metrics

    status_icon = "🟢" if report.verdict == "RESILIENT" else ("🟡" if report.verdict == "DEGRADED" else "🔴")

    lines = [
        f"# 🧪 Chaos Resilience Report: {report.experiment_name}",
        "",
        f"- **Experiment ID:** `{report.experiment_id}`",
        f"- **Target Type:** `{report.target_type}`",
        f"- **Timestamp:** `{report.created_at}`",
        f"- **Overall Verdict:** {status_icon} **{report.verdict}**",
        f"- **Resilience Score:** **{report.resilience_score} / 100.0**",
        f"- **Recovery Time:** `{report.recovery_time_seconds:.2f}s`",
        "",
        "## 📊 Phase Comparison Matrix",
        "",
        "| Metric | Pre-Fault Baseline | During Fault | Post-Fault Recovery | Delta (Post vs Pre) |",
        "|---|:---:|:---:|:---:|:---:|",
        f"| **Availability** | {pre.availability_pct:.2f}% | {during.availability_pct:.2f}% | {post.availability_pct:.2f}% | {post.availability_pct - pre.availability_pct:+.2f}% |",
        f"| **Error Rate** | {pre.error_rate_pct:.2f}% | {during.error_rate_pct:.2f}% | {post.error_rate_pct:.2f}% | {post.error_rate_pct - pre.error_rate_pct:+.2f}% |",
        f"| **Latency p50** | {pre.latency_p50_ms:.2f} ms | {during.latency_p50_ms:.2f} ms | {post.latency_p50_ms:.2f} ms | {post.latency_p50_ms - pre.latency_p50_ms:+.2f} ms |",
        f"| **Latency p95** | {pre.latency_p95_ms:.2f} ms | {during.latency_p95_ms:.2f} ms | {post.latency_p95_ms:.2f} ms | {post.latency_p95_ms - pre.latency_p95_ms:+.2f} ms |",
        f"| **Latency p99** | {pre.latency_p99_ms:.2f} ms | {during.latency_p99_ms:.2f} ms | {post.latency_p99_ms:.2f} ms | {post.latency_p99_ms - pre.latency_p99_ms:+.2f} ms |",
        f"| **Avg CPU Load** | {pre.cpu_percent_avg:.1f}% | {during.cpu_percent_avg:.1f}% | {post.cpu_percent_avg:.1f}% | {post.cpu_percent_avg - pre.cpu_percent_avg:+.1f}% |",
        f"| **Avg Memory** | {pre.memory_percent_avg:.1f}% | {during.memory_percent_avg:.1f}% | {post.memory_percent_avg:.1f}% | {post.memory_percent_avg - pre.memory_percent_avg:+.1f}% |",
        f"| **Requests (OK/Fail)** | {pre.successful_requests}/{pre.failed_requests} | {during.successful_requests}/{during.failed_requests} | {post.successful_requests}/{post.failed_requests} | — |",
        "",
        "## 📝 Executive Summary",
        "",
        f"> {report.summary}",
        "",
        "## ⚙️ Injected Fault Configuration",
        "",
        "```json",
        json.dumps(report.fault_details, indent=2),
        "```",
        "",
    ]
    return "\n".join(lines)


def export_markdown(report: ResilienceReport, filepath: Optional[str] = None) -> str:
    """Export report to Markdown string and optionally write to file."""
    md = generate_markdown_report(report)
    if filepath:
        os.makedirs(os.path.dirname(os.path.abspath(filepath)), exist_ok=True)
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(md)
    return md


def export_json(report: ResilienceReport, filepath: Optional[str] = None) -> str:
    """Export report to JSON string and optionally write to file."""
    json_str = report.model_dump_json(indent=2)
    if filepath:
        os.makedirs(os.path.dirname(os.path.abspath(filepath)), exist_ok=True)
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(json_str)
    return json_str


class PhaseCollector:
    """Collects measurements and calculates PhaseMetrics."""

    def __init__(self, phase: ExperimentPhase) -> None:
        self.phase = phase
        self.timestamp_start = datetime.datetime.now(datetime.timezone.utc).isoformat()
        self.latencies: List[float] = []
        self.cpu_samples: List[float] = []
        self.mem_samples: List[float] = []
        self.successful_requests: int = 0
        self.failed_requests: int = 0

    def record_request(self, latency_ms: float, success: bool = True) -> None:
        """Record a single synthetic or real probe request."""
        self.latencies.append(max(0.0, float(latency_ms)))
        if success:
            self.successful_requests += 1
        else:
            self.failed_requests += 1

    def record_system_sample(self, cpu_pct: float, mem_pct: float) -> None:
        """Record system resource observation."""
        self.cpu_samples.append(max(0.0, float(cpu_pct)))
        self.mem_samples.append(max(0.0, float(mem_pct)))

    def build_metrics(self, duration_seconds: float) -> PhaseMetrics:
        """Calculate aggregate PhaseMetrics from recorded samples."""
        timestamp_end = datetime.datetime.now(datetime.timezone.utc).isoformat()
        total_reqs = self.successful_requests + self.failed_requests
        avail_pct = (self.successful_requests / total_reqs * 100.0) if total_reqs > 0 else 100.0
        err_pct = (self.failed_requests / total_reqs * 100.0) if total_reqs > 0 else 0.0

        p50, p95, p99 = calculate_percentiles(self.latencies)

        avg_cpu = sum(self.cpu_samples) / len(self.cpu_samples) if self.cpu_samples else 0.0
        max_cpu = max(self.cpu_samples) if self.cpu_samples else 0.0
        avg_mem = sum(self.mem_samples) / len(self.mem_samples) if self.mem_samples else 0.0

        return PhaseMetrics(
            phase=self.phase,
            timestamp_start=self.timestamp_start,
            timestamp_end=timestamp_end,
            duration_seconds=round(duration_seconds, 2),
            cpu_percent_avg=round(avg_cpu, 2),
            cpu_percent_max=round(max_cpu, 2),
            memory_percent_avg=round(avg_mem, 2),
            total_requests=total_reqs,
            successful_requests=self.successful_requests,
            failed_requests=self.failed_requests,
            availability_pct=round(avail_pct, 2),
            error_rate_pct=round(err_pct, 2),
            latency_p50_ms=p50,
            latency_p95_ms=p95,
            latency_p99_ms=p99,
        )


class ResilienceTracker:
    """Coordinates phase tracking and compiles ResilienceReport."""

    def __init__(self, experiment_name: str, target_type: str, fault_details: Optional[Dict[str, Any]] = None) -> None:
        self.experiment_id = str(uuid.uuid4())
        self.experiment_name = experiment_name
        self.target_type = target_type
        self.fault_details = fault_details or {}

        self.pre_collector = PhaseCollector(ExperimentPhase.PRE_FAULT)
        self.during_collector = PhaseCollector(ExperimentPhase.DURING_FAULT)
        self.post_collector = PhaseCollector(ExperimentPhase.POST_FAULT)

        self._active_phase = ExperimentPhase.PRE_FAULT

    def set_phase(self, phase: ExperimentPhase) -> None:
        """Switch current recording phase."""
        self._active_phase = phase

    def record(self, latency_ms: float, success: bool = True, cpu_pct: float = 0.0, mem_pct: float = 0.0) -> None:
        """Record sample into the active phase collector."""
        collector = (
            self.pre_collector
            if self._active_phase == ExperimentPhase.PRE_FAULT
            else (
                self.during_collector
                if self._active_phase == ExperimentPhase.DURING_FAULT
                else self.post_collector
            )
        )
        collector.record_request(latency_ms, success)
        collector.record_system_sample(cpu_pct, mem_pct)

    def finalize(
        self,
        pre_duration: float = 5.0,
        during_duration: float = 10.0,
        post_duration: float = 5.0,
        recovery_time_seconds: float = 0.0,
        summary_notes: str = "",
    ) -> ResilienceReport:
        """Generate final ResilienceReport."""
        pre_m = self.pre_collector.build_metrics(pre_duration)
        during_m = self.during_collector.build_metrics(during_duration)
        post_m = self.post_collector.build_metrics(post_duration)

        score = calculate_resilience_score(pre_m, during_m, post_m)
        verdict = determine_verdict(score, post_m)

        summary = (
            summary_notes
            or f"Experiment '{self.experiment_name}' completed with score {score}/100. "
            f"Availability during fault: {during_m.availability_pct}%, post-recovery: {post_m.availability_pct}%."
        )

        return ResilienceReport(
            experiment_id=self.experiment_id,
            experiment_name=self.experiment_name,
            target_type=self.target_type,
            created_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),
            pre_metrics=pre_m,
            during_metrics=during_m,
            post_metrics=post_m,
            resilience_score=score,
            recovery_time_seconds=round(recovery_time_seconds, 2),
            verdict=verdict,
            summary=summary,
            fault_details=self.fault_details,
        )
