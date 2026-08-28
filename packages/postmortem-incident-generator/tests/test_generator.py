import json
from pathlib import Path
import pytest
from postmortem.generator import (
    IncidentReport,
    IncidentSeverity,
    IncidentStatus,
    PostmortemGenerator,
)
from postmortem.rca_engine import (
    ActionItem,
    ActionItemPriority,
    ActionItemType,
    ContributingFactor,
    FiveWhys,
    RCAResult,
)
from postmortem.timeline_builder import IncidentMetrics, TimelineEvent


@pytest.fixture
def sample_incident_report():
    timeline = [
        TimelineEvent(
            timestamp="2026-08-27T10:00:00Z",
            event_type="INCIDENT_START",
            description="Core payment processing pipeline stalled",
            source="Stripe Webhook Monitor",
            impact_level="CRITICAL",
        ),
        TimelineEvent(
            timestamp="2026-08-27T10:04:00Z",
            event_type="DETECTION",
            description="Alert PaymentProcessingLatencyCritical fired",
            source="Prometheus",
            impact_level="CRITICAL",
        ),
        TimelineEvent(
            timestamp="2026-08-27T10:06:00Z",
            event_type="ACKNOWLEDGEMENT",
            description="On-call SRE paged and joined bridge",
            source="PagerDuty",
            impact_level="INFO",
        ),
        TimelineEvent(
            timestamp="2026-08-27T10:25:00Z",
            event_type="RESOLVED",
            description="Deadlock cleared and queue drained to normal levels",
            source="SRE Incident Commander",
            impact_level="INFO",
        ),
    ]

    metrics = IncidentMetrics(
        ttd_seconds=240.0,
        mtta_seconds=120.0,
        mttr_seconds=1500.0,
        ttm_seconds=1200.0,
        total_outage_seconds=1500.0,
        ttd_formatted="4m",
        mtta_formatted="2m",
        mttr_formatted="25m",
        ttm_formatted="20m",
        total_outage_formatted="25m",
    )

    rca = RCAResult(
        trigger_event="Batch settlement job ran simultaneously with payment gateway retry surge",
        root_cause_summary="Distributed lock granularity was too coarse, serializing concurrent writes",
        five_whys=FiveWhys(
            problem_statement="Payment processing latency spiked from 120ms to 45s",
            why_chain=[
                "Database worker threads were blocked waiting on row locks",
                "Settlement cron acquired table-level advisory lock",
                "Advisory lock scope included real-time checkout records",
                "Transaction isolation level was SERIALIZABLE instead of READ COMMITTED",
                "Default ORM configuration applied global locking without partition pruning",
            ],
            root_cause="Default ORM configuration applied global locking without partition pruning",
        ),
        contributing_factors=[
            ContributingFactor(
                category="CONFIGURATION",
                description="Database pool connection timeout was set to 60s instead of fail-fast 5s",
                impact="HIGH",
            ),
        ],
        action_items=[
            ActionItem(
                id="ACT-001",
                description="Refactor batch settlement job to lock exclusively by tenant partition",
                item_type=ActionItemType.PREVENTATIVE.value,
                owner="Billing Squad",
                priority=ActionItemPriority.P0.value,
                target_date="2026-09-01",
                status="OPEN",
            ),
        ],
        what_went_well=["Automated failover circuit breaker isolated payment queue"],
        what_went_poorly=["Lock contention metric had a 3-minute collection delay"],
        where_we_got_lucky=["Off-peak volume meant only 240 transactions were delayed"],
    )

    evidences = {
        "saturation_metrics": {"load_avg_1m": 4.5, "cpu_saturation_pct": 85.0},
        "git_commits": [
            {"hash": "f4e3d2c1", "author": "dev-eng", "date": "2026-08-27T08:00:00Z", "message": "chore: bump ORM pool timeout"}
        ],
        "git_diffs": "--- a/db.py\n+++ b/db.py\n+ lock_strategy = 'TABLE'",
        "system_logs": ["[ALERT] Payment lock timeout on worker-03", "[INFO] Worker restarted"],
    }

    return IncidentReport(
        incident_id="INC-2026-0827-01",
        title="Payment Processing Service Degradation",
        severity=IncidentSeverity.SEV_1.value,
        status=IncidentStatus.RESOLVED.value,
        date="2026-08-27",
        commander="SRE Lead",
        lead="Billing Principal Engineer",
        summary="Payment pipeline degraded due to distributed lock contention during batch settlement run.",
        user_impact="240 users experienced payment processing delays (>30s). Zero lost payments.",
        revenue_or_slo_impact="0.04% Error budget consumed for Q3 Payment Availability SLO.",
        timeline=timeline,
        metrics=metrics,
        rca=rca,
        evidences=evidences,
    )


def test_generator_render_markdown(sample_incident_report):
    generator = PostmortemGenerator()
    md = generator.render_markdown(sample_incident_report)

    assert "# 📋 Post-Mortem Report: Payment Processing Service Degradation" in md
    assert "INC-2026-0827-01" in md
    assert "SEV-1" in md
    assert "Executive Summary" in md
    assert "Key SRE Metrics Dashboard" in md
    assert "| **TTD** (Time to Detect) | `4m` |" in md
    assert "| **MTTR / TTR** (Time to Resolve) | `25m` |" in md
    assert "Structured 5-Whys Analysis" in md
    assert "ACT-001" in md
    assert "Billing Squad" in md
    assert "Sanitized Technical Evidence & Audit Trail" in md


def test_generator_export_to_file(sample_incident_report, tmp_path):
    generator = PostmortemGenerator()
    out_file = tmp_path / "postmortem-output.md"
    exported_path = generator.export_to_file(sample_incident_report, out_file)

    assert exported_path.is_file()
    content = exported_path.read_text(encoding="utf-8")
    assert "INC-2026-0827-01" in content


def test_generator_render_json(sample_incident_report):
    generator = PostmortemGenerator()
    json_str = generator.render_json(sample_incident_report)
    parsed = json.loads(json_str)

    assert parsed["incident_id"] == "INC-2026-0827-01"
    assert parsed["severity"] == "SEV-1"
    assert len(parsed["timeline"]) == 4
    assert parsed["metrics"]["mttr_formatted"] == "25m"


def test_generator_custom_template(sample_incident_report):
    custom_tmpl = "INCIDENT: {{ report.incident_id }} - {{ report.title }} [{{ report.metrics.mttr_formatted }}]"
    generator = PostmortemGenerator(custom_template=custom_tmpl)
    rendered = generator.render_markdown(sample_incident_report)

    assert rendered == "INCIDENT: INC-2026-0827-01 - Payment Processing Service Degradation [25m]"
