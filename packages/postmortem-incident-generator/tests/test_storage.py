import pytest
from postmortem.generator import IncidentReport, IncidentSeverity, IncidentStatus
from postmortem.rca_engine import ActionItem, ActionItemPriority, ActionItemType, FiveWhys, RCAResult
from postmortem.storage import IncidentStorage
from postmortem.timeline_builder import IncidentMetrics, TimelineEvent


@pytest.fixture
def test_storage(tmp_path):
    db_file = tmp_path / "test_incidents.db"
    return IncidentStorage(db_path=db_file)


@pytest.fixture
def sample_report():
    timeline = [
        TimelineEvent(
            timestamp="2026-08-27T08:00:00Z",
            event_type="INCIDENT_START",
            description="DNS resolution failure on core edge",
            source="Monitor",
        ),
        TimelineEvent(
            timestamp="2026-08-27T08:10:00Z",
            event_type="RESOLVED",
            description="DNS failover to secondary provider",
            source="SRE Lead",
        ),
    ]
    metrics = IncidentMetrics(
        ttd_seconds=60.0,
        mttr_seconds=600.0,
        ttd_formatted="1m",
        mttr_formatted="10m",
    )
    rca = RCAResult(
        trigger_event="BGP route flap at transit provider",
        root_cause_summary="DNS authoritative name server unreachable",
        five_whys=FiveWhys(
            problem_statement="Edge DNS failed",
            why_chain=["Upstream route dropped", "BGP flap"],
            root_cause="BGP flap",
        ),
        action_items=[
            ActionItem(
                id="ACT-001",
                description="Implement dual-vendor Anycast DNS routing",
                priority=ActionItemPriority.P0.value,
                owner="Network Team",
            )
        ],
    )
    return IncidentReport(
        incident_id="INC-DNS-001",
        title="Edge DNS Resolution Failure",
        severity=IncidentSeverity.SEV_1.value,
        status=IncidentStatus.RESOLVED.value,
        date="2026-08-27",
        commander="Alice SRE",
        lead="Bob NetOps",
        summary="Edge DNS became unreachable for 10 minutes.",
        user_impact="5% of global requests failed DNS lookup.",
        timeline=timeline,
        metrics=metrics,
        rca=rca,
        evidences={"logs": ["DNS timeout"]},
    )


def test_storage_save_and_get(test_storage, sample_report):
    saved_id = test_storage.save_incident(sample_report)
    assert saved_id == "INC-DNS-001"

    retrieved = test_storage.get_incident("INC-DNS-001")
    assert retrieved is not None
    assert retrieved.incident_id == "INC-DNS-001"
    assert retrieved.title == "Edge DNS Resolution Failure"
    assert retrieved.severity == "SEV-1"
    assert len(retrieved.timeline) == 2
    assert retrieved.metrics.mttr_formatted == "10m"
    assert retrieved.rca.five_whys.root_cause == "BGP flap"
    assert len(retrieved.rca.action_items) == 1
    assert retrieved.rca.action_items[0].id == "ACT-001"


def test_storage_get_nonexistent(test_storage):
    assert test_storage.get_incident("NON_EXISTENT") is None


def test_storage_list_and_filter(test_storage, sample_report):
    test_storage.save_incident(sample_report)

    # Add second incident with different severity
    report2 = sample_report.model_copy(deep=True)
    report2.incident_id = "INC-APP-002"
    report2.title = "Application Minor Glitch"
    report2.severity = IncidentSeverity.SEV_3.value
    test_storage.save_incident(report2)

    all_incidents = test_storage.list_incidents()
    assert len(all_incidents) == 2

    sev1_incidents = test_storage.list_incidents(severity="SEV-1")
    assert len(sev1_incidents) == 1
    assert sev1_incidents[0]["incident_id"] == "INC-DNS-001"

    sev3_incidents = test_storage.list_incidents(severity="SEV-3")
    assert len(sev3_incidents) == 1
    assert sev3_incidents[0]["incident_id"] == "INC-APP-002"


def test_storage_search(test_storage, sample_report):
    test_storage.save_incident(sample_report)

    results = test_storage.search_incidents("DNS")
    assert len(results) == 1
    assert results[0]["incident_id"] == "INC-DNS-001"

    empty_results = test_storage.search_incidents("NonExistentKeywordXYZ")
    assert len(empty_results) == 0


def test_storage_update_status(test_storage, sample_report):
    test_storage.save_incident(sample_report)

    success = test_storage.update_incident_status("INC-DNS-001", "CLOSED")
    assert success is True

    updated = test_storage.get_incident("INC-DNS-001")
    assert updated.status == "CLOSED"

    fail = test_storage.update_incident_status("INC-DOES-NOT-EXIST", "CLOSED")
    assert fail is False


def test_storage_delete_cascade(test_storage, sample_report):
    test_storage.save_incident(sample_report)
    assert test_storage.get_incident("INC-DNS-001") is not None

    deleted = test_storage.delete_incident("INC-DNS-001")
    assert deleted is True
    assert test_storage.get_incident("INC-DNS-001") is None

    # Check that child records are deleted in SQLite
    with test_storage._get_connection() as conn:
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM timeline_events WHERE incident_id = ?", ("INC-DNS-001",))
        assert cur.fetchone()[0] == 0
        cur.execute("SELECT COUNT(*) FROM action_items WHERE incident_id = ?", ("INC-DNS-001",))
        assert cur.fetchone()[0] == 0


def test_storage_in_memory():
    storage = IncidentStorage(db_path=":memory:")
    assert storage.list_incidents() == []
