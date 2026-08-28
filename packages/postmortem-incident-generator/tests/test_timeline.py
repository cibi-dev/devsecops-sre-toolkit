from datetime import datetime, timezone
import pytest
from postmortem.timeline_builder import (
    EventType,
    IncidentMetrics,
    TimelineBuilder,
    TimelineEvent,
    format_duration,
    parse_timestamp,
)


def test_parse_timestamp_variations():
    dt_iso = parse_timestamp("2026-08-27T10:15:30Z")
    assert dt_iso.year == 2026
    assert dt_iso.tzinfo is not None

    dt_str = parse_timestamp("2026-08-27 10:15:30")
    assert dt_str.year == 2026
    assert dt_str.minute == 15

    dt_slash = parse_timestamp("2026/08/27 10:15:30")
    assert dt_slash.year == 2026

    dt_short = parse_timestamp("2026-08-27 10:15")
    assert dt_short.minute == 15

    dt_syslog = parse_timestamp("Aug 27 10:15:30")
    assert dt_syslog.month == 8

    dt_obj = datetime(2026, 8, 27, 10, 0, 0)
    dt_from_obj = parse_timestamp(dt_obj)
    assert dt_from_obj.tzinfo == timezone.utc

    dt_fallback = parse_timestamp("")
    assert dt_fallback.year == datetime.now(timezone.utc).year

    dt_invalid = parse_timestamp("invalid-date-string-xyz")
    assert dt_invalid.year == datetime.now(timezone.utc).year


def test_format_duration():
    assert format_duration(None) == "N/A"
    assert format_duration(-10) == "0s"
    assert format_duration(0) == "0s"
    assert format_duration(45) == "45s"
    assert format_duration(125) == "2m 5s"
    assert format_duration(3665) == "1h 1m 5s"
    assert format_duration(7200) == "2h"


def test_timeline_chronological_ordering():
    tb = TimelineBuilder()
    tb.add_event(timestamp="2026-08-27T10:30:00Z", event_type=EventType.RESOLVED, description="Resolution")
    tb.add_event(timestamp="2026-08-27T10:00:00Z", event_type=EventType.INCIDENT_START, description="Outage starts")
    tb.add_event(timestamp="2026-08-27T10:05:00Z", event_type=EventType.DETECTION, description="Alert triggered")

    sorted_events = tb.get_chronological_timeline()
    assert len(sorted_events) == 3
    assert sorted_events[0].event_type == EventType.INCIDENT_START.value
    assert sorted_events[1].event_type == EventType.DETECTION.value
    assert sorted_events[2].event_type == EventType.RESOLVED.value


def test_timeline_metrics_calculation_exact():
    tb = TimelineBuilder()
    tb.add_event("2026-08-27T10:00:00Z", EventType.INCIDENT_START, "Traffic surge causes gateway 502s")
    tb.add_event("2026-08-27T10:04:00Z", EventType.DETECTION, "Prometheus alert 5xx rate > 5%")
    tb.add_event("2026-08-27T10:06:00Z", EventType.ACKNOWLEDGEMENT, "On-call SRE paged and acked")
    tb.add_event("2026-08-27T10:20:00Z", EventType.CONTAINMENT, "Rate limiting activated, error rate dropped")
    tb.add_event("2026-08-27T10:35:00Z", EventType.RESOLVED, "Backend pool scaled and fully stable")

    metrics: IncidentMetrics = tb.compute_metrics()

    assert metrics.ttd_seconds == 240.0
    assert metrics.ttd_formatted == "4m"

    assert metrics.mtta_seconds == 120.0
    assert metrics.mtta_formatted == "2m"

    assert metrics.ttm_seconds == 1200.0
    assert metrics.ttm_formatted == "20m"

    assert metrics.mttr_seconds == 2100.0
    assert metrics.mttr_formatted == "35m"

    assert metrics.total_outage_seconds == 2100.0
    assert metrics.total_outage_formatted == "35m"


def test_timeline_metrics_ack_without_detection():
    tb = TimelineBuilder()
    tb.add_event("2026-08-27T10:00:00Z", "START", "Outage begins")
    tb.add_event("2026-08-27T10:05:00Z", "ACK", "Direct ack")
    tb.add_event("2026-08-27T10:30:00Z", "CLOSED", "Resolved")

    metrics = tb.compute_metrics()
    assert metrics.mtta_seconds == 300.0
    assert metrics.mttr_seconds == 1800.0


def test_timeline_add_events_from_logs():
    raw_logs = [
        "2026-08-27 12:00:00 [monitor] Critical error: database connection refused",
        "2026-08-27 12:15:00 [monitor] System recovered and healthy",
        "Aug 27 12:20:00 host[123]: normal operation log",
        "invalid non timestamp line",
    ]
    tb = TimelineBuilder()
    added = tb.add_events_from_logs(raw_logs)
    assert added == 3
    events = tb.get_chronological_timeline()
    assert len(events) == 3
    assert events[0].event_type == EventType.ALERT.value
    assert events[0].impact_level == "CRITICAL"
    assert events[1].event_type == EventType.RECOVERY.value


def test_timeline_empty_metrics():
    tb = TimelineBuilder()
    metrics = tb.compute_metrics()
    assert metrics.ttd_seconds is None
    assert metrics.ttd_formatted == "N/A"
    assert metrics.mttr_seconds is None
