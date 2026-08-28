"""Minute-by-minute incident timeline reconstruction and SRE metrics calculation engine.

Calculates exact Time to Detect (TTD), Mean Time to Acknowledge (MTTA / TTA),
Mean Time to Recover / Resolve (MTTR / TTR), and Time to Mitigate (TTM).
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Union

from pydantic import BaseModel, Field, field_validator

from postmortem.sanitizer import sanitize_data, sanitize_text


class EventType(str, Enum):
    """Standard taxonomy of incident timeline events."""

    INCIDENT_START = "INCIDENT_START"
    DETECTION = "DETECTION"
    ALERT = "ALERT"
    ACKNOWLEDGEMENT = "ACKNOWLEDGEMENT"
    INVESTIGATION = "INVESTIGATION"
    MITIGATION_ATTEMPT = "MITIGATION_ATTEMPT"
    CONTAINMENT = "CONTAINMENT"
    RECOVERY = "RECOVERY"
    RESOLVED = "RESOLVED"
    ROOT_CAUSE_IDENTIFIED = "ROOT_CAUSE_IDENTIFIED"
    STATUS_PAGE_UPDATED = "STATUS_PAGE_UPDATED"
    CUSTOM = "CUSTOM"


def parse_timestamp(ts: Union[str, datetime]) -> datetime:
    """Parse various timestamp formats into a timezone-aware UTC datetime."""
    if isinstance(ts, datetime):
        if ts.tzinfo is None:
            return ts.replace(tzinfo=timezone.utc)
        return ts.astimezone(timezone.utc)

    if not isinstance(ts, str) or not ts.strip():
        return datetime.now(timezone.utc)

    clean_ts = ts.strip()

    # Try ISO formats
    try:
        dt = datetime.fromisoformat(clean_ts.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except ValueError:
        pass

    current_year = datetime.now(timezone.utc).year

    # Common datetime string formats
    formats = [
        ("%Y-%m-%d %H:%M:%S", clean_ts),
        ("%Y-%m-%d %H:%M:%S%z", clean_ts),
        ("%Y-%m-%d %H:%M", clean_ts),
        ("%Y/%m/%d %H:%M:%S", clean_ts),
        ("%Y %b %d %H:%M:%S", f"{current_year} {clean_ts}"),
        ("%d/%b/%Y:%H:%M:%S %z", clean_ts),
    ]
    for fmt, val in formats:
        try:
            dt = datetime.strptime(val, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc)
        except ValueError:
            continue

    # Fallback to current UTC datetime
    return datetime.now(timezone.utc)


def format_duration(seconds: Optional[float]) -> str:
    """Format duration in seconds into human-readable representation."""
    if seconds is None:
        return "N/A"
    if seconds < 0:
        return "0s"

    total_secs = int(round(seconds))
    hours, remainder = divmod(total_secs, 3600)
    minutes, secs = divmod(remainder, 60)

    parts = []
    if hours > 0:
        parts.append(f"{hours}h")
    if minutes > 0:
        parts.append(f"{minutes}m")
    if secs > 0 or not parts:
        parts.append(f"{secs}s")

    return " ".join(parts)


class TimelineEvent(BaseModel):
    """Pydantic model representing an individual incident milestone."""

    timestamp: datetime
    event_type: str = EventType.CUSTOM.value
    description: str
    source: str = "MANUAL"
    impact_level: str = "INFO"
    details: Dict[str, Any] = Field(default_factory=dict)

    @field_validator("timestamp", mode="before")
    @classmethod
    def validate_timestamp(cls, v: Any) -> datetime:
        return parse_timestamp(v)

    @field_validator("description", "source", mode="before")
    @classmethod
    def sanitize_strings(cls, v: Any) -> str:
        return sanitize_text(str(v)) if v else ""

    @field_validator("details", mode="before")
    @classmethod
    def sanitize_details(cls, v: Any) -> Dict[str, Any]:
        return sanitize_data(v) if isinstance(v, dict) else {}


class IncidentMetrics(BaseModel):
    """Aggregated SRE metrics calculated from the incident timeline."""

    ttd_seconds: Optional[float] = None
    mtta_seconds: Optional[float] = None
    mttr_seconds: Optional[float] = None
    ttm_seconds: Optional[float] = None
    total_outage_seconds: Optional[float] = None

    ttd_formatted: str = "N/A"
    mtta_formatted: str = "N/A"
    mttr_formatted: str = "N/A"
    ttm_formatted: str = "N/A"
    total_outage_formatted: str = "N/A"

    start_time: Optional[str] = None
    detection_time: Optional[str] = None
    ack_time: Optional[str] = None
    mitigation_time: Optional[str] = None
    resolved_time: Optional[str] = None


class TimelineBuilder:
    """Builder and analyzer for incident timelines."""

    def __init__(self, sanitize: bool = True) -> None:
        self.sanitize = sanitize
        self.events: List[TimelineEvent] = []

    def add_event(
        self,
        timestamp: Union[str, datetime],
        event_type: Union[EventType, str],
        description: str,
        source: str = "MANUAL",
        impact_level: str = "INFO",
        details: Optional[Dict[str, Any]] = None,
    ) -> TimelineEvent:
        """Add an event to the timeline."""
        type_str = event_type.value if isinstance(event_type, EventType) else str(event_type).upper()
        event = TimelineEvent(
            timestamp=parse_timestamp(timestamp),
            event_type=type_str,
            description=sanitize_text(description) if self.sanitize else description,
            source=sanitize_text(source) if self.sanitize else source,
            impact_level=impact_level.upper(),
            details=sanitize_data(details or {}) if self.sanitize else (details or {}),
        )
        self.events.append(event)
        return event

    def add_event_object(self, event: TimelineEvent) -> None:
        """Add an existing TimelineEvent object."""
        self.events.append(event)

    def add_events_from_logs(self, logs: List[str]) -> int:
        """Heuristically extract timeline events from structured or syslog lines."""
        pattern = re.compile(
            r"^(\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2}|\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+(?:\[?(\w+)\]?\s+)?(.*)$"
        )
        added_count = 0

        for line in logs:
            match = pattern.match(line.strip())
            if match:
                ts_raw, tag, msg = match.groups()
                ts_parsed = parse_timestamp(ts_raw)

                event_type = EventType.INVESTIGATION.value
                impact = "INFO"
                lower_msg = msg.lower()
                if "alert" in lower_msg or "error" in lower_msg or "fatal" in lower_msg or "critical" in lower_msg:
                    event_type = EventType.ALERT.value
                    impact = "CRITICAL"
                elif "recovered" in lower_msg or "resolved" in lower_msg or "healthy" in lower_msg:
                    event_type = EventType.RECOVERY.value
                    impact = "INFO"

                self.add_event(
                    timestamp=ts_parsed,
                    event_type=event_type,
                    description=msg,
                    source=tag or "SYSTEM_LOG",
                    impact_level=impact,
                )
                added_count += 1
        return added_count

    def get_chronological_timeline(self) -> List[TimelineEvent]:
        """Return the timeline sorted chronologically in ascending order."""
        return sorted(self.events, key=lambda e: e.timestamp)

    def compute_metrics(self) -> IncidentMetrics:
        """Calculate TTD, MTTA, MTTR, and TTM based on milestone events."""
        sorted_events = self.get_chronological_timeline()
        if not sorted_events:
            return IncidentMetrics()

        start_dt: Optional[datetime] = None
        detection_dt: Optional[datetime] = None
        ack_dt: Optional[datetime] = None
        mitigation_dt: Optional[datetime] = None
        resolved_dt: Optional[datetime] = None

        # 1. First pass: find canonical event types
        for event in sorted_events:
            etype = event.event_type.upper()
            if etype in (EventType.INCIDENT_START.value, "START", "OUTAGE_START") and start_dt is None:
                start_dt = event.timestamp
            elif etype in (EventType.DETECTION.value, EventType.ALERT.value, "ALERT_TRIGGERED") and detection_dt is None:
                detection_dt = event.timestamp
            elif etype in (EventType.ACKNOWLEDGEMENT.value, "ACK", "PAGERDUTY_ACK") and ack_dt is None:
                ack_dt = event.timestamp
            elif etype in (EventType.CONTAINMENT.value, EventType.MITIGATION_ATTEMPT.value, "MITIGATED") and mitigation_dt is None:
                mitigation_dt = event.timestamp
            elif etype in (EventType.RECOVERY.value, EventType.RESOLVED.value, "CLOSED") and resolved_dt is None:
                resolved_dt = event.timestamp

        # Fallback start time if not explicitly tagged: first event in timeline
        if start_dt is None and sorted_events:
            start_dt = sorted_events[0].timestamp

        # Fallback resolved time if not explicitly tagged: last event if marked recovery or last event
        if resolved_dt is None and sorted_events:
            last_event = sorted_events[-1]
            if last_event.event_type.upper() in (EventType.RECOVERY.value, EventType.RESOLVED.value):
                resolved_dt = last_event.timestamp

        # Calculate exact deltas
        ttd_sec: Optional[float] = None
        if start_dt and detection_dt:
            ttd_sec = max(0.0, (detection_dt - start_dt).total_seconds())

        mtta_sec: Optional[float] = None
        if detection_dt and ack_dt:
            mtta_sec = max(0.0, (ack_dt - detection_dt).total_seconds())
        elif start_dt and ack_dt:
            mtta_sec = max(0.0, (ack_dt - start_dt).total_seconds())

        ttm_sec: Optional[float] = None
        if start_dt and mitigation_dt:
            ttm_sec = max(0.0, (mitigation_dt - start_dt).total_seconds())

        mttr_sec: Optional[float] = None
        if start_dt and resolved_dt:
            mttr_sec = max(0.0, (resolved_dt - start_dt).total_seconds())

        total_outage_sec = mttr_sec or ttm_sec

        return IncidentMetrics(
            ttd_seconds=ttd_sec,
            mtta_seconds=mtta_sec,
            mttr_seconds=mttr_sec,
            ttm_seconds=ttm_sec,
            total_outage_seconds=total_outage_sec,
            ttd_formatted=format_duration(ttd_sec),
            mtta_formatted=format_duration(mtta_sec),
            mttr_formatted=format_duration(mttr_sec),
            ttm_formatted=format_duration(ttm_sec),
            total_outage_formatted=format_duration(total_outage_sec),
            start_time=start_dt.isoformat() if start_dt else None,
            detection_time=detection_dt.isoformat() if detection_dt else None,
            ack_time=ack_dt.isoformat() if ack_dt else None,
            mitigation_time=mitigation_dt.isoformat() if mitigation_dt else None,
            resolved_time=resolved_dt.isoformat() if resolved_dt else None,
        )
