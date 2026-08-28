"""Structured JSON-Lines audit logging with PII/secret sanitization for Linux SRE Watchdog.

Enforces strict sanitization (CWE-209 / CWE-22) for pre/post remediation audit trails.
"""

from __future__ import annotations

import json
import logging
import re
import sys
import time
from pathlib import Path
from typing import Any, Optional, TextIO

from pydantic import BaseModel, ConfigDict, Field

# Sensitive pattern matching for token/secret redaction (CWE-209)
SECRET_PATTERNS = [
    (re.compile(r"sk-[a-zA-Z0-9_\-]{20,}", re.IGNORECASE), "[REDACTED_API_KEY]"),
    (re.compile(r"AIza[0-9A-Za-z\-_]{20,}", re.IGNORECASE), "[REDACTED_GOOGLE_KEY]"),
    (re.compile(r"ghp_[a-zA-Z0-9]{20,}", re.IGNORECASE), "[REDACTED_GH_TOKEN]"),
    (re.compile(r"Bearer\s+[a-zA-Z0-9_\-\.]{15,}", re.IGNORECASE), "Bearer [REDACTED_BEARER]"),
    (re.compile(r"(password|secret|token|passwd|auth)\s*[:=]\s*['\"]?[^\s'\",]+['\"]?", re.IGNORECASE), r"\1=[REDACTED]"),
    (re.compile(r"/home/[a-zA-Z0-9_\-]+/\.(ssh|gnupg|aws|kube|config)/[^\s'\",]*", re.IGNORECASE), "[REDACTED_PATH]"),
]


def sanitize_string(value: str) -> str:
    """Mask sensitive tokens and private paths in strings."""
    if not isinstance(value, str):
        return value
    sanitized = value
    for pattern, replacement in SECRET_PATTERNS:
        sanitized = pattern.sub(replacement, sanitized)
    return sanitized


def sanitize_data(data: Any) -> Any:
    """Recursively sanitize dictionary, list, or primitive data structures."""
    if isinstance(data, str):
        return sanitize_string(data)
    elif isinstance(data, dict):
        return {sanitize_string(k): sanitize_data(v) for k, v in data.items()}
    elif isinstance(data, (list, tuple, set)):
        return [sanitize_data(x) for x in data]
    return data


class SREAuditEvent(BaseModel):
    """Schema for SRE watchdog structured audit log records."""

    model_config = ConfigDict(extra="forbid")

    timestamp: float = Field(default_factory=time.time, description="Epoch timestamp of event")
    iso_time: str = Field(description="ISO-8601 formatted timestamp")
    stage: str = Field(description="Audit stage: PRE_REMEDIATION, POST_REMEDIATION, CHECK, ALERT")
    runbook_name: Optional[str] = Field(default=None, description="Name of runbook involved")
    success: Optional[bool] = Field(default=None, description="Outcome of runbook if applicable")
    circuit_breaker_state: Optional[str] = Field(default=None, description="State of circuit breaker")
    anomaly: Optional[dict[str, Any]] = Field(default=None, description="Triggering anomaly payload")
    metrics_diff: Optional[dict[str, Any]] = Field(default=None, description="Pre/post metrics diff")
    details: dict[str, Any] = Field(default_factory=dict, description="Arbitrary sanitized context")


class StructuredAuditLogger:
    """Thread-safe JSON-Lines structured audit logger for SRE events."""

    def __init__(
        self,
        log_file: Optional[Path | str] = None,
        stream: Optional[TextIO] = None,
        level: int = logging.INFO,
    ) -> None:
        self._stream = stream or sys.stdout
        self._log_file = Path(log_file) if log_file else None
        self._level = level

        if self._log_file:
            self._log_file.parent.mkdir(parents=True, exist_ok=True)

    def _emit(self, event: SREAuditEvent) -> str:
        """Serialize event to sanitized JSON-Lines and write to output streams."""
        raw_dict = event.model_dump()
        sanitized_dict = sanitize_data(raw_dict)
        json_line = json.dumps(sanitized_dict, ensure_ascii=False)

        try:
            self._stream.write(f"{json_line}\n")
            self._stream.flush()
        except OSError:
            pass

        if self._log_file:
            try:
                with self._log_file.open("a", encoding="utf-8") as f:
                    f.write(f"{json_line}\n")
            except OSError:
                pass

        return json_line

    def log_check(
        self,
        snapshot_summary: dict[str, Any],
        anomalies_count: int,
    ) -> str:
        """Log regular inspection check."""
        now = time.time()
        event = SREAuditEvent(
            timestamp=now,
            iso_time=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now)),
            stage="CHECK",
            details={
                "snapshot": snapshot_summary,
                "anomalies_detected": anomalies_count,
            },
        )
        return self._emit(event)

    def log_pre_remediation(
        self,
        runbook_name: str,
        circuit_breaker_state: str,
        anomaly_payload: dict[str, Any],
        dry_run: bool = False,
    ) -> str:
        """Log pre-remediation intent and circuit breaker gate status."""
        now = time.time()
        event = SREAuditEvent(
            timestamp=now,
            iso_time=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now)),
            stage="PRE_REMEDIATION",
            runbook_name=runbook_name,
            circuit_breaker_state=circuit_breaker_state,
            anomaly=anomaly_payload,
            details={"dry_run": dry_run},
        )
        return self._emit(event)

    def log_post_remediation(
        self,
        runbook_name: str,
        success: bool,
        circuit_breaker_state: str,
        execution_time_ms: float,
        stdout: str = "",
        stderr: str = "",
        details: Optional[dict[str, Any]] = None,
    ) -> str:
        """Log post-remediation outcome and execution details."""
        now = time.time()
        event = SREAuditEvent(
            timestamp=now,
            iso_time=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now)),
            stage="POST_REMEDIATION",
            runbook_name=runbook_name,
            success=success,
            circuit_breaker_state=circuit_breaker_state,
            details={
                "execution_time_ms": execution_time_ms,
                "stdout": stdout,
                "stderr": stderr,
                **(details or {}),
            },
        )
        return self._emit(event)
