"""Unit tests for StructuredAuditLogger and log sanitization (CWE-209)."""

from __future__ import annotations

import io
import json
from pathlib import Path

import pytest

from watchdog.logger import (
    StructuredAuditLogger,
    sanitize_data,
    sanitize_string,
)


def test_sanitize_string_api_keys():
    # OpenAI style
    mock_openai = "sk-" + "testdummytoken1234567890"
    raw = f"Connecting with token {mock_openai} to endpoint"
    sanitized = sanitize_string(raw)
    assert mock_openai not in sanitized
    assert "[REDACTED_API_KEY]" in sanitized

    # Google key
    mock_google = "AIzaSy" + "testgoogletarget00000000"
    raw_google = f"Key {mock_google} detected"
    sanitized_google = sanitize_string(raw_google)
    assert mock_google not in sanitized_google
    assert "[REDACTED_GOOGLE_KEY]" in sanitized_google

    # GitHub token
    mock_gh = "ghp_" + "testgithubtoken1234567890"
    raw_gh = f"GitHub token {mock_gh}"
    sanitized_gh = sanitize_string(raw_gh)
    assert mock_gh not in sanitized_gh
    assert "[REDACTED_GH_TOKEN]" in sanitized_gh


def test_sanitize_bearer_and_passwords():
    raw_bearer = "Authorization: Bearer my_test_bearer_token_123456789"
    sanitized_bearer = sanitize_string(raw_bearer)
    assert "my_test_bearer_token" not in sanitized_bearer
    assert "Bearer [REDACTED_BEARER]" in sanitized_bearer

    raw_pwd = "database password: 'my_test_db_pass_val'"
    sanitized_pwd = sanitize_string(raw_pwd)
    assert "my_test_db_pass_val" not in sanitized_pwd
    assert "[REDACTED]" in sanitized_pwd


def test_sanitize_private_paths():
    raw_path = "Reading private key from /home/testuser/.ssh/id_rsa and config /home/testuser/.aws/credentials"
    sanitized_path = sanitize_string(raw_path)
    assert ".ssh/id_rsa" not in sanitized_path
    assert ".aws/credentials" not in sanitized_path
    assert "[REDACTED_PATH]" in sanitized_path


def test_sanitize_nested_data_structures():
    mock_token = "sk-" + "dummytesttokenvalue0000000"
    mock_gh = "ghp_" + "dummyghtokenvalue0000000"
    nested = {
        "user": "sre-admin",
        "custom_token": mock_token,
        "details": {
            "oauth_token": mock_gh,
            "paths": ["/var/log/syslog", "/home/testuser/.config/secret.yaml"],
        },
    }

    sanitized = sanitize_data(nested)
    assert sanitized["user"] == "sre-admin"
    assert sanitized["custom_token"] == "[REDACTED_API_KEY]"
    assert sanitized["details"]["oauth_token"] == "[REDACTED_GH_TOKEN]"
    assert sanitized["details"]["paths"][0] == "/var/log/syslog"
    assert sanitized["details"]["paths"][1] == "[REDACTED_PATH]"


def test_structured_logger_emits_valid_jsonlines(tmp_path: Path):
    log_file = tmp_path / "audit.jsonl"
    stream = io.StringIO()
    logger = StructuredAuditLogger(log_file=log_file, stream=stream)

    logger.log_check(
        snapshot_summary={"cpu": 25.0, "ram": 40.0},
        anomalies_count=0,
    )

    logger.log_pre_remediation(
        runbook_name="clear_pagecache",
        circuit_breaker_state="CLOSED",
        anomaly_payload={"metric": "memory", "current": 95.0},
        dry_run=True,
    )

    logger.log_post_remediation(
        runbook_name="clear_pagecache",
        success=True,
        circuit_breaker_state="CLOSED",
        execution_time_ms=12.5,
        stdout="Flushed caches",
    )

    # Verify stream output
    stream_content = stream.getvalue().strip().split("\n")
    assert len(stream_content) == 3

    for line in stream_content:
        record = json.loads(line)
        assert "timestamp" in record
        assert "iso_time" in record
        assert "stage" in record

    # Verify file persistence
    assert log_file.is_file()
    file_lines = log_file.read_text(encoding="utf-8").strip().split("\n")
    assert len(file_lines) == 3
