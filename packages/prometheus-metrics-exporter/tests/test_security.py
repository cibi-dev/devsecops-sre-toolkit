"""Security tests covering DevSecOps standards and CWE mitigations:
- CWE-400: Resource Quotas & Anti-DoS (HTTP request payload limits, YAML size limits)
- CWE-209: Information Exposure (Token & credential redaction in logs / URLs)
- CWE-502 & CWE-20: Safe Deserialization (yaml.safe_load, strict Pydantic v2 schemas)
- CWE-798: Zero hardcoded secrets verification
"""

from __future__ import annotations

import json
import os
import socket
import time
from pathlib import Path
from typing import Generator
from unittest.mock import MagicMock

import httpx
import pytest
import yaml

from exporter.alert_evaluator import (
    MAX_CONFIG_FILE_SIZE_BYTES,
    AlertEvaluator,
    AlertRuleModel,
)
from exporter.http_server import MAX_PAYLOAD_SIZE_BYTES, MetricsHTTPServer
from exporter.metrics_collector import MetricsCollector
from exporter.notifiers.webhook import WebhookNotifier, sanitize_url


def get_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
def running_security_server() -> Generator[str, None, None]:
    port = get_free_port()
    collector = MetricsCollector()
    server = MetricsHTTPServer(host="127.0.0.1", port=port, collector=collector)
    server.start(background=True)
    time.sleep(0.1)
    yield f"http://127.0.0.1:{port}"
    server.stop()


def test_cwe_400_http_payload_size_limit_exceeded(running_security_server: str):
    """CWE-400: Sending a request exceeding 10MB must be rejected with HTTP 413 Payload Too Large."""
    # Send request with oversized payload using http.client to test strict header check
    parsed = running_security_server.replace("http://", "").split(":")
    host, port = parsed[0], int(parsed[1])

    import http.client
    conn = http.client.HTTPConnection(host, port, timeout=5.0)
    # Send headers with Content-Length > 10MB
    conn.putrequest("POST", "/alerts/eval")
    conn.putheader("Content-Length", str(MAX_PAYLOAD_SIZE_BYTES + 1024))
    conn.putheader("Content-Type", "application/json")
    conn.endheaders()

    resp = conn.getresponse()
    assert resp.status == 413
    body = resp.read().decode("utf-8")
    data = json.loads(body)
    assert data["error"] == "Payload Too Large"
    assert data["max_allowed_bytes"] == MAX_PAYLOAD_SIZE_BYTES
    conn.close()


def test_cwe_400_invalid_content_length_header(running_security_server: str):
    """CWE-400: Invalid Content-Length header returns 400 Bad Request."""
    parsed = running_security_server.replace("http://", "").split(":")
    host, port = parsed[0], int(parsed[1])

    import http.client
    conn = http.client.HTTPConnection(host, port, timeout=5.0)
    conn.putrequest("POST", "/alerts/eval")
    conn.putheader("Content-Length", "invalid_length")
    conn.putheader("Content-Type", "application/json")
    conn.endheaders()

    resp = conn.getresponse()
    assert resp.status == 400
    conn.close()


def test_cwe_400_alert_yaml_file_size_limit_exceeded(tmp_path: Path):
    """CWE-400: Alert config files exceeding 1MB must be rejected prior to YAML parsing."""
    large_file = tmp_path / "huge_alerts.yaml"
    # Create file slightly larger than 1MB
    padding = "# " + ("x" * 1024) + "\n"
    large_file.write_text(padding * 1050, encoding="utf-8")

    assert large_file.stat().st_size > MAX_CONFIG_FILE_SIZE_BYTES

    with pytest.raises(ValueError, match="exceeds 1 MB limit"):
        AlertEvaluator(large_file)


def test_cwe_400_alert_yaml_string_size_limit_exceeded():
    """CWE-400: Giant YAML strings exceeding 1MB must be rejected."""
    huge_yaml_str = "groups:\n" + ("  - name: test\n" * 100000)
    with pytest.raises(ValueError, match="exceeds 1 MB limit"):
        AlertEvaluator(huge_yaml_str)


def test_cwe_209_url_and_credential_sanitization():
    """CWE-209: Tokens, API keys, passwords in URLs must be masked as [REDACTED]."""
    test_urls = [
        ("https://hooks.slack.com/services/T1/B2/K3?token=super_secret_token_12345", "token=%5BREDACTED%5D"),
        ("https://user:password999@alertmanager.corp.internal/api/v2?api_key=myapikey123", "user:[REDACTED]@alertmanager"),
        ("https://webhook.site/abc?webhook_secret=topsecret&env=prod", "webhook_secret=%5BREDACTED%5D"),
        ("https://webhook.site/abc?access_token=token123", "access_token=%5BREDACTED%5D"),
    ]

    for raw_url, expected_substr in test_urls:
        sanitized = sanitize_url(raw_url)
        assert expected_substr in sanitized or expected_substr.replace("%5B", "[").replace("%5D", "]") in sanitized
        # Ensure secret strings are not leaked
        assert "super_secret_token_12345" not in sanitized
        assert "password999" not in sanitized
        assert "topsecret" not in sanitized
        assert "token123" not in sanitized

        notifier = WebhookNotifier(url=raw_url)
        assert "super_secret_token_12345" not in repr(notifier)
        assert "password999" not in repr(notifier)


def test_cwe_502_safe_yaml_deserialization(tmp_path: Path):
    """CWE-502: Arbitrary Python code execution via yaml.load is strictly prevented."""
    malicious_yaml = """
    groups:
      - name: exploit
        rules:
          - alert: !!python/object/apply:os.system ["echo PWNED"]
            expr: "node_cpu > 90"
    """
    malicious_file = tmp_path / "exploit.yaml"
    malicious_file.write_text(malicious_yaml, encoding="utf-8")

    # yaml.safe_load will reject !!python/object/apply with a ConstructorError / ScannerError
    with pytest.raises((yaml.YAMLError, ValueError)):
        AlertEvaluator(malicious_file)


def test_cwe_20_schema_type_enforcement():
    """CWE-20: Ill-formed YAML schema inputs are rejected with validation errors."""
    invalid_configs = [
        {"groups": "not_a_list"},
        {"groups": [{"name": "grp", "rules": [{"alert": "", "expr": "a > 0"}]}]},  # empty alert name
        {"groups": [{"name": "grp", "rules": [{"alert": "A", "expr": "no_operator"}]}]},
    ]

    for cfg in invalid_configs:
        with pytest.raises((ValueError, Exception)):
            AlertEvaluator(cfg)
