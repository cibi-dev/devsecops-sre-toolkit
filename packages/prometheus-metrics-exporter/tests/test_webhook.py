"""Unit tests for WebhookNotifier, exponential backoff, and URL sanitization."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import httpx
import pytest

from exporter.alert_evaluator import AlertInstance, AlertRuleModel, AlertState
from exporter.notifiers.webhook import (
    WebhookNotifier,
    WebhookPayload,
    sanitize_url,
)


def test_sanitize_url_tokens_and_credentials():
    url_with_token = "https://hooks.slack.com/services/T123/B456/XYZ?token=secret123&format=json"
    sanitized = sanitize_url(url_with_token)
    assert "token=%5BREDACTED%5D" in sanitized or "token=[REDACTED]" in sanitized
    assert "format=json" in sanitized
    assert "secret123" not in sanitized

    url_with_auth = "https://admin:supersecret@alertmanager.internal/api/v2/alerts?api_key=my_key"
    sanitized_auth = sanitize_url(url_with_auth)
    assert "admin:[REDACTED]@alertmanager.internal" in sanitized_auth
    assert "api_key=%5BREDACTED%5D" in sanitized_auth or "api_key=[REDACTED]" in sanitized_auth
    assert "supersecret" not in sanitized_auth
    assert "my_key" not in sanitized_auth

    assert sanitize_url("") == ""


def test_webhook_payload_structure():
    rule = AlertRuleModel(
        alert="HighCPU",
        expr="node_cpu > 90",
        severity="critical",
        labels={"instance": "server-01"},
        annotations={"summary": "CPU overload"},
    )
    instance = AlertInstance(rule=rule, group_name="compute")
    instance.state = AlertState.FIRING
    instance.current_value = 95.5
    instance.active_since = 1700000000.0
    instance.firing_since = 1700000030.0

    payload = WebhookPayload.from_alert_instances([instance])

    assert payload["version"] == "4"
    assert payload["status"] == "firing"
    assert len(payload["alerts"]) == 1

    alert_obj = payload["alerts"][0]
    assert alert_obj["status"] == "firing"
    assert alert_obj["labels"]["alertname"] == "HighCPU"
    assert alert_obj["labels"]["severity"] == "critical"
    assert alert_obj["labels"]["instance"] == "server-01"
    assert alert_obj["annotations"]["summary"] == "CPU overload"
    assert "fingerprint" in alert_obj
    assert alert_obj["value"] == 95.5


def test_webhook_dispatch_success():
    rule = AlertRuleModel(alert="DiskFull", expr="disk > 95", severity="critical")
    instance = AlertInstance(rule=rule)
    instance.state = AlertState.FIRING

    mock_client = MagicMock(spec=httpx.Client)
    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.status_code = 200
    mock_client.post.return_value = mock_resp

    notifier = WebhookNotifier(
        url="https://hooks.example.com/alerts?token=xyz",
        client=mock_client,
    )

    success = notifier.dispatch([instance])
    assert success is True
    assert mock_client.post.call_count == 1
    assert "token=%5BREDACTED%5D" in notifier.sanitized_url or "token=[REDACTED]" in notifier.sanitized_url
    assert "xyz" not in repr(notifier)


def test_webhook_dispatch_client_error_no_retry():
    rule = AlertRuleModel(alert="Test", expr="a > 0")
    instance = AlertInstance(rule=rule)
    instance.state = AlertState.FIRING

    mock_client = MagicMock(spec=httpx.Client)
    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.status_code = 400
    mock_resp.text = "Bad Request"
    mock_client.post.return_value = mock_resp

    notifier = WebhookNotifier(
        url="https://hooks.example.com/alerts",
        max_retries=3,
        client=mock_client,
    )

    success = notifier.dispatch([instance])
    assert success is False
    # Should not retry on 4xx error
    assert mock_client.post.call_count == 1


def test_webhook_dispatch_server_error_with_retry_and_recovery():
    rule = AlertRuleModel(alert="Test", expr="a > 0")
    instance = AlertInstance(rule=rule)
    instance.state = AlertState.FIRING

    mock_client = MagicMock(spec=httpx.Client)
    resp_503 = MagicMock(spec=httpx.Response)
    resp_503.status_code = 503

    resp_200 = MagicMock(spec=httpx.Response)
    resp_200.status_code = 200

    # Fail twice with 503, succeed on 3rd attempt
    mock_client.post.side_effect = [resp_503, resp_503, resp_200]

    notifier = WebhookNotifier(
        url="https://hooks.example.com/alerts",
        max_retries=3,
        initial_backoff=0.01,  # fast test
        jitter_factor=0.0,
        client=mock_client,
    )

    success = notifier.dispatch([instance])
    assert success is True
    assert mock_client.post.call_count == 3


def test_sanitize_url_user_without_password():
    url = "https://myuser@webhook.site/alerts"
    sanitized = sanitize_url(url)
    assert "[REDACTED]@webhook.site" in sanitized


def test_webhook_dispatch_network_exception_retry_exhaustion():
    rule = AlertRuleModel(alert="Test", expr="a > 0")
    instance = AlertInstance(rule=rule)
    instance.state = AlertState.FIRING

    mock_client = MagicMock(spec=httpx.Client)
    mock_client.post.side_effect = httpx.ConnectError("Connection refused")

    notifier = WebhookNotifier(
        url="https://hooks.example.com/alerts",
        max_retries=2,
        initial_backoff=0.01,
        jitter_factor=0.0,
        client=mock_client,
    )

    success = notifier.dispatch([instance])
    assert success is False
    assert mock_client.post.call_count == 3  # 1 initial + 2 retries


def test_webhook_empty_alerts():
    notifier = WebhookNotifier(url="https://hooks.example.com")
    # Empty list should succeed immediately without network call
    assert notifier.dispatch([]) is True
