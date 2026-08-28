"""Tests for WebhookNotifier alert dispatching and retries."""

import asyncio
from unittest.mock import AsyncMock, patch
import httpx
import pytest
from prober.notifier import AlertEvent, WebhookNotifier


@pytest.mark.asyncio
async def test_notifier_no_url():
    """Verify notifier returns False when no URL configured."""
    notifier = WebhookNotifier(webhook_url=None)
    event = AlertEvent(
        target="https://example.com",
        probe_type="http",
        severity="WARNING",
        status="HTTP_500",
        summary="Service down",
    )
    result = await notifier.notify(event)
    assert result is False


@pytest.mark.asyncio
async def test_notifier_successful_dispatch():
    """Verify successful alert dispatch with HMAC signature."""
    notifier = WebhookNotifier(
        webhook_url="https://hooks.example.com/alerts",
        secret_token="my-webhook-secret-token",
        cooldown_seconds=0.0,
    )
    event = AlertEvent(
        target="https://api.example.com",
        probe_type="http",
        severity="CRITICAL",
        status="TIMEOUT",
        summary="API Gateway Timed Out",
        details={"latency_ms": 5000},
    )

    mock_resp = httpx.Response(status_code=200, request=httpx.Request("POST", "https://hooks.example.com/alerts"))
    with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
        mock_post.return_value = mock_resp
        success = await notifier.notify(event)

        assert success is True
        mock_post.assert_called_once()
        headers = mock_post.call_args[1]["headers"]
        assert "X-Signature-SHA256" in headers
        assert "X-Hub-Signature-256" in headers
        assert headers["Content-Type"] == "application/json"


@pytest.mark.asyncio
async def test_notifier_retry_on_server_error():
    """Verify retry logic on 500 server response."""
    notifier = WebhookNotifier(
        webhook_url="https://hooks.example.com/failing",
        cooldown_seconds=0.0,
        max_retries=2,
    )
    event = AlertEvent(
        target="https://service.internal",
        probe_type="tcp",
        severity="CRITICAL",
        status="CONN_REFUSED",
        summary="DB port down",
    )

    mock_resp = httpx.Response(status_code=500, request=httpx.Request("POST", "https://hooks.example.com/failing"))
    with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
        mock_post.return_value = mock_resp
        success = await notifier.notify(event)

        assert success is False
        assert mock_post.call_count == 2


@pytest.mark.asyncio
async def test_notifier_retry_on_exception():
    """Verify exception handling during HTTP dispatch."""
    notifier = WebhookNotifier(
        webhook_url="https://hooks.example.com/error",
        cooldown_seconds=0.0,
        max_retries=2,
    )
    event = AlertEvent(
        target="https://service.internal",
        probe_type="dns",
        severity="CRITICAL",
        status="NXDOMAIN",
        summary="DNS record missing",
    )

    with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
        mock_post.side_effect = httpx.ConnectError("Connection refused")
        success = await notifier.notify(event)

        assert success is False
        assert mock_post.call_count == 2
