"""Secure Webhook Alerting and Notification engine."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import time
from datetime import datetime, timezone
from typing import Any, Dict, Optional

import httpx
from pydantic import BaseModel, Field

from prober.probes.http import sanitize_url

logger = logging.getLogger(__name__)


class AlertEvent(BaseModel):
    """Event model representing a detected degradation or failure."""

    target: str
    probe_type: str
    severity: str = "WARNING"  # INFO, WARNING, CRITICAL, EMERGENCY
    status: str
    summary: str
    details: Dict[str, Any] = Field(default_factory=dict)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


def generate_hmac_signature(payload_bytes: bytes, secret: str) -> str:
    """Generate SHA256 HMAC signature for webhook payload verification."""
    return hmac.new(
        key=secret.encode("utf-8"),
        msg=payload_bytes,
        digestmod=hashlib.sha256,
    ).hexdigest()


def verify_hmac_signature(payload_bytes: bytes, secret: str, signature: str) -> bool:
    """Verify HMAC signature in constant time (CWE-208 mitigation)."""
    expected = generate_hmac_signature(payload_bytes, secret)
    return hmac.compare_digest(expected, signature)


class WebhookNotifier:
    """Dispatches encrypted/signed alert notifications to configured webhooks."""

    def __init__(
        self,
        webhook_url: Optional[str] = None,
        secret_token: Optional[str] = None,
        timeout: float = 5.0,
        cooldown_seconds: float = 300.0,
        max_retries: int = 3,
    ) -> None:
        self.webhook_url = webhook_url
        self.secret_token = secret_token
        self.timeout = timeout
        self.cooldown_seconds = cooldown_seconds
        self.max_retries = max_retries
        self._last_alert_time: Dict[str, float] = {}

    def should_alert(self, target_key: str) -> bool:
        """Evaluate if alert is allowed under cooldown throttling to prevent alert storms."""
        now = time.time()
        last_time = self._last_alert_time.get(target_key, 0.0)
        if now - last_time >= self.cooldown_seconds:
            self._last_alert_time[target_key] = now
            return True
        return False

    async def notify(self, event: AlertEvent) -> bool:
        """Send structured alert JSON to webhook endpoint with retry and signature verification.

        Args:
            event: The alert event details.

        Returns:
            True if delivered successfully, False otherwise.
        """
        if not self.webhook_url:
            logger.warning("No webhook URL configured; skipping alert dispatch")
            return False

        target_key = f"{event.target}:{event.severity}:{event.status}"
        if not self.should_alert(target_key):
            logger.info("Throttling alert for %s (cooldown active)", target_key)
            return False

        payload_dict = {
            "source": "synthetic-blackbox-prober",
            "target": event.target,
            "probe_type": event.probe_type,
            "severity": event.severity,
            "status": event.status,
            "summary": event.summary,
            "details": event.details,
            "timestamp": event.timestamp.isoformat(),
        }

        payload_bytes = json.dumps(payload_dict, default=str).encode("utf-8")
        headers = {
            "Content-Type": "application/json",
            "User-Agent": "SyntheticBlackboxProber-Notifier/0.1.0",
        }

        if self.secret_token:
            sig = generate_hmac_signature(payload_bytes, self.secret_token)
            headers["X-Signature-SHA256"] = sig
            headers["X-Hub-Signature-256"] = f"sha256={sig}"

        sanitized_url = sanitize_url(self.webhook_url)

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            for attempt in range(1, self.max_retries + 1):
                try:
                    response = await client.post(
                        self.webhook_url,
                        content=payload_bytes,
                        headers=headers,
                    )
                    if response.is_success:
                        logger.info("Alert delivered to %s (attempt %d)", sanitized_url, attempt)
                        return True
                    else:
                        logger.warning(
                            "Webhook %s responded with status %d (attempt %d)",
                            sanitized_url,
                            response.status_code,
                            attempt,
                        )
                except Exception as e:
                    logger.warning("Failed to send webhook to %s (attempt %d): %s", sanitized_url, attempt, e)

                if attempt < self.max_retries:
                    await asyncio.sleep(0.5 * (2 ** (attempt - 1)))

        return False
