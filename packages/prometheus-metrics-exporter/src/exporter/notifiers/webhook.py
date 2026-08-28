"""HTTP POST Webhook alert notifier with exponential backoff, jitter, and URL sanitization.

Implements CWE-209 sanitization to redact authentication tokens and secrets from logs and URLs.
"""

from __future__ import annotations

import datetime
import hashlib
import logging
import random
import re
import time
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import httpx

from ..alert_evaluator import AlertInstance, AlertState

logger = logging.getLogger(__name__)

# Sensitive query parameter names to mask in URLs (CWE-209 compliance)
SENSITIVE_PARAM_NAMES = {
    "token",
    "access_token",
    "auth",
    "api_key",
    "apikey",
    "key",
    "secret",
    "webhook_secret",
    "password",
    "pass",
    "bearer",
}


def sanitize_url(url: str) -> str:
    """Redacts credentials and sensitive query parameters from a URL string.

    Example:
        https://user:pass@hooks.slack.com/services/T00/B00/X?token=secret123
        -> https://user:[REDACTED]@hooks.slack.com/services/T00/B00/X?token=[REDACTED]
    """
    if not url:
        return ""

    try:
        parsed = urlparse(url)
    except Exception:
        return "[INVALID_URL]"

    # Mask user:pass in netloc
    netloc = parsed.netloc
    if "@" in netloc:
        user_info, host = netloc.split("@", 1)
        if ":" in user_info:
            user, _ = user_info.split(":", 1)
            netloc = f"{user}:[REDACTED]@{host}"
        else:
            netloc = f"[REDACTED]@{host}"

    # Mask sensitive query params
    query = parsed.query
    if query:
        params = parse_qs(query, keep_blank_values=True)
        sanitized_params: Dict[str, List[str]] = {}
        for k, v_list in params.items():
            if k.lower() in SENSITIVE_PARAM_NAMES:
                sanitized_params[k] = ["[REDACTED]"]
            else:
                sanitized_params[k] = v_list
        query = urlencode(sanitized_params, doseq=True)

    sanitized = urlunparse((
        parsed.scheme,
        netloc,
        parsed.path,
        parsed.params,
        query,
        parsed.fragment,
    ))
    return sanitized


class WebhookPayload:
    """Builds standard Alertmanager-compatible JSON alert payloads."""

    @staticmethod
    def _format_timestamp(ts: Optional[float]) -> str:
        if ts is None:
            return datetime.datetime.now(datetime.timezone.utc).isoformat()
        return datetime.datetime.fromtimestamp(ts, tz=datetime.timezone.utc).isoformat()

    @classmethod
    def from_alert_instances(
        cls,
        alerts: List[AlertInstance],
        status: Optional[str] = None,
        generator_url: str = "http://localhost:9100/metrics",
    ) -> Dict[str, Any]:
        """Converts a list of AlertInstances to a standard JSON alert dispatch payload."""
        alert_dicts: List[Dict[str, Any]] = []

        is_firing = any(a.state == AlertState.FIRING for a in alerts)
        overall_status = status or ("firing" if is_firing else "resolved")

        for alert in alerts:
            alert_labels = {
                "alertname": alert.rule.alert,
                "severity": alert.rule.severity,
                "group": alert.group_name,
            }
            alert_labels.update(alert.rule.labels)

            annotations = alert.render_annotations()

            # Generate fingerprint from labels
            lbl_key = "-".join(f"{k}={v}" for k, v in sorted(alert_labels.items()))
            fingerprint = hashlib.sha256(lbl_key.encode("utf-8")).hexdigest()[:16]

            starts_at = cls._format_timestamp(alert.firing_since or alert.active_since)
            ends_at = cls._format_timestamp(alert.resolved_at) if alert.state == AlertState.RESOLVED else "0001-01-01T00:00:00Z"

            alert_dicts.append({
                "status": alert.state.value,
                "labels": alert_labels,
                "annotations": annotations,
                "startsAt": starts_at,
                "endsAt": ends_at,
                "generatorURL": generator_url,
                "fingerprint": fingerprint,
                "value": alert.current_value,
            })

        return {
            "version": "4",
            "groupKey": f"{{:{alerts[0].group_name}}}" if alerts else "",
            "status": overall_status,
            "receiver": "webhook",
            "alerts": alert_dicts,
            "truncatedAlerts": 0,
        }


class WebhookNotifier:
    """Dispatches webhook notifications with exponential backoff and jitter."""

    def __init__(
        self,
        url: str,
        max_retries: int = 3,
        initial_backoff: float = 0.5,
        backoff_factor: float = 2.0,
        jitter_factor: float = 0.1,
        timeout: float = 5.0,
        client: Optional[httpx.Client] = None,
    ) -> None:
        self.url = url
        self.max_retries = max_retries
        self.initial_backoff = initial_backoff
        self.backoff_factor = backoff_factor
        self.jitter_factor = jitter_factor
        self.timeout = timeout
        self._custom_client = client

    @property
    def sanitized_url(self) -> str:
        """Returns URL with credentials and sensitive query tokens masked."""
        return sanitize_url(self.url)

    def __repr__(self) -> str:
        return f"<WebhookNotifier url='{self.sanitized_url}' max_retries={self.max_retries}>"

    def _compute_backoff(self, attempt: int) -> float:
        """Computes backoff delay with exponential factor and random jitter."""
        base_delay = self.initial_backoff * (self.backoff_factor ** attempt)
        jitter = random.uniform(0.0, self.jitter_factor * base_delay)  # nosec B311
        return base_delay + jitter

    def dispatch(
        self,
        alerts: List[AlertInstance],
        status: Optional[str] = None,
        generator_url: str = "http://localhost:9100/metrics",
    ) -> bool:
        """Sends alert payload via HTTP POST to the webhook URL.

        Retries on network errors or 5xx server responses with exponential backoff.
        Returns True if successful (2xx), False otherwise.
        """
        if not alerts:
            return True

        payload = WebhookPayload.from_alert_instances(
            alerts=alerts,
            status=status,
            generator_url=generator_url,
        )

        headers = {
            "Content-Type": "application/json",
            "User-Agent": "Prometheus-Metrics-Exporter/0.1.0",
        }

        client_to_use = self._custom_client or httpx.Client(timeout=self.timeout)
        should_close_client = self._custom_client is None

        try:
            for attempt in range(self.max_retries + 1):
                try:
                    logger.info(
                        "Dispatching alert webhook to %s (attempt %d/%d)",
                        self.sanitized_url,
                        attempt + 1,
                        self.max_retries + 1,
                    )
                    resp = client_to_use.post(
                        self.url,
                        json=payload,
                        headers=headers,
                        timeout=self.timeout,
                    )

                    if resp.status_code < 400:
                        logger.info("Webhook delivered successfully (HTTP %d)", resp.status_code)
                        return True

                    if resp.status_code < 500:
                        # 4xx client error (e.g. 400 Bad Request, 401 Unauthorized) - don't retry
                        logger.error(
                            "Webhook returned client error HTTP %d to %s: %s",
                            resp.status_code,
                            self.sanitized_url,
                            resp.text[:200],
                        )
                        return False

                    # 5xx server error - retry
                    logger.warning(
                        "Webhook server error HTTP %d from %s (attempt %d/%d)",
                        resp.status_code,
                        self.sanitized_url,
                        attempt + 1,
                        self.max_retries + 1,
                    )

                except (httpx.RequestError, httpx.TimeoutException) as exc:
                    logger.warning(
                        "Network error dispatching webhook to %s: %s (attempt %d/%d)",
                        self.sanitized_url,
                        exc,
                        attempt + 1,
                        self.max_retries + 1,
                    )

                if attempt < self.max_retries:
                    delay = self._compute_backoff(attempt)
                    time.sleep(delay)

            logger.error("Failed to dispatch alert webhook to %s after %d attempts", self.sanitized_url, self.max_retries + 1)
            return False

        finally:
            if should_close_client:
                client_to_use.close()
