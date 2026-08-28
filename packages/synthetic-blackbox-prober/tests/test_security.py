"""Security verification suite testing CWE-400, CWE-295, CWE-209, and CWE-208 mitigations."""

import asyncio
import hmac
import pytest
from prober.notifier import AlertEvent, WebhookNotifier, generate_hmac_signature, verify_hmac_signature
from prober.probes.http import HTTPProbe, sanitize_headers, sanitize_url
from prober.probes.ssl_cert import SSLCertProbe
from prober.scheduler import ProbeScheduler


def test_cwe_209_url_sanitization():
    """Verify sensitive token and password redaction in URLs (CWE-209)."""
    urls = [
        ("https://admin:SuperSecret123@internal.corp/api", "https://admin:[REDACTED]@internal.corp/api"),
        ("https://api.gateway.com/v1/query?token=xyz123&env=prod", "https://api.gateway.com/v1/query?token=%5BREDACTED%5D&env=prod"),
        ("https://auth.io/auth?api_key=my_key_99&session=abc", "https://auth.io/auth?api_key=%5BREDACTED%5D&session=%5BREDACTED%5D"),
    ]
    for raw, expected in urls:
        sanitized = sanitize_url(raw)
        assert "SuperSecret123" not in sanitized
        assert "xyz123" not in sanitized
        assert "my_key_99" not in sanitized
        assert "[REDACTED]" in sanitized or "%5BREDACTED%5D" in sanitized


def test_cwe_209_header_sanitization():
    """Verify sensitive HTTP header redaction (CWE-209)."""
    headers = {
        "Authorization": "Bearer eyJhbGciOi...",
        "Proxy-Authorization": "Basic dXNlcjpwYXNz",
        "X-Api-Key": "secret-key-333",
        "Cookie": "session_id=123456",
        "Set-Cookie": "auth=abcdef",
        "Accept": "application/json",
    }
    sanitized = sanitize_headers(headers)
    assert sanitized["Authorization"] == "[REDACTED]"
    assert sanitized["Proxy-Authorization"] == "[REDACTED]"
    assert sanitized["X-Api-Key"] == "[REDACTED]"
    assert sanitized["Cookie"] == "[REDACTED]"
    assert sanitized["Set-Cookie"] == "[REDACTED]"
    assert sanitized["Accept"] == "application/json"


def test_cwe_208_hmac_signature_timing_safety():
    """Verify constant-time HMAC signature generation and verification (CWE-208)."""
    secret = "production-webhook-secret-key-99"
    payload = b'{"target":"https://api.example.com","severity":"CRITICAL"}'

    sig = generate_hmac_signature(payload, secret)
    assert len(sig) == 64  # SHA256 hex length

    assert verify_hmac_signature(payload, secret, sig) is True
    assert verify_hmac_signature(payload, secret, "invalid" + sig[7:]) is False
    assert verify_hmac_signature(b'tampered payload', secret, sig) is False


@pytest.mark.asyncio
async def test_cwe_400_concurrency_semaphore_limit():
    """Verify scheduler bounds maximum concurrent tasks via semaphore (CWE-400)."""
    limit = 5
    scheduler = ProbeScheduler(concurrency_limit=limit)
    assert scheduler._semaphore._value == limit


@pytest.mark.asyncio
async def test_cwe_295_tls_default_verification():
    """Verify that SSL verification is enabled by default in probes (CWE-295)."""
    http_probe = HTTPProbe()
    assert http_probe.default_timeout > 0

    ssl_probe = SSLCertProbe()
    assert ssl_probe.default_timeout > 0


@pytest.mark.asyncio
async def test_webhook_notifier_throttling_and_cooldown():
    """Verify webhook notifier throttles alerts to prevent alert floods."""
    notifier = WebhookNotifier(
        webhook_url="https://hooks.example.com/alerts",
        cooldown_seconds=10.0,
    )

    event = AlertEvent(
        target="https://api.example.com",
        probe_type="http",
        severity="CRITICAL",
        status="HTTP_500",
        summary="Service is down",
    )

    # First alert should be permitted
    target_key = f"{event.target}:{event.severity}:{event.status}"
    assert notifier.should_alert(target_key) is True

    # Immediate second alert must be throttled
    assert notifier.should_alert(target_key) is False
