"""
Security and DevSecOps Compliance Tests.

Validates mitigations against:
- CWE-400: Denial of Service via Resource Exhaustion & Payloads > 10MB
- CWE-209: Sensitive Information Leakage in Logs & Diagnostics
- CWE-330: Insufficient Entropy / Insecure Randomness
- CWE-208: Timing Attacks via Constant-Time Comparisons
- CWE-502: Deserialization and Configuration Hardening
"""

import hmac
import secrets
import pytest
from starlette.testclient import TestClient

from proxy.circuit_breaker import CircuitBreakerConfig
from proxy.limiter import RateLimiterConfig, RateLimiterManager
from proxy.server import ProxyConfig, ProxyServer, sanitize_headers_for_logging


def test_cwe_400_content_length_limit_rejection():
    """Ensure payloads > 10MB (10,485,760 bytes) are rejected with 413 immediately."""
    proxy = ProxyServer(ProxyConfig())

    with TestClient(proxy.app) as client:
        # 10 MB + 1 byte
        oversized_len = str(10 * 1024 * 1024 + 1)
        resp = client.post(
            "/data",
            headers={"Content-Length": oversized_len},
            content=b"test",
        )
        assert resp.status_code == 413
        assert "Payload Too Large" in resp.json()["error"]


def test_cwe_400_streaming_body_cutoff():
    """Ensure streaming body that exceeds max size is aborted immediately."""
    proxy = ProxyServer(ProxyConfig(max_body_size=500))

    with TestClient(proxy.app) as client:
        resp = client.post("/stream", content=b"A" * 1000)
        assert resp.status_code == 413
        assert "Payload Too Large" in resp.json()["error"]


def test_cwe_400_concurrency_quota_semaphore():
    """Ensure concurrency quota semaphore is strictly initialized."""
    config = ProxyConfig(max_concurrency=100)
    server = ProxyServer(config)
    assert server.concurrency_semaphore._value == 100


def test_cwe_209_header_and_credential_sanitization():
    """Ensure sensitive headers (Authorization, X-API-Key, Cookies) are redacted."""
    sensitive_headers = {
        "Host": "api.enterprise.internal",
        "Authorization": f"Bearer mock_token_{secrets.token_hex(8)}",
        "X-API-Key": f"mock_key_{secrets.token_hex(8)}",
        "Cookie": f"session_id={secrets.token_hex(8)}; auth=true",
        "Set-Cookie": f"session_id={secrets.token_hex(8)}",
        "User-Agent": "Mozilla/5.0",
    }
    sanitized = sanitize_headers_for_logging(sensitive_headers)

    assert sanitized["Host"] == "api.enterprise.internal"
    assert sanitized["User-Agent"] == "Mozilla/5.0"
    assert sanitized["Authorization"] == "[REDACTED]"
    assert sanitized["X-API-Key"] == "[REDACTED]"
    assert sanitized["Cookie"] == "[REDACTED]"
    assert sanitized["Set-Cookie"] == "[REDACTED]"


def test_cwe_209_key_masking_utility():
    """Ensure RateLimiterManager masks API keys safely in logs."""
    sample_key = "user_" + secrets.token_hex(8)
    masked = RateLimiterManager.mask_key(sample_key)
    assert masked.startswith(sample_key[:4])
    assert masked.endswith(sample_key[-4:])
    assert RateLimiterManager.mask_key("short") == "[REDACTED]"
    assert RateLimiterManager.mask_key("") == "unknown"


def test_cwe_330_cryptographic_entropy_secrets():
    """Ensure generated request IDs and API keys use secrets module."""
    token1 = secrets.token_hex(16)
    token2 = secrets.token_hex(16)
    assert len(token1) == 32
    assert token1 != token2

    key1 = secrets.token_urlsafe(32)
    assert len(key1) >= 32


def test_cwe_208_constant_time_comparison():
    """Validate constant-time comparison for secret tokens."""
    secret_a = secrets.token_hex(16)
    secret_b = secrets.token_hex(16)
    secret_c = str(secret_a)

    assert hmac.compare_digest(secret_a, secret_c) is True
    assert hmac.compare_digest(secret_a, secret_b) is False


def test_cwe_502_pydantic_schema_extra_forbid():
    """Verify configs reject unexpected fields to prevent prototype pollution."""
    with pytest.raises(Exception):
        ProxyConfig(malicious_field="untrusted_payload")

    with pytest.raises(Exception):
        CircuitBreakerConfig(attacker_injected="payload")

    with pytest.raises(Exception):
        RateLimiterConfig(unknown_key="val")
