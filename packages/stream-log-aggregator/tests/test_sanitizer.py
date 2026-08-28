"""Comprehensive tests for PIISanitizer and CWE-209 redaction rules."""

import pytest
from aggregator import LogEvent
from aggregator.transformers.sanitizer import PIISanitizer, is_private_ipv4


class TestPIISanitizer:
    """Test suite for PII, secrets, and private IP redaction."""

    def test_private_ipv4_detection(self):
        """Verify RFC 1918 / 3927 private IPv4 recognition."""
        assert is_private_ipv4("10.0.0.1") is True
        assert is_private_ipv4("10.255.255.254") is True
        assert is_private_ipv4("172.16.0.1") is True
        assert is_private_ipv4("172.31.255.255") is True
        assert is_private_ipv4("192.168.1.1") is True
        assert is_private_ipv4("127.0.0.1") is True
        assert is_private_ipv4("169.254.10.20") is True

        # Public IPs
        assert is_private_ipv4("8.8.8.8") is False
        assert is_private_ipv4("1.1.1.1") is False
        assert is_private_ipv4("172.15.0.1") is False
        assert is_private_ipv4("172.32.0.1") is False
        assert is_private_ipv4("192.169.1.1") is False
        assert is_private_ipv4("invalid.ip") is False
        assert is_private_ipv4("999.999.999.999") is False

    def test_redact_private_ips_in_message(self):
        """Verify private IPs are redacted while public IPs remain intact."""
        sanitizer = PIISanitizer()
        event = LogEvent.create("Connection from 192.168.1.100 to 8.8.8.8 and 10.0.5.1 via 127.0.0.1")
        res = sanitizer.transform(event)

        assert "192.168.1.100" not in res.message
        assert "10.0.5.1" not in res.message
        assert "127.0.0.1" not in res.message
        assert "8.8.8.8" in res.message
        assert "[REDACTED]" in res.message
        assert "sanitized" in res.tags

    def test_redact_ipv6_private(self):
        """Verify private IPv6 addresses are redacted."""
        sanitizer = PIISanitizer()
        event = LogEvent.create("Loopback ::1 and link-local fe80::1ff:fe23:4567:890a access")
        res = sanitizer.transform(event)
        assert "::1" not in res.message
        assert "fe80::1ff:fe23:4567:890a" not in res.message
        assert "[REDACTED]" in res.message

    def test_redact_emails(self):
        """Verify email addresses are sanitized."""
        sanitizer = PIISanitizer()
        event = LogEvent.create("Contact user.john+ops@sub.example.co.uk or admin@corp.net")
        res = sanitizer.transform(event)

        assert "user.john+ops@sub.example.co.uk" not in res.message
        assert "admin@corp.net" not in res.message
        assert res.message == "Contact [REDACTED] or [REDACTED]"
        assert "sanitized" in res.tags

    def test_redact_bearer_and_jwt_tokens(self):
        """Verify Bearer tokens and JWTs are redacted."""
        sanitizer = PIISanitizer()
        mock_jwt = "eyJhbGci" + "OiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        raw = f"Auth: Bearer secret_token_123456789 and jwt={mock_jwt}"
        event = LogEvent.create(raw)
        res = sanitizer.transform(event)

        assert "secret_token_123456789" not in res.message
        assert "eyJhbGci" not in res.message
        assert "Bearer [REDACTED]" in res.message
        assert "sanitized" in res.tags

    def test_redact_key_value_secrets(self):
        """Verify passwords, api keys, and tokens in key-value formats are redacted."""
        sanitizer = PIISanitizer()
        mock_stripe = "sk_" + "live_" + "9988776655443322"
        raw = f"db_connect: password=MySecret123! api_key: '{mock_stripe}' token=tok_alpha_omega_100"
        event = LogEvent.create(raw)
        res = sanitizer.transform(event)

        assert "MySecret123!" not in res.message
        assert mock_stripe not in res.message
        assert "tok_alpha_omega_100" not in res.message
        assert "password=[REDACTED]" in res.message or "password:[REDACTED]" in res.message
        assert "api_key:[REDACTED]" in res.message or "api_key=[REDACTED]" in res.message
        assert "token=[REDACTED]" in res.message

    def test_redact_credit_cards(self):
        """Verify 16-digit credit cards are redacted."""
        sanitizer = PIISanitizer()
        event = LogEvent.create("Payment card 4111 2222 3333 4444 approved")
        res = sanitizer.transform(event)

        assert "4111 2222 3333 4444" not in res.message
        assert "[REDACTED]" in res.message

    def test_nested_structured_metadata_sanitization(self):
        """Verify recursive sanitization inside event.metadata dicts and lists."""
        sanitizer = PIISanitizer()
        event = LogEvent.create(
            raw="Order placed",
            metadata={
                "customer": {
                    "email": "customer@gmail.com",
                    "ip": "192.168.1.55",
                    "auth": "Bearer tok_123456789",
                },
                "audit": [
                    {"admin": "admin@company.com", "host": "10.10.0.1"},
                    "password=secret_db_pass",
                ],
            },
        )
        res = sanitizer.transform(event)

        assert res.metadata["customer"]["email"] == "[REDACTED]"
        assert res.metadata["customer"]["ip"] == "[REDACTED]"
        assert res.metadata["customer"]["auth"] == "Bearer [REDACTED]"
        assert res.metadata["audit"][0]["admin"] == "[REDACTED]"
        assert res.metadata["audit"][0]["host"] == "[REDACTED]"
        assert "secret_db_pass" not in res.metadata["audit"][1]

    def test_no_pii_no_mutation(self):
        """Verify messages without PII are unmodified and not tagged."""
        sanitizer = PIISanitizer()
        event = LogEvent.create("Public service heartbeat OK on server01 at 8.8.4.4")
        res = sanitizer.transform(event)

        assert res.message == "Public service heartbeat OK on server01 at 8.8.4.4"
        assert "sanitized" not in res.tags

    def test_custom_replacement_token(self):
        """Verify custom replacement string."""
        sanitizer = PIISanitizer(replacement="<HIDDEN>")
        event = LogEvent.create("Email admin@test.com")
        res = sanitizer.transform(event)
        assert res.message == "Email <HIDDEN>"

    def test_metrics_tracking(self):
        """Verify sanitizer counts processed and modified events."""
        sanitizer = PIISanitizer()
        event1 = LogEvent.create("Secret email=dev@test.com")
        event2 = LogEvent.create("Clean message")

        sanitizer.transform(event1)
        sanitizer.transform(event2)

        m = sanitizer.metrics
        assert m["processed"] == 2
        assert m["modified"] == 1
        assert m["errors"] == 0
