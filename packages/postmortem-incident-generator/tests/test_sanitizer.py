import re
import pytest
from postmortem.sanitizer import (
    EvidenceSanitizer,
    is_clean,
    sanitize_data,
    sanitize_dict,
    sanitize_list,
    sanitize_text,
)


def test_sanitize_private_keys():
    rsa_key = """-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA0Y3w1...sample_fake_key_material...
-----END RSA PRIVATE KEY-----"""
    clean = sanitize_text(rsa_key)
    assert "[REDACTED]" in clean
    assert "MIIEowIBAAKCAQEA0Y3w1" not in clean


def test_sanitize_bearer_token():
    log_line = "2026-08-27 HTTP 401 Unauthorized Header: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.do_not_leak"
    clean = sanitize_text(log_line)
    assert "[REDACTED]" in clean
    assert "do_not_leak" not in clean


def test_sanitize_aws_credentials():
    log_entry = "Failed to upload snapshot to s3 using AKIAIOSFODNN7EXAMPLE key"
    clean = sanitize_text(log_entry)
    assert "AKIAIOSFODNN7EXAMPLE" not in clean
    assert "[REDACTED]" in clean


def test_sanitize_generic_secrets():
    examples = [
        "DB_CONNECT: api_key='sk-live-9876543210abcdef'",
        "redis_pass: password=SuperSecretPassword123!",
        "auth_token: 'secret_token_12345678'",
        "client_secret: \"client_secret_9988776655\"",
        "secret: my_super_secret_999",
    ]
    for ex in examples:
        clean = sanitize_text(ex)
        assert "[REDACTED]" in clean
        assert "sk-live-9876543210abcdef" not in clean
        assert "SuperSecretPassword123!" not in clean


def test_sanitize_url_basic_auth():
    url = "Failed connecting to upstream: postgres://admin:SuperSecretPass123@internal.service.local:5432/v1/health"
    clean = sanitize_text(url)
    assert "postgres://admin:[REDACTED]@internal.service.local:5432" in clean
    assert "SuperSecretPass123" not in clean


def test_sanitize_jwt_token():
    jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    clean = sanitize_text(f"User JWT: {jwt}")
    assert jwt not in clean
    assert "[REDACTED]" in clean


def test_sanitize_credit_card():
    cc_log = "Processing payment for card 4532-1234-5678-9012 failed at gateway"
    clean = sanitize_text(cc_log)
    assert "4532-1234-5678-9012" not in clean
    assert "[REDACTED]" in clean


def test_sanitize_email_pii():
    text = "Incident commander contact: alex.engineer@enterprise-domain.com"
    clean = sanitize_text(text, mask_emails=True)
    assert "alex.engineer@enterprise-domain.com" not in clean
    assert "[REDACTED]" in clean

    unmasked = sanitize_text(text, mask_emails=False)
    assert "alex.engineer@enterprise-domain.com" in unmasked


def test_sanitize_dict_and_list_recursive():
    payload = {
        "user_email": "ops-lead@company.internal",
        "nested": {
            "token": "api_key=my_secret_token_123",
            "numbers": [1, 2, 3],
            "raw_key": "AKIA1234567890ABCDEF",
        },
        "tags": ["env:prod", "secret=ultra_secret_val_123"],
    }
    clean = sanitize_dict(payload)
    assert clean["user_email"] == "[REDACTED]"
    assert clean["nested"]["token"] == "api_key=[REDACTED]"
    assert clean["nested"]["raw_key"] == "[REDACTED]"
    assert clean["nested"]["numbers"] == [1, 2, 3]
    assert clean["tags"][1] == "secret=[REDACTED]"


def test_sanitize_data_tuples_and_sets():
    raw_tuple = ("api_key=secret123456", "safe_item")
    clean_tuple = sanitize_data(raw_tuple)
    assert isinstance(clean_tuple, tuple)
    assert "secret123456" not in clean_tuple[0]

    raw_set = {"password=Secret987654"}
    clean_set = sanitize_data(raw_set)
    assert isinstance(clean_set, set)
    assert list(clean_set)[0] == "password=[REDACTED]"

    clean_int = sanitize_data(42)
    assert clean_int == 42


def test_sanitize_list_helper():
    items = ["password=Pass12345", "user@domain.com"]
    clean = sanitize_list(items, mask_emails=True)
    assert clean[0] == "password=[REDACTED]"
    assert clean[1] == "[REDACTED]"

    clean_no_email = sanitize_list(items, mask_emails=False)
    assert clean_no_email[1] == "user@domain.com"


def test_is_clean_verification():
    assert is_clean("System restarted successfully at 14:00 UTC")
    assert not is_clean("Bearer secret_token_value_here_12345")
    assert not is_clean("AKIA1234567890ABCDEF")
    assert not is_clean("admin@domain.com", mask_emails=True)
    assert is_clean("admin@domain.com", mask_emails=False)
    assert is_clean("")
    assert is_clean(None)


def test_custom_patterns_sanitizer():
    sanitizer = EvidenceSanitizer(custom_patterns=[re.compile(r"PROJECT_SECRET_[A-Z0-9]+")])
    cleaned = sanitizer.sanitize_text("Internal token: PROJECT_SECRET_999888")
    assert "PROJECT_SECRET_999888" not in cleaned
    assert "[REDACTED]" in cleaned
    assert not sanitizer.is_clean("Contains PROJECT_SECRET_123")
