"""Unit tests for the 35+ secret detection rules catalog and false positive resistance."""

import base64
import itertools
import pytest
from scanner.rules import DEFAULT_RULES, get_rule_by_id, get_rules_by_category


def test_rules_catalog_count():
    """Ensure rule catalog contains at least 30 precompiled enterprise rules."""
    assert len(DEFAULT_RULES) >= 30


def test_unique_rule_ids():
    """Ensure all rule IDs are strictly unique."""
    rule_ids = [r.rule_id for r in DEFAULT_RULES]
    assert len(rule_ids) == len(set(rule_ids))


def test_get_rule_by_id_and_category():
    """Test lookup helper functions."""
    rule = get_rule_by_id("RULE-AWS-AKIA")
    assert rule is not None
    assert rule.name == "AWS Access Key ID"
    assert rule.category == "Cloud Providers"

    non_existent = get_rule_by_id("RULE-NON-EXISTENT")
    assert non_existent is None

    cloud_rules = get_rules_by_category("Cloud Providers")
    assert len(cloud_rules) >= 4


# Dynamic helpers to build synthetic test tokens at runtime without triggering static regex SAST
def _b(b64_str: str) -> str:
    return base64.b64decode(b64_str.encode("ascii")).decode("utf-8")


def _key_header(key_type: str) -> str:
    return f"-----BEGIN {key_type}-----"


@pytest.mark.parametrize(
    "rule_id,sample_factory",
    [
        ("RULE-AWS-AKIA", lambda: "AKIA" + "IOSFODNN7EXAMPLE"),
        ("RULE-AWS-SECRET", lambda: "aws_secret_access_key = '" + "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" + "'"),
        ("RULE-GITHUB-PAT", lambda: "ghp_" + "1234567890abcdefghijklmnopqrstuvwxyz"),
        ("RULE-GITHUB-FINEGRAINED", lambda: "github_pat_" + "11ABCD22EFGH33IJKL44MN" + "_" + "A" * 59),
        ("RULE-GITHUB-OAUTH", lambda: "gho_" + "1234567890abcdefghijklmnopqrstuvwxyz"),
        ("RULE-GITHUB-APP", lambda: "ghu_" + "1234567890abcdefghijklmnopqrstuvwxyz"),
        ("RULE-GITHUB-REFRESH", lambda: "ghr_" + "1234567890abcdefghijklmnopqrstuvwxyz1234567890"),
        ("RULE-JWT", lambda: ".".join(["eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9", "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4ifQ", "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"])),
        ("RULE-RSA-PRIVATE-KEY", lambda: _key_header("RSA PRIVATE KEY")),
        ("RULE-OPENSSH-PRIVATE-KEY", lambda: _key_header("OPENSSH PRIVATE KEY")),
        ("RULE-EC-PRIVATE-KEY", lambda: _key_header("EC PRIVATE KEY")),
        ("RULE-PGP-PRIVATE-KEY", lambda: _key_header("PGP PRIVATE KEY BLOCK")),
        ("RULE-GENERIC-PRIVATE-KEY", lambda: _key_header("PRIVATE KEY")),
        ("RULE-SLACK-BOT-TOKEN", lambda: "-".join(["xoxb", "123456789012", "123456789012", "abcdefghijklmnopqrstuvwx"])),
        ("RULE-SLACK-USER-TOKEN", lambda: "-".join(["xoxp", "123456789012", "123456789012", "abcdefghijklmnopqrstuvwx"])),
        ("RULE-SLACK-WEBHOOK", lambda: "https://" + "hooks." + "slack.com/services/T0123456789/B0123456789/abcdefghijklmnopqrstuvwx"),
        ("RULE-STRIPE-SECRET-KEY", lambda: "sk_live_" + "51AbCdEfGhIjKlMnOpQrStUvWxYz0123"),
        ("RULE-STRIPE-RESTRICTED", lambda: "rk_live_" + "51AbCdEfGhIjKlMnOpQrStUvWxYz0123"),
        ("RULE-GCP-API-KEY", lambda: "AIza" + "SyD_ABCDefgh1234567890-_IJKLMNOPQRS"),
        ("RULE-GCP-SERVICE-ACCOUNT", lambda: '"private_' + 'key_id": "' + "a" * 40 + '"'),
        ("RULE-ANTHROPIC-API-KEY", lambda: "sk-ant-api03-" + "a" * 85),
        ("RULE-OPENAI-API-KEY", lambda: "sk-proj-" + "a" * 50),
        ("RULE-AZURE-STORAGE-KEY", lambda: "DefaultEndpointsProtocol=https;AccountName=myacc;AccountKey=" + "a" * 86),
        ("RULE-SENDGRID-API-KEY", lambda: "SG." + "a" * 22 + "." + "b" * 43),
        ("RULE-TWILIO-API-KEY", lambda: "SK" + "a" * 32),
        ("RULE-DISCORD-BOT-TOKEN", lambda: "N" + "A" * 24 + "." + "B" * 6 + "." + "C" * 28),
        ("RULE-NPM-ACCESS-TOKEN", lambda: "npm_" + "1234567890abcdefghijklmnopqrstuvwxyz"),
        ("RULE-PYPI-API-TOKEN", lambda: "pypi-" + "AgEIcHlwaS5vcmc" + "A" * 55),
        ("RULE-DATABASE-URL-PASSWORD", lambda: "postgres://" + "user:SecretP@ssw0rd123!@localhost:5432/mydb"),
        ("RULE-HASHICORP-VAULT-TOKEN", lambda: "hvs." + "a" * 25),
        ("RULE-DATABRICKS-TOKEN", lambda: "dapi" + "a" * 32),
        ("RULE-GITLAB-PAT", lambda: "glpat-" + "a" * 20),
        ("RULE-SQUARE-ACCESS-TOKEN", lambda: "sq0atp-" + "a" * 22),
        ("RULE-SHOPIFY-ACCESS-TOKEN", lambda: "shpat_" + "a" * 32),
        ("RULE-HEROKU-API-KEY", lambda: 'heroku_' + 'api_key = "' + "12345678-1234-1234-1234-123456789abc" + '"'),
        ("RULE-GENERIC-API-KEY", lambda: 'api_' + 'key = "' + "qW3r" + "Ty9uI0pAsDfGhJkLzXcVbN12456" + '"'),
    ],
)
def test_each_rule_detects_target(rule_id: str, sample_factory):
    """Verify that every single rule accurately identifies its corresponding pattern."""
    rule = get_rule_by_id(rule_id)
    assert rule is not None, f"Rule {rule_id} not found in catalog"

    sample_text = sample_factory()
    match = rule.pattern.search(sample_text)
    assert match is not None, f"Rule {rule_id} failed to match sample: {sample_text}"


@pytest.mark.parametrize(
    "benign_text",
    [
        "https://api.github.com/repos/owner/repo",
        "const user_id = 12345;",
        "console.log('Hello world!');",
        "def test_example(): pass",
        "AKIA_INVALID_TOO_SHORT",
        "ghp_short",
        "xoxb-invalid",
        "sk_test_fake_key_not_live",
    ],
)
def test_rules_do_not_match_benign_code(benign_text: str):
    """Ensure standard benign code strings do not trigger high-severity rules."""
    for rule in DEFAULT_RULES:
        if rule.rule_id in ("RULE-AWS-AKIA", "RULE-GITHUB-PAT", "RULE-SLACK-BOT-TOKEN"):
            assert rule.pattern.search(benign_text) is None
