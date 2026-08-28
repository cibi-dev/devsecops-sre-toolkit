"""Detection rules catalog for secrets, tokens, API keys, and private credentials."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Optional


@dataclass(frozen=True)
class SecretRule:
    """Definition of a static secret detection rule."""

    rule_id: str
    name: str
    description: str
    pattern: re.Pattern[str]
    severity: str  # "CRITICAL", "HIGH", "MEDIUM", "LOW"
    cwe_id: str
    category: str
    min_entropy: Optional[float] = None
    match_group: int = 0


# Precompiled regular expression catalog (35+ enterprise rules)
DEFAULT_RULES: List[SecretRule] = [
    # 1. AWS
    SecretRule(
        rule_id="RULE-AWS-AKIA",
        name="AWS Access Key ID",
        description="Identifies AWS Access Key IDs (AKIA/ASIA/ABIA/ACCA prefixes).",
        pattern=re.compile(r"\b(AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b"),
        severity="HIGH",
        cwe_id="CWE-798",
        category="Cloud Providers",
    ),
    SecretRule(
        rule_id="RULE-AWS-SECRET",
        name="AWS Secret Access Key",
        description="Identifies AWS Secret Access Key assignments.",
        pattern=re.compile(
            r"(?i)(?:aws_secret_access_key|aws_secret_key|aws_sec_key)\s*[:=]\s*['\"]?([a-zA-Z0-9/+=]{40})['\"]?"
        ),
        severity="CRITICAL",
        cwe_id="CWE-798",
        category="Cloud Providers",
        min_entropy=4.0,
        match_group=1,
    ),
    # 2. GitHub
    SecretRule(
        rule_id="RULE-GITHUB-PAT",
        name="GitHub Personal Access Token",
        description="Identifies classic GitHub Personal Access Tokens.",
        pattern=re.compile(r"\bghp_[a-zA-Z0-9]{36}\b"),
        severity="CRITICAL",
        cwe_id="CWE-798",
        category="Version Control",
    ),
    SecretRule(
        rule_id="RULE-GITHUB-FINEGRAINED",
        name="GitHub Fine-Grained Personal Access Token",
        description="Identifies fine-grained GitHub Personal Access Tokens.",
        pattern=re.compile(r"\bgithub_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}\b"),
        severity="CRITICAL",
        cwe_id="CWE-798",
        category="Version Control",
    ),
    SecretRule(
        rule_id="RULE-GITHUB-OAUTH",
        name="GitHub OAuth Access Token",
        description="Identifies GitHub OAuth access tokens.",
        pattern=re.compile(r"\bgho_[a-zA-Z0-9]{36}\b"),
        severity="CRITICAL",
        cwe_id="CWE-798",
        category="Version Control",
    ),
    SecretRule(
        rule_id="RULE-GITHUB-APP",
        name="GitHub App Token",
        description="Identifies GitHub App user-to-server or server-to-server tokens.",
        pattern=re.compile(r"\b(ghu|ghs)_[a-zA-Z0-9]{36}\b"),
        severity="CRITICAL",
        cwe_id="CWE-798",
        category="Version Control",
    ),
    SecretRule(
        rule_id="RULE-GITHUB-REFRESH",
        name="GitHub Refresh Token",
        description="Identifies GitHub user refresh tokens.",
        pattern=re.compile(r"\bghr_[a-zA-Z0-9]{36,}\b"),
        severity="HIGH",
        cwe_id="CWE-798",
        category="Version Control",
    ),
    # 3. JWT
    SecretRule(
        rule_id="RULE-JWT",
        name="JSON Web Token (JWT)",
        description="Identifies signed JSON Web Tokens.",
        pattern=re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
        severity="HIGH",
        cwe_id="CWE-312",
        category="Authentication & Tokens",
        min_entropy=4.0,
    ),
    # 4. Cryptographic Private Keys
    SecretRule(
        rule_id="RULE-RSA-PRIVATE-KEY",
        name="RSA Private Key",
        description="Identifies PEM formatted RSA private key headers.",
        pattern=re.compile(r"-----BEGIN " + r"RSA PRIVATE KEY-----"),
        severity="CRITICAL",
        cwe_id="CWE-312",
        category="Cryptographic Keys",
    ),
    SecretRule(
        rule_id="RULE-OPENSSH-PRIVATE-KEY",
        name="OpenSSH Private Key",
        description="Identifies OpenSSH private key headers.",
        pattern=re.compile(r"-----BEGIN " + r"OPENSSH PRIVATE KEY-----"),
        severity="CRITICAL",
        cwe_id="CWE-312",
        category="Cryptographic Keys",
    ),
    SecretRule(
        rule_id="RULE-EC-PRIVATE-KEY",
        name="EC Private Key",
        description="Identifies Elliptic Curve private key headers.",
        pattern=re.compile(r"-----BEGIN " + r"EC PRIVATE KEY-----"),
        severity="CRITICAL",
        cwe_id="CWE-312",
        category="Cryptographic Keys",
    ),
    SecretRule(
        rule_id="RULE-PGP-PRIVATE-KEY",
        name="PGP Private Key",
        description="Identifies PGP private key blocks.",
        pattern=re.compile(r"-----BEGIN " + r"PGP PRIVATE KEY BLOCK-----"),
        severity="CRITICAL",
        cwe_id="CWE-312",
        category="Cryptographic Keys",
    ),
    SecretRule(
        rule_id="RULE-GENERIC-PRIVATE-KEY",
        name="Generic Private Key",
        description="Identifies unencrypted PKCS#8 or generic private key headers.",
        pattern=re.compile(r"-----BEGIN " + r"(?:[A-Z0-9_-]+ )?PRIVATE KEY-----"),
        severity="CRITICAL",
        cwe_id="CWE-312",
        category="Cryptographic Keys",
    ),
    # 5. Slack
    SecretRule(
        rule_id="RULE-SLACK-BOT-TOKEN",
        name="Slack Bot Token",
        description="Identifies Slack bot access tokens (xoxb-).",
        pattern=re.compile(r"\bxoxb-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}\b"),
        severity="CRITICAL",
        cwe_id="CWE-798",
        category="Messaging & Webhooks",
    ),
    SecretRule(
        rule_id="RULE-SLACK-USER-TOKEN",
        name="Slack User Token",
        description="Identifies Slack user access tokens (xoxp-).",
        pattern=re.compile(r"\bxoxp-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}\b"),
        severity="CRITICAL",
        cwe_id="CWE-798",
        category="Messaging & Webhooks",
    ),
    SecretRule(
        rule_id="RULE-SLACK-WEBHOOK",
        name="Slack Webhook URL",
        description="Identifies Slack incoming webhook URLs.",
        pattern=re.compile(r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8,12}/B[a-zA-Z0-9_]{8,12}/[a-zA-Z0-9]{24}"),
        severity="HIGH",
        cwe_id="CWE-798",
        category="Messaging & Webhooks",
    ),
    # 6. Stripe
    SecretRule(
        rule_id="RULE-STRIPE-SECRET-KEY",
        name="Stripe Secret Key",
        description="Identifies Stripe live secret API keys.",
        pattern=re.compile(r"\bsk_live_[0-9a-zA-Z]{24,34}\b"),
        severity="CRITICAL",
        cwe_id="CWE-798",
        category="Payment Processors",
    ),
    SecretRule(
        rule_id="RULE-STRIPE-RESTRICTED",
        name="Stripe Restricted API Key",
        description="Identifies Stripe live restricted API keys.",
        pattern=re.compile(r"\brk_live_[0-9a-zA-Z]{24,34}\b"),
        severity="CRITICAL",
        cwe_id="CWE-798",
        category="Payment Processors",
    ),
    # 7. Google Cloud & AI
    SecretRule(
        rule_id="RULE-GCP-API-KEY",
        name="Google Cloud / Gemini API Key",
        description="Identifies Google Cloud Platform and Gemini API keys (AIza...).",
        pattern=re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
        severity="HIGH",
        cwe_id="CWE-798",
        category="Cloud Providers",
    ),
    SecretRule(
        rule_id="RULE-GCP-SERVICE-ACCOUNT",
        name="GCP Service Account Private Key ID",
        description="Identifies GCP Service Account JSON private_key_id.",
        pattern=re.compile(r'(?i)"private_key_id":\s*"([a-f0-9]{40})"'),
        severity="HIGH",
        cwe_id="CWE-798",
        category="Cloud Providers",
        match_group=1,
    ),
    SecretRule(
        rule_id="RULE-ANTHROPIC-API-KEY",
        name="Anthropic Claude API Key",
        description="Identifies Anthropic API keys (sk-ant-api03-...).",
        pattern=re.compile(r"\bsk-ant-api03-[a-zA-Z0-9\-_]{80,100}\b"),
        severity="CRITICAL",
        cwe_id="CWE-798",
        category="Cloud Providers",
    ),
    SecretRule(
        rule_id="RULE-OPENAI-API-KEY",
        name="OpenAI API Key",
        description="Identifies OpenAI legacy and project API keys.",
        pattern=re.compile(r"\b(?:sk-[a-zA-Z0-9]{20,48}|sk-proj-[a-zA-Z0-9_-]{48,})\b"),
        severity="CRITICAL",
        cwe_id="CWE-798",
        category="Cloud Providers",
    ),
    # 8. Azure
    SecretRule(
        rule_id="RULE-AZURE-STORAGE-KEY",
        name="Azure Storage Account Key",
        description="Identifies Azure Storage connection strings and account keys.",
        pattern=re.compile(r"(?i)(?:DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=)([a-zA-Z0-9+/=]{86,90})"),
        severity="CRITICAL",
        cwe_id="CWE-798",
        category="Cloud Providers",
        match_group=1,
    ),
    # 9. Communication APIs
    SecretRule(
        rule_id="RULE-SENDGRID-API-KEY",
        name="SendGrid API Key",
        description="Identifies SendGrid API keys (SG.xxx).",
        pattern=re.compile(r"\bSG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}\b"),
        severity="HIGH",
        cwe_id="CWE-798",
        category="Messaging & Webhooks",
    ),
    SecretRule(
        rule_id="RULE-TWILIO-API-KEY",
        name="Twilio API Key",
        description="Identifies Twilio API keys (SK...).",
        pattern=re.compile(r"\bSK[0-9a-fA-F]{32}\b"),
        severity="HIGH",
        cwe_id="CWE-798",
        category="Messaging & Webhooks",
    ),
    SecretRule(
        rule_id="RULE-DISCORD-BOT-TOKEN",
        name="Discord Bot Token",
        description="Identifies Discord bot tokens.",
        pattern=re.compile(r"\b[MN][A-Za-z0-9]{23,26}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,38}\b"),
        severity="CRITICAL",
        cwe_id="CWE-798",
        category="Messaging & Webhooks",
    ),
    # 10. Package Registries
    SecretRule(
        rule_id="RULE-NPM-ACCESS-TOKEN",
        name="NPM Access Token",
        description="Identifies NPM authentication tokens (npm_...).",
        pattern=re.compile(r"\bnpm_[a-zA-Z0-9]{36}\b"),
        severity="CRITICAL",
        cwe_id="CWE-798",
        category="Version Control",
    ),
    SecretRule(
        rule_id="RULE-PYPI-API-TOKEN",
        name="PyPI API Token",
        description="Identifies PyPI project upload tokens.",
        pattern=re.compile(r"\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9\-_]{50,100}\b"),
        severity="CRITICAL",
        cwe_id="CWE-798",
        category="Version Control",
    ),
    # 11. Databases & Infrastructure
    SecretRule(
        rule_id="RULE-DATABASE-URL-PASSWORD",
        name="Database Connection String Password",
        description="Identifies embedded passwords in database connection URIs.",
        pattern=re.compile(r"\b(?:postgres|postgresql|mysql|mongodb|redis|amqp)://[^:]+:([^@\s]+)@[a-zA-Z0-9.-]+"),
        severity="HIGH",
        cwe_id="CWE-798",
        category="Databases",
        match_group=1,
    ),
    SecretRule(
        rule_id="RULE-HASHICORP-VAULT-TOKEN",
        name="HashiCorp Vault Token",
        description="Identifies HashiCorp Vault service and batch tokens (hvs./hvb.).",
        pattern=re.compile(r"\b(?:hvb|hvs)\.[a-zA-Z0-9_-]{24,}\b"),
        severity="CRITICAL",
        cwe_id="CWE-798",
        category="Authentication & Tokens",
    ),
    SecretRule(
        rule_id="RULE-DATABRICKS-TOKEN",
        name="Databricks Personal Access Token",
        description="Identifies Databricks API access tokens (dapi...).",
        pattern=re.compile(r"\bdapi[a-f0-9]{32}\b"),
        severity="HIGH",
        cwe_id="CWE-798",
        category="Cloud Providers",
    ),
    SecretRule(
        rule_id="RULE-GITLAB-PAT",
        name="GitLab Personal Access Token",
        description="Identifies GitLab personal access tokens (glpat-...).",
        pattern=re.compile(r"\bglpat-[0-9a-zA-Z\-_]{20,24}\b"),
        severity="CRITICAL",
        cwe_id="CWE-798",
        category="Version Control",
    ),
    SecretRule(
        rule_id="RULE-SQUARE-ACCESS-TOKEN",
        name="Square Access Token",
        description="Identifies Square production access tokens.",
        pattern=re.compile(r"\bsq0atp-[0-9A-Za-z\-_]{22}\b"),
        severity="CRITICAL",
        cwe_id="CWE-798",
        category="Payment Processors",
    ),
    SecretRule(
        rule_id="RULE-SHOPIFY-ACCESS-TOKEN",
        name="Shopify Admin API Token",
        description="Identifies Shopify admin API access tokens (shpat_...).",
        pattern=re.compile(r"\bshpat_[a-fA-F0-9]{32}\b"),
        severity="HIGH",
        cwe_id="CWE-798",
        category="Payment Processors",
    ),
    SecretRule(
        rule_id="RULE-HEROKU-API-KEY",
        name="Heroku API Key",
        description="Identifies Heroku API key assignments.",
        pattern=re.compile(
            r"(?i)(?:heroku_api_key|heroku_key)\s*[:=]\s*['\"]?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})['\"]?"
        ),
        severity="HIGH",
        cwe_id="CWE-798",
        category="Cloud Providers",
        match_group=1,
    ),
    # 12. Generic High-Entropy Secret Assignment
    SecretRule(
        rule_id="RULE-GENERIC-API-KEY",
        name="Generic High-Entropy Secret Assignment",
        description="Identifies generic secret, token, or API key variable assignments with high Shannon entropy.",
        pattern=re.compile(
            r"(?i)(?:api_key|apikey|secret_key|auth_token|access_token|private_key|client_secret)\s*[:=]\s*['\"]([a-zA-Z0-9+/=_-]{16,64})['\"]"
        ),
        severity="MEDIUM",
        cwe_id="CWE-798",
        category="Generic",
        min_entropy=4.5,
        match_group=1,
    ),
]


def get_rule_by_id(rule_id: str) -> Optional[SecretRule]:
    """Retrieve a detection rule by its unique rule ID.

    Args:
        rule_id: Unique string identifier (e.g. 'RULE-AWS-AKIA').

    Returns:
        The matching SecretRule if found, None otherwise.
    """
    for rule in DEFAULT_RULES:
        if rule.rule_id == rule_id:
            return rule
    return None


def get_rules_by_category(category: str) -> List[SecretRule]:
    """Filter rules by category.

    Args:
        category: Category name (e.g. 'Cloud Providers').

    Returns:
        List of matching SecretRule instances.
    """
    return [r for r in DEFAULT_RULES if r.category.lower() == category.lower()]
