"""Strict PII and Credentials Redaction Transformer (CWE-209)."""

import re
from typing import Any, Dict, List, Union
from aggregator import LogEvent
from aggregator.transformers import BaseTransformer

# Email Regex
RE_EMAIL = re.compile(
    r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b"
)

# Bearer token regex
RE_BEARER = re.compile(
    r"\b(Bearer)\s+([A-Za-z0-9\-._~+/]+=*)", re.IGNORECASE
)

# JWT token regex
RE_JWT = re.compile(
    r"\beyJ[A-Za-z0-9-_=]+\.eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_.+/=]*\b"
)

# API Keys and generic secrets (key=value, key: value)
RE_SECRETS = re.compile(
    r"(?i)\b(api[_-]?key|access[_-]?token|auth[_-]?token|secret[_-]?key|client[_-]?secret|"
    r"private[_-]?key|password|passwd|pwd|secret|token)\s*([:=])\s*(['\"]?)([^\s,;'\"]{3,})\3"
)

# Credit Card (13-16 digits with optional spaces/dashes)
RE_CREDIT_CARD = re.compile(
    r"\b(?:\d{4}[ -]?){3}\d{4}\b"
)

# IPv4 Regex matcher
RE_IPV4 = re.compile(
    r"\b((?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\."
    r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d))\b"
)

# IPv6 private / link-local / loopback
RE_IPV6_PRIVATE = re.compile(
    r"(?:\b(?:fe80|fc00|fd00):[0-9a-fA-F:]+\b|(?<![0-9a-zA-Z:])(?:::1|0:0:0:0:0:0:0:1)(?![0-9a-zA-Z:]))",
    re.IGNORECASE,
)


def is_private_ipv4(ip_str: str) -> bool:
    """Determine if an IPv4 string belongs to RFC1918 / RFC3927 / Loopback."""
    parts = ip_str.split(".")
    if len(parts) != 4:
        return False
    try:
        o1 = int(parts[0])
        # Fast exit for non-private leading octets
        if o1 not in (10, 127, 169, 172, 192):
            return False
        o2 = int(parts[1])
    except ValueError:
        return False

    # 10.0.0.0/8
    if o1 == 10:
        return True
    # 127.0.0.0/8 (Loopback)
    if o1 == 127:
        return True
    # 169.254.0.0/16 (Link-Local)
    if o1 == 169 and o2 == 254:
        return True
    # 172.16.0.0/12
    if o1 == 172 and 16 <= o2 <= 31:
        return True
    # 192.168.0.0/16
    if o1 == 192 and o2 == 168:
        return True

    return False


class PIISanitizer(BaseTransformer):
    """Sanitizes PII, private IPs, emails, passwords, tokens and secrets to [REDACTED]."""

    def __init__(
        self,
        name: str = "pii-sanitizer",
        redact_private_ips: bool = True,
        redact_emails: bool = True,
        redact_secrets: bool = True,
        redact_tokens: bool = True,
        redact_credit_cards: bool = True,
        sanitize_raw: bool = True,
        replacement: str = "[REDACTED]",
    ):
        super().__init__(name=name)
        self.redact_private_ips = redact_private_ips
        self.redact_emails = redact_emails
        self.redact_secrets = redact_secrets
        self.redact_tokens = redact_tokens
        self.redact_credit_cards = redact_credit_cards
        self.sanitize_raw = sanitize_raw
        self.replacement = replacement

    def sanitize_text(self, text: str) -> str:
        """Sanitize a single text string against configured redaction rules."""
        if not text:
            return text

        result = text

        # 1. Bearer tokens & JWTs
        if self.redact_tokens:
            if "Bearer" in result or "bearer" in result:
                result = RE_BEARER.sub(rf"\1 {self.replacement}", result)
            if "eyJ" in result:
                result = RE_JWT.sub(self.replacement, result)

        # 2. Key-value secrets & passwords
        if self.redact_secrets:
            lower = result.lower()
            if any(k in lower for k in ("pass", "pwd", "secret", "token", "key")):
                result = RE_SECRETS.sub(rf"\1\2{self.replacement}", result)

        # 3. Credit cards
        if self.redact_credit_cards:
            if any(c.isdigit() for c in result):
                result = RE_CREDIT_CARD.sub(self.replacement, result)

        # 4. Emails
        if self.redact_emails:
            if "@" in result:
                result = RE_EMAIL.sub(self.replacement, result)

        # 5. Private IPv4 / IPv6 addresses
        if self.redact_private_ips:
            if "." in result and any(c.isdigit() for c in result):
                def _replace_ip(match: re.Match) -> str:
                    ip = match.group(1)
                    if is_private_ipv4(ip):
                        return self.replacement
                    return ip

                result = RE_IPV4.sub(_replace_ip, result)

            if ":" in result:
                result = RE_IPV6_PRIVATE.sub(self.replacement, result)

        return result

    def _sanitize_data(self, data: Any) -> Any:
        """Recursively sanitize nested dictionaries, lists, and primitives."""
        if isinstance(data, str):
            return self.sanitize_text(data)
        elif isinstance(data, dict):
            return {k: self._sanitize_data(v) for k, v in data.items()}
        elif isinstance(data, list):
            return [self._sanitize_data(v) for v in data]
        return data

    def transform(self, event: LogEvent) -> LogEvent:
        """Sanitize message, raw text, and structured metadata."""
        self._processed_count += 1
        try:
            original_msg = event.message
            new_msg = self.sanitize_text(original_msg)
            new_metadata = self._sanitize_data(event.metadata)

            new_raw = self.sanitize_text(event.raw) if self.sanitize_raw else event.raw

            if (
                new_msg != original_msg
                or new_metadata != event.metadata
                or new_raw != event.raw
            ):
                self._modified_count += 1
                event.message = new_msg
                event.metadata = new_metadata
                event.raw = new_raw
                if "sanitized" not in event.tags:
                    event.tags.append("sanitized")

        except Exception:
            self._errors_count += 1

        return event
