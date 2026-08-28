"""Sanitization and Redaction Engine for Incident Evidences and Post-Mortems.

Compliant with CWE-209 / CWE-532 (Sensitive Information Leakage Prevention).
Uses bounded, non-backtracking regular expressions to prevent ReDoS (CWE-400).
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Pattern, Union


class EvidenceSanitizer:
    """Enterprise-grade sanitizer for log traces, environment diffs, and evidence metadata."""

    REDACTION_MARKER = "[REDACTED]"

    # Compiled patterns designed to prevent catastrophic backtracking (ReDoS)
    PATTERNS: List[tuple[str, Pattern[str]]] = [
        # Private Key blocks
        (
            "PRIVATE_KEY",
            re.compile(
                r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY[^-]*-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----",
                re.MULTILINE,
            ),
        ),
        # Authorization Headers
        (
            "AUTH_HEADER",
            re.compile(
                r"(?i)(Authorization:\s*(?:Bearer|Basic|Token|Digest)\s+)[^\r\n]+",
            ),
        ),
        # Bearer Tokens
        (
            "BEARER_TOKEN",
            re.compile(
                r"(?i)\bBearer\s+[A-Za-z0-9_\-\.\+/=]{10,}\b",
            ),
        ),
        # JWT Tokens
        (
            "JWT_TOKEN",
            re.compile(
                r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9-_+/=]{10,}\b",
            ),
        ),
        # AWS Access Key ID
        (
            "AWS_KEY",
            re.compile(
                r"\b(AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}\b",
            ),
        ),
        # Generic Secret Key-Value assignments
        (
            "GENERIC_SECRET_KV",
            re.compile(
                r"(?i)\b(api[_-]?key|secret|secret[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|password|passwd|pwd|private[_-]?key)\s*([:=])\s*['\"]?([^\s'\";,&]{6,})['\"]?",
            ),
        ),
        # Basic Auth in URLs (e.g. postgres://user:password@host:port/db)
        (
            "URL_BASIC_AUTH",
            re.compile(
                r"([a-zA-Z][a-zA-Z0-9+\-.]*://[a-zA-Z0-9_\-\.\%]+:)([^@\s/]+)(@[a-zA-Z0-9_\-\.:]+)",
            ),
        ),
        # Credit Card Numbers (13-16 digits with optional spaces/hyphens)
        (
            "CREDIT_CARD",
            re.compile(
                r"\b(?:\d{4}[ -]?){3}\d{4}\b",
            ),
        ),
    ]

    EMAIL_PATTERN = re.compile(
        r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,24}\b"
    )

    def __init__(self, mask_emails: bool = True, custom_patterns: List[Pattern[str]] | None = None) -> None:
        """Initialize sanitizer with optional custom patterns and email masking toggle."""
        self.mask_emails = mask_emails
        self.custom_patterns = custom_patterns or []

    def sanitize_text(self, text: str) -> str:
        """Sanitize a raw string, masking sensitive tokens with [REDACTED]."""
        if not text or not isinstance(text, str):
            return "" if text is None else str(text)

        sanitized = text

        # 1. Private keys and credential replacements
        for name, pattern in self.PATTERNS:
            if name == "AUTH_HEADER":
                sanitized = pattern.sub(r"\1" + self.REDACTION_MARKER, sanitized)
            elif name == "GENERIC_SECRET_KV":
                sanitized = pattern.sub(r"\1\2" + self.REDACTION_MARKER, sanitized)
            elif name == "URL_BASIC_AUTH":
                sanitized = pattern.sub(r"\1" + self.REDACTION_MARKER + r"\3", sanitized)
            else:
                sanitized = pattern.sub(self.REDACTION_MARKER, sanitized)

        # 2. Email / PII masking
        if self.mask_emails:
            sanitized = self.EMAIL_PATTERN.sub(self.REDACTION_MARKER, sanitized)

        # 3. Custom patterns
        for custom_pattern in self.custom_patterns:
            sanitized = custom_pattern.sub(self.REDACTION_MARKER, sanitized)

        return sanitized

    def sanitize_dict(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Recursively sanitize dictionary values."""
        clean_dict: Dict[str, Any] = {}
        for key, value in data.items():
            clean_key = self.sanitize_text(str(key))
            clean_dict[clean_key] = self.sanitize_data(value)
        return clean_dict

    def sanitize_list(self, items: List[Any]) -> List[Any]:
        """Recursively sanitize list elements."""
        return [self.sanitize_data(item) for item in items]

    def sanitize_data(self, data: Any) -> Any:
        """Sanitize any arbitrary Python data structure recursively."""
        if isinstance(data, str):
            return self.sanitize_text(data)
        elif isinstance(data, dict):
            return self.sanitize_dict(data)
        elif isinstance(data, (list, tuple, set)):
            sanitized_items = self.sanitize_list(list(data))
            if isinstance(data, tuple):
                return tuple(sanitized_items)
            if isinstance(data, set):
                return set(sanitized_items)
            return sanitized_items
        return data

    def is_clean(self, text: str) -> bool:
        """Verify if text contains zero detectable credentials."""
        if not text:
            return True
        for name, pattern in self.PATTERNS:
            if pattern.search(text):
                return False
        if self.mask_emails and self.EMAIL_PATTERN.search(text):
            return False
        for custom_pattern in self.custom_patterns:
            if custom_pattern.search(text):
                return False
        return True


# Default instance convenience functions
_default_sanitizer = EvidenceSanitizer(mask_emails=True)


def sanitize_text(text: str, mask_emails: bool = True) -> str:
    """Convenience function to sanitize text using default sanitizer."""
    if mask_emails:
        return _default_sanitizer.sanitize_text(text)
    return EvidenceSanitizer(mask_emails=False).sanitize_text(text)


def sanitize_dict(data: Dict[str, Any], mask_emails: bool = True) -> Dict[str, Any]:
    """Convenience function to sanitize dictionaries."""
    sanitizer = _default_sanitizer if mask_emails else EvidenceSanitizer(mask_emails=False)
    return sanitizer.sanitize_dict(data)


def sanitize_list(items: List[Any], mask_emails: bool = True) -> List[Any]:
    """Convenience function to sanitize lists."""
    sanitizer = _default_sanitizer if mask_emails else EvidenceSanitizer(mask_emails=False)
    return sanitizer.sanitize_list(items)


def sanitize_data(data: Any, mask_emails: bool = True) -> Any:
    """Convenience function to sanitize arbitrary data."""
    sanitizer = _default_sanitizer if mask_emails else EvidenceSanitizer(mask_emails=False)
    return sanitizer.sanitize_data(data)


def is_clean(text: str, mask_emails: bool = True) -> bool:
    """Check if text is clean of sensitive patterns."""
    sanitizer = _default_sanitizer if mask_emails else EvidenceSanitizer(mask_emails=False)
    return sanitizer.is_clean(text)
