"""Safe YAML manifest parser with strict validation and size limits (CWE-502, CWE-400)."""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any
import yaml
from pydantic import ValidationError

from drift.schema import Manifest

# Max manifest size: 1 MiB to prevent memory exhaustion and decompression bombs (CWE-400)
MAX_MANIFEST_BYTES = 1024 * 1024


class ManifestParseError(Exception):
    """Raised when manifest parsing or schema validation fails."""


class FileSizeExceededError(ManifestParseError):
    """Raised when manifest size exceeds the allowable limit."""


# Common patterns for tokens, keys, passwords (CWE-209 / CWE-798)
RE_SECRETS = [
    (re.compile(r"(?i)(password|passwd|secret|token|api[_-]?key)\s*[:=]\s*['\"]?([^'\"\s\n]+)['\"]?"), r"\1: [REDACTED]"),
    (re.compile(r"ghp_[a-zA-Z0-9]{36,255}"), "[REDACTED_GH_TOKEN]"),
    (re.compile(r"sk-[a-zA-Z0-9]{20,255}"), "[REDACTED_OPENAI_KEY]"),
    (re.compile(r"AKIA[0-9A-Z]{16}"), "[REDACTED_AWS_KEY]"),
    (re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"), "[REDACTED_PRIVATE_KEY]"),
]


def sanitize_secrets(text: str) -> str:
    """Mask sensitive tokens, passwords, and private keys from output strings (CWE-209)."""
    sanitized = text
    for pattern, replacement in RE_SECRETS:
        sanitized = pattern.sub(replacement, sanitized)
    return sanitized


def parse_manifest(source: str | Path) -> Manifest:
    """Parse and validate a YAML manifest from a file path or raw string.

    Args:
        source: File path (str/Path) or raw YAML string.

    Returns:
        Manifest: Validated Pydantic Manifest object.

    Raises:
        FileSizeExceededError: If the source exceeds 1 MiB.
        ManifestParseError: If parsing or validation fails.
    """
    raw_content: str

    if isinstance(source, Path) or (isinstance(source, str) and (os.path.exists(source) or source.endswith((".yaml", ".yml")))):
        file_path = Path(source)
        if not file_path.is_file():
            raise ManifestParseError(f"Manifest file not found: {file_path}")
        
        file_size = file_path.stat().st_size
        if file_size > MAX_MANIFEST_BYTES:
            raise FileSizeExceededError(
                f"Manifest size ({file_size} bytes) exceeds maximum limit of {MAX_MANIFEST_BYTES} bytes"
            )
        
        try:
            raw_content = file_path.read_text(encoding="utf-8")
        except UnicodeDecodeError as exc:
            raise ManifestParseError(f"Manifest is not valid UTF-8: {exc}") from exc
        except OSError as exc:
            raise ManifestParseError(f"Failed to read manifest file: {exc}") from exc
    else:
        raw_content = str(source)
        if len(raw_content.encode("utf-8")) > MAX_MANIFEST_BYTES:
            raise FileSizeExceededError(
                f"Manifest content size exceeds maximum limit of {MAX_MANIFEST_BYTES} bytes"
            )

    try:
        # Use safe_load to prevent arbitrary code execution (CWE-502)
        parsed_data: Any = yaml.safe_load(raw_content)
    except yaml.YAMLError as exc:
        raise ManifestParseError(f"Invalid YAML syntax: {exc}") from exc

    if parsed_data is None:
        # Empty manifest defaults to empty Manifest model
        parsed_data = {}

    if not isinstance(parsed_data, dict):
        raise ManifestParseError(f"Expected YAML mapping at root, got {type(parsed_data).__name__}")

    try:
        manifest = Manifest.model_validate(parsed_data)
    except ValidationError as exc:
        # Format Pydantic errors cleanly
        error_lines = []
        for err in exc.errors():
            loc = " -> ".join(str(l) for l in err.get("loc", []))
            msg = err.get("msg", "")
            error_lines.append(f"Field '{loc}': {msg}")
        raise ManifestParseError(f"Schema validation failed:\n  " + "\n  ".join(error_lines)) from exc

    return manifest
