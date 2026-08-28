"""
Secure Command Sandbox and Environment Sanitizer.
Implements CWE-78 (Command Injection Prevention), CWE-22 (Path Traversal Defense),
and CWE-209 / CWE-532 (Log Sanitization / Secret Redaction).
"""

from __future__ import annotations

import os
import re
import shlex
from pathlib import Path
from typing import Dict, List, Optional, Union


# Common secret patterns for automated redaction
SECRET_PATTERNS = [
    re.compile(r"gh[pousr]_[A-Za-z0-9_]{36,255}"),                # GitHub tokens
    re.compile(r"AKIA[0-9A-Z]{16}"),                                # AWS Access Key ID
    re.compile(r"Bearer\s+[A-Za-z0-9\-._~+/]+=*", re.IGNORECASE),   # Bearer Auth
    re.compile(r"-----BEGIN [A-Z ]+PRIVATE KEY-----[\s\S]*?-----END [A-Z ]+PRIVATE KEY-----"), # RSA/EC Private keys
    re.compile(r"(password|passwd|secret|token|api_key|apikey)\s*[:=]\s*['\"]?([^\s'\"]+)['\"]?", re.IGNORECASE),
]


def tokenize_command(command: str) -> List[str]:
    """
    Parses a raw shell command string into a secure, discrete argument list.
    CWE-78 Prevention: Tokenized execution strictly with shell=False.
    """
    if not isinstance(command, str):
        raise TypeError(f"Command must be a string, got {type(command).__name__}")

    stripped = command.strip()
    if not stripped:
        raise ValueError("Cannot execute an empty command string")

    # Anti null-byte injection
    if "\x00" in stripped:
        raise ValueError("Null bytes are prohibited in command strings (CWE-78 defense)")

    try:
        tokens = shlex.split(stripped, posix=True)
    except ValueError as e:
        raise ValueError(f"Command string could not be parsed safely: {e}") from e

    if not tokens:
        raise ValueError("Command contains no executable tokens")

    return tokens


def sanitize_output(text: str, secrets: Optional[List[str]] = None) -> str:
    """
    Sanitizes stdout/stderr logs by masking sensitive secrets and credentials.
    CWE-209 / CWE-532 Prevention: Replaces sensitive data with [REDACTED].
    """
    if not text:
        return ""

    sanitized = text

    # 1. Mask user-declared secrets
    if secrets:
        for secret in secrets:
            if secret and len(secret) >= 3:
                sanitized = sanitized.replace(secret, "[REDACTED]")

    # 2. Mask known secret patterns
    # Password / Token assignment pattern
    for pattern in SECRET_PATTERNS:
        if pattern == SECRET_PATTERNS[-1]:
            # password/secret key-value match
            sanitized = pattern.sub(r"\1: [REDACTED]", sanitized)
        elif "PRIVATE KEY" in pattern.pattern:
            sanitized = pattern.sub("[REDACTED_PRIVATE_KEY]", sanitized)
        else:
            sanitized = pattern.sub("[REDACTED]", sanitized)

    return sanitized


def validate_working_dir(
    working_dir: Optional[Union[str, Path]],
    allowed_root: Optional[Union[str, Path]] = None,
) -> Path:
    """
    Validates the working directory to prevent path traversal attacks (CWE-22).
    """
    if working_dir is None:
        target_dir = Path.cwd().resolve()
    else:
        target_dir = Path(working_dir).resolve()

    if not target_dir.exists():
        raise FileNotFoundError(f"Working directory does not exist: {target_dir}")

    if not target_dir.is_dir():
        raise NotADirectoryError(f"Working directory path is not a directory: {target_dir}")

    if allowed_root is not None:
        root_dir = Path(allowed_root).resolve()
        try:
            # os.path.commonpath verifies target_dir is strictly inside or equal to root_dir
            common = os.path.commonpath([str(target_dir), str(root_dir)])
            if common != str(root_dir):
                raise PermissionError(
                    f"Path traversal detected: '{target_dir}' is outside allowed root '{root_dir}' (CWE-22 defense)"
                )
        except ValueError as e:
            raise PermissionError(f"Invalid path comparison for working directory: {e}") from e

    return target_dir


def build_sanitized_env(
    base_env: Optional[Dict[str, str]] = None,
    job_env: Optional[Dict[str, str]] = None,
    secrets: Optional[List[str]] = None,
) -> Dict[str, str]:
    """
    Constructs a controlled, isolated execution environment for job execution.
    Preserves minimal system variables (PATH, HOME, USER) while injecting pipeline vars.
    """
    # Safe base system environment keys
    safe_keys = {"PATH", "HOME", "USER", "LANG", "LC_ALL", "TERM", "TMPDIR", "TEMP", "TMP"}
    env: Dict[str, str] = {}

    for k in safe_keys:
        if k in os.environ:
            env[k] = os.environ[k]

    # Global pipeline env overrides
    if base_env:
        for k, v in base_env.items():
            env[str(k)] = str(v)

    # Job-specific env overrides
    if job_env:
        for k, v in job_env.items():
            env[str(k)] = str(v)

    # Inject standard CI environment markers
    env["CI"] = "true"
    env["CI_RUNNER"] = "lightweight-ci-runner"
    env["LIGHTWEIGHT_CI"] = "1"

    return env
