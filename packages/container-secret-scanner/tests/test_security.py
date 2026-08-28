"""Security and DevSecOps compliance tests adhering to cibi-dev standard and CWE mitigations."""

import ast
import inspect
import re
import subprocess
from pathlib import Path

from scanner.engine import (
    MAX_WORKER_LIMIT,
    ScanOptions,
    SecretScannerEngine,
    redact_secret,
    sanitize_line_context,
)
from scanner.tar_parser import (
    DEFAULT_MAX_FILE_COUNT,
    DEFAULT_MAX_TOTAL_BYTES,
    is_safe_tar_path,
)


def test_cwe_400_threadpool_bounded_concurrency():
    """Verify ThreadPool workers are strictly bounded to prevent resource exhaustion (CWE-400)."""
    assert MAX_WORKER_LIMIT <= 32
    opt = ScanOptions(max_workers=100)
    assert opt.max_workers == 32
    opt_zero = ScanOptions(max_workers=0)
    assert opt_zero.max_workers == 1


def test_cwe_409_tar_bomb_default_quotas():
    """Verify default quotas against zip/tar bombs (CWE-409)."""
    assert DEFAULT_MAX_TOTAL_BYTES <= 500 * 1024 * 1024  # <= 500 MB
    assert DEFAULT_MAX_FILE_COUNT <= 10_000


def test_cwe_59_cwe_22_tar_path_traversal_rejection():
    """Verify path traversal attack vectors are blocked by is_safe_tar_path (CWE-59 & CWE-22)."""
    dangerous_paths = [
        "../test.txt",
        "../../etc/shadow",
        "/etc/passwd",
        "nested/../../secret",
        "C:\\Windows\\System32\\cmd.exe",
        "..\\windows\\test.txt",
    ]
    for path in dangerous_paths:
        assert not is_safe_tar_path(path), f"Failed to reject dangerous path: {path}"


def test_cwe_209_secret_redaction_masking():
    """Verify secrets are masked to prevent information disclosure in logs/reports (CWE-209)."""
    raw_secret = "AIza" + "SyD_ABCDefgh1234567890-_IJKLMNOPQRS"
    redacted = redact_secret(raw_secret)
    assert raw_secret not in redacted
    assert redacted == "[REDACTED]...PQRS"

    line = f"export API_KEY='{raw_secret}' # credentials"
    sanitized = sanitize_line_context(line, raw_secret)
    assert raw_secret not in sanitized
    assert "[REDACTED]...PQRS" in sanitized


def test_cwe_78_zero_shell_true_in_engine():
    """Verify all subprocess executions in engine.py avoid shell=True (CWE-78)."""
    import scanner.engine as eng
    source = inspect.getsource(eng)
    assert "shell=True" not in source


def test_cwe_798_zero_hardcoded_secrets_in_source():
    """Verify no hardcoded credentials exist in source code files (CWE-798)."""
    src_dir = Path(__file__).resolve().parent.parent / "src"
    scanner = SecretScannerEngine()

    for py_file in src_dir.rglob("*.py"):
        content = py_file.read_text(encoding="utf-8")
        # Ensure tests don't fail on regex pattern definitions in rules.py
        if py_file.name == "rules.py":
            continue
        findings = scanner.scan_content(content, str(py_file))
        assert len(findings) == 0, f"Found hardcoded secret in {py_file}: {findings}"
