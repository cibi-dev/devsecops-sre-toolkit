"""Unit tests for the multi-threaded secret scanner engine and guardrails."""

import io
import subprocess
import tarfile
import pytest
from pathlib import Path
from unittest.mock import MagicMock, patch

from scanner.engine import (
    Finding,
    ScanOptions,
    ScanSummary,
    SecretScannerEngine,
    redact_secret,
    sanitize_line_context,
)


def test_redact_secret_short_and_empty():
    """Short secrets or empty strings are fully masked as [REDACTED]."""
    assert redact_secret("") == "[REDACTED]"
    assert redact_secret("1234567") == "[REDACTED]"
    assert redact_secret("12345678") == "[REDACTED]"


def test_redact_secret_long():
    """Secrets longer than 8 characters display only trailing 4 characters."""
    token = "AKIA" + "IOSFODNN7EXAMPLE"
    redacted = redact_secret(token)
    assert redacted.startswith("[REDACTED]...")
    assert redacted.endswith("MPLE")
    assert "IOSFODNN7" not in redacted


def test_sanitize_line_context():
    """Source lines containing secrets have the secret masked."""
    token = "AKIA" + "IOSFODNN7EXAMPLE"
    line = f"AWS_KEY = '{token}' # primary key"
    sanitized = sanitize_line_context(line, token)
    assert token not in sanitized
    assert "[REDACTED]" in sanitized
    assert "# primary key" in sanitized

    # Empty context
    assert sanitize_line_context("", token) == ""

    # Long line context truncation
    long_line = "A" * 300 + token
    sanitized_long = sanitize_line_context(long_line, token)
    assert len(sanitized_long) <= 205
    assert sanitized_long.endswith("...")


def test_scan_summary_properties():
    """ScanSummary severity properties correctly compute counts."""
    findings = [
        Finding("R1", "N1", "f1", 1, 1, "t1", "[R]", 5.0, "CRITICAL", "CWE-798", "Cat", "ctx"),
        Finding("R2", "N2", "f2", 2, 1, "t2", "[R]", 5.0, "HIGH", "CWE-798", "Cat", "ctx"),
        Finding("R3", "N3", "f3", 3, 1, "t3", "[R]", 5.0, "MEDIUM", "CWE-798", "Cat", "ctx"),
        Finding("R4", "N4", "f4", 4, 1, "t4", "[R]", 5.0, "LOW", "CWE-798", "Cat", "ctx"),
    ]
    summary = ScanSummary(
        files_scanned=4,
        bytes_scanned=1000,
        findings=findings,
        duration_seconds=1.0,
    )
    assert summary.has_findings is True
    assert summary.critical_count == 1
    assert summary.high_count == 1
    assert summary.medium_count == 1
    assert summary.low_count == 1


def test_scan_options_worker_bounding():
    """Worker threads are strictly bounded between 1 and 32 (CWE-400)."""
    opt_high = ScanOptions(max_workers=999)
    assert opt_high.max_workers == 32

    opt_low = ScanOptions(max_workers=-10)
    assert opt_low.max_workers == 1

    opt_zero = ScanOptions(max_workers=0)
    assert opt_zero.max_workers == 1

    opt_valid = ScanOptions(max_workers=8)
    assert opt_valid.max_workers == 8


def test_scan_content_detects_secret():
    """Engine detects regex secrets in string content."""
    engine = SecretScannerEngine()
    token = "ghp_" + "1234567890abcdefghijklmnopqrstuvwxyz"
    content = f"// Setup\nconst token = '{token}';\n"
    findings = engine.scan_content(content, "src/config.js")

    assert len(findings) >= 1
    f = findings[0]
    assert f.rule_id == "RULE-GITHUB-PAT"
    assert f.line_number == 2
    assert f.severity == "CRITICAL"
    assert token not in f.redacted_text


def test_scan_content_empty_or_long_lines():
    """Engine handles empty content and skips minified >50k character lines."""
    engine = SecretScannerEngine()
    assert engine.scan_content("", "empty.txt") == []

    # Giant minified line
    giant_line = "x" * 60_000
    assert engine.scan_content(giant_line, "minified.js") == []


def test_scan_content_with_ast():
    """scan_content executes AST scan on .py files and avoids duplicates."""
    engine = SecretScannerEngine()
    code = "secret_key = '" + "qW3r" + "Ty9uI0pAsDfGhJkLzXcVbN12456'\n"
    findings = engine.scan_content(code, "config.py")
    assert len(findings) >= 1


def test_scan_directory(tmp_path: Path):
    """Engine scans directories recursively across threads."""
    dir_path = tmp_path / "project"
    dir_path.mkdir()

    # Clean file
    (dir_path / "main.py").write_text("print('Hello World')\n", encoding="utf-8")

    # File with secret
    token = "xoxb-" + "123456789012" + "-" + "123456789012" + "-" + "abcdefghijklmnopqrstuvwx"
    (dir_path / "slack.py").write_text(f"SLACK_BOT = '{token}'\n", encoding="utf-8")

    engine = SecretScannerEngine(options=ScanOptions(max_workers=2))
    summary = engine.scan_directory(dir_path)

    assert summary.files_scanned == 2
    assert summary.bytes_scanned > 0
    assert summary.critical_count >= 1
    assert any(f.rule_id == "RULE-SLACK-BOT-TOKEN" for f in summary.findings)


def test_scan_directory_non_existent():
    """Scanning non-existent directory returns error summary."""
    engine = SecretScannerEngine()
    summary = engine.scan_directory("/non/existent/path/for/secret/test")
    assert summary.files_scanned == 0
    assert len(summary.errors) == 1


def test_scan_directory_worker_error(tmp_path: Path):
    """Worker exception in scan_directory is caught and added to errors."""
    dir_path = tmp_path / "project_err"
    dir_path.mkdir()
    (dir_path / "file1.txt").write_text("content", encoding="utf-8")

    engine = SecretScannerEngine()
    with patch.object(engine, "scan_file", side_effect=ValueError("Worker failed")):
        summary = engine.scan_directory(dir_path)
        assert len(summary.errors) == 1
        assert "Unhandled worker error" in summary.errors[0]


def test_scan_directory_exclusions(tmp_path: Path):
    """Excluded directories (.git, node_modules, .venv) are ignored."""
    dir_path = tmp_path / "repo"
    dir_path.mkdir()

    # Secret inside node_modules
    nm_dir = dir_path / "node_modules" / "subpkg"
    nm_dir.mkdir(parents=True)
    token = "ghp_" + "1234567890abcdefghijklmnopqrstuvwxyz"
    (nm_dir / "secret.js").write_text(f"token = '{token}'", encoding="utf-8")

    # Clean file in root
    (dir_path / "index.js").write_text("console.log('clean');", encoding="utf-8")

    engine = SecretScannerEngine()
    summary = engine.scan_directory(dir_path)

    assert summary.files_scanned == 1
    assert summary.has_findings is False


def test_scan_file_edge_cases(tmp_path: Path):
    """Test scan_file error branches, non-files, and oversized files."""
    engine = SecretScannerEngine(options=ScanOptions(max_file_size_bytes=100))

    # 1. Non-existent file
    findings, size, err = engine.scan_file(tmp_path / "missing.txt")
    assert err is not None

    # 2. Oversized file
    big_file = tmp_path / "large.txt"
    big_file.write_text("A" * 200, encoding="utf-8")
    findings, size, err = engine.scan_file(big_file)
    assert findings == []
    assert size == 200
    assert err is None


def test_scan_file_skips_binary(tmp_path: Path):
    """Binary files containing null bytes are safely skipped."""
    bin_file = tmp_path / "blob.bin"
    bin_file.write_bytes(b"\x00\x01\x02\x03\x00\x00\x00")

    engine = SecretScannerEngine()
    findings, size, err = engine.scan_file(bin_file)
    assert findings == []
    assert size == 7
    assert err is None


def test_scan_tar_integration(tmp_path: Path):
    """Engine scans a tar archive and detects secrets inside entries."""
    tar_path = tmp_path / "archive.tar"
    token = "AIza" + "SyD_ABCDefgh1234567890-_IJKLMNOPQRS"

    with tarfile.open(tar_path, "w") as tar:
        data = f"GOOGLE_KEY = '{token}'\n".encode("utf-8")
        info = tarfile.TarInfo(name="app/config.py")
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))

    engine = SecretScannerEngine()
    summary = engine.scan_tar(tar_path)

    assert summary.files_scanned == 1
    assert len(summary.findings) >= 1
    assert summary.findings[0].rule_id == "RULE-GCP-API-KEY"


def test_scan_tar_non_existent():
    """scan_tar with missing file returns error summary."""
    engine = SecretScannerEngine()
    summary = engine.scan_tar("/missing/archive.tar")
    assert summary.files_scanned == 0
    assert len(summary.errors) == 1


def test_scan_tar_with_binary_and_security_error(tmp_path: Path):
    """scan_tar handles binary entries and security violations gracefully."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        info = tarfile.TarInfo(name="../../evil.txt")
        data = b"secret"
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))
    buf.seek(0)
    evil_path = tmp_path / "evil.tar"
    evil_path.write_bytes(buf.getvalue())

    engine = SecretScannerEngine()
    summary = engine.scan_tar(evil_path)
    assert len(summary.errors) >= 1
    assert "Security constraint violated" in summary.errors[0]


def test_scan_git_integration(tmp_path: Path):
    """Engine scans Git tracked files safely via subprocess (CWE-78)."""
    git_dir = tmp_path / "git_repo"
    git_dir.mkdir()

    # Initialize git repo
    subprocess.run(["git", "init"], cwd=git_dir, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.name", "TestUser"], cwd=git_dir, check=True)
    subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=git_dir, check=True)

    token = "ghp_" + "1234567890abcdefghijklmnopqrstuvwxyz"
    (git_dir / "auth.py").write_text(f"TOKEN = '{token}'\n", encoding="utf-8")
    subprocess.run(["git", "add", "auth.py"], cwd=git_dir, check=True)

    engine = SecretScannerEngine()
    summary = engine.scan_git(git_dir)

    assert summary.files_scanned == 1
    assert len(summary.findings) >= 1
    assert summary.findings[0].rule_id == "RULE-GITHUB-PAT"


def test_scan_git_not_a_repo(tmp_path: Path):
    """scan_git on non-repo directory returns error summary."""
    engine = SecretScannerEngine()
    summary = engine.scan_git(tmp_path)
    assert summary.files_scanned == 0
    assert len(summary.errors) == 1


def test_scan_git_command_error(tmp_path: Path):
    """scan_git handles git command errors gracefully."""
    git_dir = tmp_path / "fake_git"
    git_dir.mkdir()
    (git_dir / ".git").mkdir()

    engine = SecretScannerEngine()
    summary = engine.scan_git(git_dir)
    assert len(summary.errors) >= 1
