"""Unit tests for CLI commands, argument parsing, formats, and exit codes."""

import io
import json
import subprocess
import tarfile
import pytest
from pathlib import Path
from unittest.mock import patch

from scanner.cli import build_parser, main
from scanner.engine import Finding, ScanSummary
from scanner.reporters.console import render_console_report


def test_cli_version_flag(capsys):
    """--version prints version and exits."""
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    captured = capsys.readouterr()
    assert "container-secret-scanner 0.1.0" in captured.out or "container-secret-scanner 0.1.0" in captured.err


def test_cli_no_args_shows_help(capsys):
    """No arguments prints help menu with exit code 0."""
    code = main([])
    assert code == 0
    captured = capsys.readouterr()
    assert "usage:" in captured.out


def test_cli_scan_dir_clean(tmp_path: Path):
    """scan-dir on clean folder returns code 0."""
    clean_file = tmp_path / "clean.txt"
    clean_file.write_text("Clean file content without secrets\n", encoding="utf-8")

    code = main(["scan-dir", str(tmp_path), "--quiet"])
    assert code == 0


def test_cli_scan_dir_with_secret_and_fail_flag(tmp_path: Path):
    """scan-dir with --fail-on-secrets returns code 1 when secrets are present."""
    secret_file = tmp_path / "leaked.txt"
    token = "ghp_" + "1234567890abcdefghijklmnopqrstuvwxyz"
    secret_file.write_text(f"TOKEN={token}\n", encoding="utf-8")

    code = main(["scan-dir", str(tmp_path), "--fail-on-secrets", "--quiet"])
    assert code == 1


def test_cli_scan_dir_sarif_output(tmp_path: Path, capsys):
    """scan-dir with --format sarif writes SARIF report to file and stdout."""
    secret_file = tmp_path / "leaked.txt"
    token = "ghp_" + "1234567890abcdefghijklmnopqrstuvwxyz"
    secret_file.write_text(f"TOKEN={token}\n", encoding="utf-8")

    out_sarif = tmp_path / "results.sarif"
    code = main([
        "scan-dir",
        str(tmp_path),
        "--format", "sarif",
        "--output", str(out_sarif),
    ])
    assert code == 0
    assert out_sarif.exists()
    sarif_obj = json.loads(out_sarif.read_text(encoding="utf-8"))
    assert sarif_obj["version"] == "2.1.0"
    assert len(sarif_obj["runs"][0]["results"]) >= 1

    # Also test stdout printing
    code_stdout = main([
        "scan-dir",
        str(tmp_path),
        "--format", "sarif",
    ])
    assert code_stdout == 0
    captured = capsys.readouterr()
    assert "sarif-schema-2.1.0.json" in captured.out


def test_cli_scan_dir_json_output(tmp_path: Path, capsys):
    """scan-dir with --format json outputs JSON to file and stdout."""
    out_json = tmp_path / "results.json"
    code = main([
        "scan-dir",
        str(tmp_path),
        "--format", "json",
        "--output", str(out_json),
    ])
    assert code == 0
    assert out_json.exists()

    code_stdout = main([
        "scan-dir",
        str(tmp_path),
        "--format", "json",
    ])
    assert code_stdout == 0
    captured = capsys.readouterr()
    assert "container-secret-scanner" in captured.out


def test_cli_scan_dir_console_output_file(tmp_path: Path):
    """scan-dir with console format writes plain report to output file."""
    out_txt = tmp_path / "report.txt"
    code = main([
        "scan-dir",
        str(tmp_path),
        "--format", "console",
        "--output", str(out_txt),
        "--no-ast",
        "--no-color",
    ])
    assert code == 0
    assert out_txt.exists()
    assert "CONTAINER SECRET SCANNER" in out_txt.read_text(encoding="utf-8")


def test_cli_scan_tar(tmp_path: Path):
    """scan-tar analyzes tarballs and reports results."""
    tar_path = tmp_path / "bundle.tar"
    with tarfile.open(tar_path, "w") as tar:
        data = b"print('hello world')"
        info = tarfile.TarInfo(name="test.py")
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))

    code = main(["scan-tar", str(tar_path), "--quiet"])
    assert code == 0


def test_cli_scan_git(tmp_path: Path):
    """scan-git invokes Git repository scan."""
    code = main(["scan-git", str(tmp_path), "--quiet"])
    assert code == 0


def test_cli_invalid_command_or_exception():
    """Unrecognized command or fatal error returns non-zero code."""
    with patch("scanner.cli.run_scan", side_effect=RuntimeError("Simulated crash")):
        code = main(["scan-dir", "."])
        assert code == 1


def test_render_console_report_with_many_errors_and_severities():
    """Verify console report rendering with all severity badges and error overflow."""
    findings = [
        Finding("R1", "N1", "f1", 1, 1, "t1", "[R]", 5.0, "CRITICAL", "CWE-798", "Cat", "ctx"),
        Finding("R2", "N2", "f2", 2, 1, "t2", "[R]", 5.0, "HIGH", "CWE-798", "Cat", "ctx"),
        Finding("R3", "N3", "f3", 3, 1, "t3", "[R]", 5.0, "MEDIUM", "CWE-798", "Cat", "ctx"),
        Finding("R4", "N4", "f4", 4, 1, "t4", "[R]", 5.0, "LOW", "CWE-798", "Cat", "ctx"),
    ]
    summary = ScanSummary(
        files_scanned=4,
        bytes_scanned=1024 * 1024 * 2,
        findings=findings,
        duration_seconds=0.15,
        errors=[f"Warning {i}" for i in range(8)],
    )

    report_colored = render_console_report(summary, use_color=True)
    report_plain = render_console_report(summary, use_color=False)

    assert "[CRITICAL]" in report_plain
    assert "[HIGH]" in report_plain
    assert "[MEDIUM]" in report_plain
    assert "[LOW]" in report_plain
    assert "and 3 more" in report_plain
