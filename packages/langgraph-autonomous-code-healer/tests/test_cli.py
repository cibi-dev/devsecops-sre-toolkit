"""Unit tests for healer.cli command line interface."""

from __future__ import annotations

import json
from pathlib import Path
import pytest

from healer.cli import build_parser, main


def test_cli_parser_build():
    """Test building CLI parser and argument defaults."""
    parser = build_parser()
    args = parser.parse_args(["--file", "app.py", "--max-iterations", "5", "--dry-run"])
    assert args.file == "app.py"
    assert args.max_iterations == 5
    assert args.dry_run is True


def test_cli_no_args(capsys):
    """Test CLI execution with no arguments exits with 1 and prints help."""
    code = main([])
    assert code == 1


def test_cli_nonexistent_file(tmp_path: Path, capsys):
    """Test CLI execution with non-existent file."""
    nonexistent = tmp_path / "nonexistent_file_99999.py"
    code = main(["--file", str(nonexistent)])
    assert code == 1
    captured = capsys.readouterr()
    assert "Target file not found" in captured.err


def test_cli_directory_target(tmp_path: Path, capsys):
    """Test CLI execution with directory path instead of file."""
    code = main(["--file", str(tmp_path)])
    assert code == 1
    captured = capsys.readouterr()
    assert "Target path is not a file" in captured.err


def test_cli_clean_file(tmp_path: Path):
    """Test CLI execution on a clean Python file."""
    clean_file = tmp_path / "clean_code.py"
    clean_file.write_text("def add(a: int, b: int) -> int:\n    return a + b\n", encoding="utf-8")

    code = main(["--file", str(clean_file)])
    assert code == 0


def test_cli_vulnerable_file_live_patching(tmp_path: Path):
    """Test CLI execution on vulnerable file with in-place modification."""
    vuln_file = tmp_path / "vuln_code.py"
    vuln_file.write_text("import yaml\ndef load_data(x):\n    return yaml.load(x)\n", encoding="utf-8")

    code = main(["--file", str(vuln_file)])
    assert code == 0

    healed_content = vuln_file.read_text(encoding="utf-8")
    assert "yaml.safe_load" in healed_content


def test_cli_dry_run_mode(tmp_path: Path):
    """Test CLI --dry-run does not modify target file."""
    vuln_file = tmp_path / "vuln_dry.py"
    original_content = "import yaml\ndef load_data(x):\n    return yaml.load(x)\n"
    vuln_file.write_text(original_content, encoding="utf-8")

    code = main(["--file", str(vuln_file), "--dry-run"])
    assert code == 0

    # Content must remain untouched
    assert vuln_file.read_text(encoding="utf-8") == original_content


def test_cli_output_flag(tmp_path: Path):
    """Test CLI -o / --output saves healed code to a separate file."""
    vuln_file = tmp_path / "vuln_src.py"
    out_file = tmp_path / "healed_out.py"
    vuln_file.write_text("import yaml\ndef load_data(x):\n    return yaml.load(x)\n", encoding="utf-8")

    code = main(["--file", str(vuln_file), "-o", str(out_file)])
    assert code == 0
    assert out_file.exists()
    assert "yaml.safe_load" in out_file.read_text(encoding="utf-8")


def test_cli_with_report_file(tmp_path: Path):
    """Test CLI with a pre-existing Bandit report file."""
    target_file = tmp_path / "report_target.py"
    target_file.write_text(
        "import subprocess\n"
        "def execute(cmd):\n"
        "    subprocess.call(cmd, shell=True)\n",
        encoding="utf-8",
    )

    report_file = tmp_path / "bandit_report.json"
    report_file.write_text(
        json.dumps(
            {
                "generated_at": "2026-08-27T12:00:00Z",
                "results": [
                    {
                        "filename": str(target_file),
                        "test_name": "subprocess_popen_with_shell_equals_true",
                        "test_id": "B602",
                        "issue_severity": "HIGH",
                        "issue_confidence": "HIGH",
                        "issue_text": "subprocess call with shell=True",
                        "issue_cwe": {"id": 78},
                        "line_number": 3,
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    code = main(["--file", str(target_file), "--report", str(report_file)])
    assert code == 0
