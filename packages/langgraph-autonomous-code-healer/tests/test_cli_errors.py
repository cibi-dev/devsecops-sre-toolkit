"""Error handling and edge case tests for healer.cli."""

from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import patch
import pytest

from healer.cli import main


def test_cli_unreadable_source_file(tmp_path: Path, monkeypatch):
    """Test CLI error handling when target file cannot be read."""
    unreadable = tmp_path / "unreadable.py"
    unreadable.write_text("x = 1\n", encoding="utf-8")

    def mock_read_text(*args, **kwargs):
        raise PermissionError("Access denied")

    monkeypatch.setattr(Path, "read_text", mock_read_text)
    code = main(["--file", str(unreadable)])
    assert code == 1


def test_cli_nonexistent_report_file(tmp_path: Path, capsys):
    """Test CLI when specified report file does not exist."""
    src = tmp_path / "src.py"
    src.write_text("x = 1\n", encoding="utf-8")
    nonexistent = tmp_path / "nonexistent_report_file.json"

    code = main(["--file", str(src), "--report", str(nonexistent)])
    assert code == 1
    captured = capsys.readouterr()
    assert "Report file not found" in captured.err


def test_cli_unreadable_report_file(tmp_path: Path, monkeypatch, capsys):
    """Test CLI when report file cannot be read."""
    src = tmp_path / "src.py"
    src.write_text("x = 1\n", encoding="utf-8")
    rep = tmp_path / "rep.json"
    rep.write_text("{}", encoding="utf-8")

    original_read_text = Path.read_text

    def mock_read(self, *args, **kwargs):
        if str(self).endswith(".json"):
            raise OSError("I/O error reading report")
        return original_read_text(self, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", mock_read)
    code = main(["--file", str(src), "--report", str(rep)])
    assert code == 1
    captured = capsys.readouterr()
    assert "Error reading report file" in captured.err


def test_cli_graph_execution_exception(tmp_path: Path, monkeypatch, capsys):
    """Test CLI when graph execution raises an unexpected fatal error."""
    src = tmp_path / "src.py"
    src.write_text("x = 1\n", encoding="utf-8")

    def mock_run_healer(*args, **kwargs):
        raise RuntimeError("Graph runtime crashed")

    monkeypatch.setattr("healer.cli.run_healer", mock_run_healer)
    code = main(["--file", str(src)])
    assert code == 1
    captured = capsys.readouterr()
    assert "Fatal error during graph execution" in captured.err


def test_cli_output_write_error(tmp_path: Path, monkeypatch, capsys):
    """Test CLI when saving output file fails with permission or disk error."""
    src = tmp_path / "src.py"
    src.write_text("import yaml\ndef l(x): return yaml.load(x)\n", encoding="utf-8")

    def mock_write_text(*args, **kwargs):
        raise OSError("Read-only filesystem")

    monkeypatch.setattr(Path, "write_text", mock_write_text)
    code = main(["--file", str(src)])
    assert code == 1
    captured = capsys.readouterr()
    assert "Error saving healed code" in captured.err
