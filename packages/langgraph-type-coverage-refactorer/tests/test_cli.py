"""Unit tests for Refactorer CLI interface.

Tests argument parsing, exit codes, output saving, and Human-in-the-Loop confirmations.
Adheres to SECURITY.md Standard #3, #13, and #16.
"""

from __future__ import annotations

import io
import os
import tempfile
import pytest

from refactorer.cli import main, parse_args


def test_cli_parse_args_defaults():
    args = parse_args(["my_module.py"])
    assert args.target == "my_module.py"
    assert args.strict is True
    assert args.target_cov == 90.0
    assert args.max_iter == 3
    assert args.in_place is False
    assert args.auto_confirm is False


def test_cli_parse_args_explicit_flags():
    args = parse_args([
        "--target", "custom.py",
        "-o", "out.py",
        "--gen-tests", "test_out.py",
        "--no-strict",
        "--target-cov", "85.0",
        "--max-iter", "2",
        "--db-path", "state.db",
        "--in-place",
        "-y",
        "--json",
    ])
    assert args.target_opt == "custom.py"
    assert args.output == "out.py"
    assert args.test_output == "test_out.py"
    assert args.strict is False
    assert args.target_cov == 85.0
    assert args.max_iter == 2
    assert args.db_path == "state.db"
    assert args.in_place is True
    assert args.auto_confirm is True
    assert args.json_output is True


def test_cli_main_missing_target():
    exit_code = main([])
    assert exit_code == 1


def test_cli_main_nonexistent_file():
    exit_code = main(["/nonexistent/path/module.py"])
    assert exit_code == 1


def test_cli_main_success_with_output_file():
    with tempfile.TemporaryDirectory() as temp_dir:
        src_file = os.path.join(temp_dir, "calc.py")
        out_file = os.path.join(temp_dir, "calc_refactored.py")
        test_file = os.path.join(temp_dir, "test_calc.py")

        with open(src_file, "w", encoding="utf-8") as f:
            f.write("def add(a=1, b=2): return a + b\n")

        exit_code = main([
            src_file,
            "-o", out_file,
            "--gen-tests", test_file,
            "--max-iter", "1",
        ])

        assert os.path.isfile(out_file)
        assert os.path.isfile(test_file)
        with open(out_file, "r", encoding="utf-8") as f:
            content = f.read()
            assert "def add(a: int=1, b: int=2)" in content or "def add(a: int = 1, b: int = 2)" in content


def test_cli_main_json_output(capsys: pytest.CaptureFixture[str]):
    with tempfile.TemporaryDirectory() as temp_dir:
        src_file = os.path.join(temp_dir, "simple.py")
        with open(src_file, "w", encoding="utf-8") as f:
            f.write("def simple_func(x=10): return x\n")

        main([src_file, "--json", "--max-iter", "1"])
        captured = capsys.readouterr()
        assert "target_path" in captured.out
        assert "verification_history" in captured.out


def test_cli_main_in_place_with_auto_confirm():
    with tempfile.TemporaryDirectory() as temp_dir:
        src_file = os.path.join(temp_dir, "target.py")
        with open(src_file, "w", encoding="utf-8") as f:
            f.write("def multiply(x=2, y=3): return x * y\n")

        exit_code = main([src_file, "--in-place", "-y", "--max-iter", "1"])
        with open(src_file, "r", encoding="utf-8") as f:
            content = f.read()
            assert "def multiply(x: int=2, y: int=3)" in content or "def multiply(x: int = 2, y: int = 3)" in content


def test_cli_main_in_place_interactive_rejection(monkeypatch: pytest.MonkeyPatch):
    with tempfile.TemporaryDirectory() as temp_dir:
        src_file = os.path.join(temp_dir, "target.py")
        original_code = "def multiply(x=2, y=3): return x * y\n"
        with open(src_file, "w", encoding="utf-8") as f:
            f.write(original_code)

        # Simulate user typing 'n' to reject in-place mutation
        monkeypatch.setattr("builtins.input", lambda _: "n")
        exit_code = main([src_file, "--in-place", "--max-iter", "1"])
        assert exit_code == 0

        # File content must remain unchanged
        with open(src_file, "r", encoding="utf-8") as f:
            assert f.read() == original_code
