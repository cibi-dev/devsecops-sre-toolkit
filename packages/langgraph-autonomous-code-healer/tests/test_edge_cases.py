"""Targeted tests for edge cases and branch coverage in analyzer, patcher, tester, and state."""

from __future__ import annotations

import asyncio
import time
from unittest.mock import patch
import pytest

from healer.nodes.analyzer import parse_bandit_json, run_sast_scan, validate_python_ast
from healer.nodes.patcher import (
    CodePatcher,
    ensure_imports,
    patch_code_deterministically,
)
from healer.nodes.tester import evaluate_code_sandboxed_async
from healer.state import BanditFinding, BanditReport, CweInfo


def test_state_cwe_id_non_digit_and_none():
    """Test cwe_id property with non-digit strings, empty strings, and None."""
    f1 = BanditFinding(
        filename="a.py",
        test_name="t1",
        test_id="B101",
        issue_text="msg",
        issue_cwe="NO_DIGITS_HERE",
        line_number=1,
    )
    assert f1.cwe_id is None

    f2 = BanditFinding(
        filename="a.py",
        test_name="t2",
        test_id="B101",
        issue_text="msg",
        issue_cwe={"id": "NON_NUMERIC"},
        line_number=1,
    )
    assert f2.cwe_id is None

    f3 = BanditFinding(
        filename="a.py",
        test_name="t3",
        test_id="B101",
        issue_text="msg",
        issue_cwe=None,
        line_number=1,
    )
    assert f3.cwe_id is None

    f4 = BanditFinding(
        filename="a.py",
        test_name="t4",
        test_id="B101",
        issue_text="msg",
        issue_cwe=CweInfo(id="ALPHA_ONLY"),
        line_number=1,
    )
    assert f4.cwe_id is None


def test_analyzer_validate_ast_unexpected_exception(monkeypatch):
    """Test validate_python_ast when ast.parse raises non-SyntaxError exception."""
    import ast

    def mock_parse(code):
        raise TypeError("Unexpected type error in AST parser")

    monkeypatch.setattr(ast, "parse", mock_parse)
    is_valid, err, tree = validate_python_ast("x = 1")
    assert is_valid is False
    assert "AST parse error" in err


def test_analyzer_parse_bandit_skips_malformed_finding():
    """Test parse_bandit_json skips elements that fail BanditFinding validation."""
    raw = {
        "results": [
            "THIS_IS_NOT_A_DICT",
            {
                "filename": "good.py",
                "test_name": "t1",
                "test_id": "B101",
                "line_number": 1,
                "issue_text": "text",
            },
        ]
    }
    report = parse_bandit_json(raw)
    assert len(report.results) == 1


def test_analyzer_run_sast_unlink_os_error(monkeypatch):
    """Test run_sast_scan handles os.unlink failure during temporary file cleanup."""
    import os

    def mock_unlink(path):
        raise OSError("Cannot delete file")

    monkeypatch.setattr(os, "unlink", mock_unlink)
    report = run_sast_scan("x = 1\n", filename="test.py")
    assert report is not None


def test_patcher_ensure_imports_multiline_docstrings():
    """Test ensure_imports with multiline triple-quoted docstrings."""
    code = "'''\nMultiline\nDocstring\n'''\n\nx = 1\n"
    updated = ensure_imports(code, ["import os"])
    assert "import os" in updated
    assert updated.startswith("'''\nMultiline\nDocstring\n'''\nimport os")


def test_patcher_ensure_imports_single_line_triple_quote():
    """Test ensure_imports with single-line triple quote."""
    code = "'''Short doc'''\nx = 1\n"
    updated = ensure_imports(code, ["import os"])
    assert "import os" in updated


def test_patcher_unused_import_removal():
    """Test removing unused pickle and marshal imports after remediation."""
    code = "import pickle\nimport marshal\n\nx = 1\n"
    patched, msgs = CodePatcher.patch_cwe_502(code)
    assert "import pickle" not in patched
    assert "import marshal" not in patched


def test_patcher_ast_safety_fallback_on_broken_patch():
    """Test deterministic patcher falls back cleanly when a patched candidate is invalid AST."""
    code = "def good(): return 1\n"
    findings = [{"test_id": "B602", "issue_cwe": 78}]

    with patch.object(CodePatcher, "patch_cwe_78", return_value=("def broken(:\n", ["Bad patch"])):
        patched, proposals, diff = patch_code_deterministically(code, findings)
        assert patched == code
        assert len(proposals) == 0


@pytest.mark.asyncio
async def test_tester_async_timeout():
    """Test asynchronous sandbox evaluation handling timeout."""
    code = "x = 1\n"

    def slow_scan(*args, **kwargs):
        time.sleep(0.05)
        return BanditReport()

    with patch("healer.nodes.tester.run_sast_scan", side_effect=slow_scan):
        res = await evaluate_code_sandboxed_async(code, timeout_seconds=0.01)
        assert res["is_clean"] is False
        assert res["test_passed"] is False
        assert "EXECUTION TIMEOUT" in res["test_output"]
