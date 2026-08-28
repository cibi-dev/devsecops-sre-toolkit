"""Unit tests for healer.nodes.tester process sandboxing and timeout evaluation."""

from __future__ import annotations

import pytest

from healer.nodes.tester import (
    evaluate_code_sandboxed_async,
    evaluate_code_sandboxed_sync,
    tester_node as run_tester_node,
    tester_node_async as run_tester_node_async,
)
from healer.state import CodePatchState


def test_evaluate_code_sandboxed_sync_clean():
    """Test synchronous sandbox evaluation on clean code."""
    clean_code = "def add(a: int, b: int) -> int:\n    return a + b\n"
    res = evaluate_code_sandboxed_sync(clean_code, filename="clean.py")
    assert res["is_clean"] is True
    assert res["test_passed"] is True
    assert "ALL CHECKS PASSED" in res["test_output"]
    assert len(res["findings"]) == 0


def test_evaluate_code_sandboxed_sync_syntax_error():
    """Test synchronous sandbox evaluation on broken syntax."""
    bad_code = "def broken(:"
    res = evaluate_code_sandboxed_sync(bad_code, filename="bad.py")
    assert res["is_clean"] is False
    assert res["test_passed"] is False
    assert "AST Syntax Check FAILED" in res["test_output"]
    assert len(res["findings"]) == 1


def test_evaluate_code_sandboxed_sync_vulnerable():
    """Test synchronous sandbox evaluation on vulnerable code."""
    vuln_code = (
        "import subprocess\n"
        "def run_cmd(user_input):\n"
        "    subprocess.call(user_input, shell=True)\n"
    )
    res = evaluate_code_sandboxed_sync(vuln_code, filename="vuln.py")
    assert res["is_clean"] is False
    assert "SAST CHECKS FAILED" in res["test_output"]
    assert len(res["findings"]) > 0


@pytest.mark.asyncio
async def test_evaluate_code_sandboxed_async_clean():
    """Test asynchronous sandbox evaluation on clean code."""
    clean_code = "x = [1, 2, 3]\ny = sum(x)\n"
    res = await evaluate_code_sandboxed_async(clean_code, filename="async_clean.py")
    assert res["is_clean"] is True
    assert res["test_passed"] is True
    assert "ALL CHECKS PASSED" in res["test_output"]


@pytest.mark.asyncio
async def test_evaluate_code_sandboxed_async_syntax_error():
    """Test asynchronous sandbox evaluation on syntax errors."""
    bad_code = "def bad(x:\n"
    res = await evaluate_code_sandboxed_async(bad_code, filename="async_bad.py")
    assert res["is_clean"] is False
    assert res["test_passed"] is False
    assert "AST Syntax Check FAILED" in res["test_output"]


def test_tester_node_sync():
    """Test tester_node LangGraph node execution."""
    state: CodePatchState = {
        "source_file": "clean.py",
        "original_code": "x = 10\n",
        "current_code": "x = 10\n",
        "bandit_report": {},
        "findings": [],
        "proposed_patch": "x = 10\n",
        "patch_history": [],
        "test_output": "",
        "test_passed": False,
        "is_clean": False,
        "iterations": 0,
        "max_iterations": 3,
        "error_message": None,
        "dry_run": False,
        "diff": "",
    }

    result = run_tester_node(state)
    assert result["is_clean"] is True
    assert result["test_passed"] is True
    assert result["iterations"] == 1


@pytest.mark.asyncio
async def test_tester_node_async():
    """Test tester_node_async LangGraph node execution."""
    state: CodePatchState = {
        "source_file": "clean.py",
        "original_code": "x = 10\n",
        "current_code": "x = 10\n",
        "bandit_report": {},
        "findings": [],
        "proposed_patch": "x = 10\n",
        "patch_history": [],
        "test_output": "",
        "test_passed": False,
        "is_clean": False,
        "iterations": 0,
        "max_iterations": 3,
        "error_message": None,
        "dry_run": False,
        "diff": "",
    }

    result = await run_tester_node_async(state)
    assert result["is_clean"] is True
    assert result["test_passed"] is True
    assert result["iterations"] == 1
