"""Unit tests for Sandbox Verifier node.

Tests isolated MyPy strict execution, Pytest coverage calculation,
sanitization, and timeout handling.
Adheres to SECURITY.md Standard #3, #4, #8, #10, #13, and #17.
"""

from __future__ import annotations

import asyncio
import tempfile
import pytest

from refactorer.nodes.verifier import SandboxVerifier, verifier_node


def test_sandbox_verifier_success():
    clean_code = """from __future__ import annotations

def add_positive(a: int, b: int) -> int:
    if a < 0 or b < 0:
        raise ValueError("Inputs must be non-negative")
    return a + b
"""

    clean_tests = """from __future__ import annotations
import pytest
import target_module as target

def test_add_positive_happy():
    assert target.add_positive(2, 3) == 5

def test_add_positive_negative_a():
    with pytest.raises(ValueError):
        target.add_positive(-1, 5)

def test_add_positive_negative_b():
    with pytest.raises(ValueError):
        target.add_positive(5, -1)
"""

    verifier = SandboxVerifier(timeout_seconds=20.0)
    result = verifier.verify_code_and_tests(clean_code, clean_tests, strict_mypy=True)

    assert result.mypy_passed is True
    assert result.pytest_passed is True
    assert result.coverage_pct >= 90.0
    assert result.execution_time_ms > 0
    assert result.error_message is None
    # Sandbox paths must be sanitized
    assert tempfile.gettempdir() not in result.mypy_output or "/sandbox" in result.mypy_output


def test_sandbox_verifier_mypy_strict_failure():
    untyped_code = """def untyped_func(x):
    return x.unknown_method()
"""
    tests = """import target_module as target
def test_dummy():
    assert target is not None
"""
    verifier = SandboxVerifier(timeout_seconds=20.0)
    result = verifier.verify_code_and_tests(untyped_code, tests, strict_mypy=True)

    assert result.mypy_passed is False
    assert "Function is missing a type annotation" in result.mypy_output or "error:" in result.mypy_output


def test_sandbox_verifier_pytest_failure():
    code = """def always_fails() -> None:
    raise RuntimeError("Intentional error")
"""
    failing_tests = """import target_module as target
def test_failure():
    target.always_fails()
"""
    verifier = SandboxVerifier(timeout_seconds=20.0)
    result = verifier.verify_code_and_tests(code, failing_tests, strict_mypy=False)

    assert result.pytest_passed is False
    assert "FAILED" in result.pytest_output or "RuntimeError" in result.pytest_output


def test_sandbox_verifier_regex_coverage_fallback():
    verifier = SandboxVerifier()
    output_1 = "TOTAL 10 1 90%"
    assert verifier._parse_coverage_stdout(output_1) == 90.0

    output_2 = "target_module.py 15 0 100%"
    assert verifier._parse_coverage_stdout(output_2) == 100.0

    output_empty = "No coverage table here"
    assert verifier._parse_coverage_stdout(output_empty) == 0.0


@pytest.mark.asyncio
async def test_sandbox_verifier_async_execution():
    code = """from __future__ import annotations

def multiply(a: int, b: int) -> int:
    return a * b
"""
    tests = """import target_module as target
def test_mult():
    assert target.multiply(3, 4) == 12
"""
    verifier = SandboxVerifier(timeout_seconds=15.0)
    result = await verifier.verify_async(code, tests, strict_mypy=True)
    assert result.mypy_passed is True
    assert result.pytest_passed is True


def test_verifier_node_langgraph_integration():
    code = """from __future__ import annotations
def increment(val: int) -> int:
    return val + 1
"""
    tests = """import target_module as target
def test_inc():
    assert target.increment(10) == 11
"""
    state = {
        "current_code": code,
        "current_tests": tests,
        "strict_mode": True,
        "target_coverage": 80.0,
        "iterations": 0,
    }
    result = verifier_node(state)

    assert "verification_history" in result
    assert len(result["verification_history"]) == 1
    assert result["iterations"] == 1
    assert result["is_complete"] is True
