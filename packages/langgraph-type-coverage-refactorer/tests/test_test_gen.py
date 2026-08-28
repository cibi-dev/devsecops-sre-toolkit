"""Unit tests for Test Generator node.

Tests automated synthesis of executable Pytest suites targeting high branch coverage.
Adheres to SECURITY.md Standard #2 and #15.
"""

from __future__ import annotations

import ast
import pytest

from refactorer.nodes.test_gen import TestGenerator, test_gen_node as invoke_test_gen_node


def test_test_generator_simple_function():
    code = """def compute_tax(income: float, is_resident: bool = True) -> float:
    if income <= 0:
        return 0.0
    if not is_resident:
        return income * 0.30
    return income * 0.15
"""
    generator = TestGenerator()
    test_suite = generator.generate_tests_for_source(code, module_name="tax_service")

    assert "import tax_service as target" in test_suite
    assert "def test_compute_tax_happy_path():" in test_suite
    assert "test_compute_tax_edge_cases" in test_suite

    # Check syntax validity of generated test suite
    parsed = ast.parse(test_suite)
    assert parsed is not None


def test_test_generator_class_and_methods():
    code = """class SessionManager:
    def __init__(self, session_id: str, timeout: int = 3600) -> None:
        self.session_id = session_id
        self.timeout = timeout

    def is_valid(self) -> bool:
        return len(self.session_id) > 0

    def renew(self, extension: int = 1800) -> int:
        self.timeout += extension
        return self.timeout
"""
    generator = TestGenerator()
    test_suite = generator.generate_tests_for_source(code, module_name="session_mod")

    assert "def test_SessionManager_instantiation():" in test_suite
    assert "def test_SessionManager_is_valid_call():" in test_suite
    assert "def test_SessionManager_renew_call():" in test_suite
    ast.parse(test_suite)


def test_test_generator_async_functions():
    code = """async def fetch_user_data(user_id: int) -> dict:
    if user_id < 0:
        raise ValueError("Invalid user_id")
    return {"id": user_id, "name": "Test User"}
"""
    generator = TestGenerator()
    test_suite = generator.generate_tests_for_source(code, module_name="async_service")

    assert "@pytest.mark.asyncio" in test_suite
    assert "async def test_fetch_user_data_happy_path():" in test_suite
    assert "await target.fetch_user_data(" in test_suite
    ast.parse(test_suite)


def test_test_generator_fallback_on_invalid_tree():
    generator = TestGenerator()
    # If passed empty or fallback
    test_suite = generator.generate_tests_for_source("pass", module_name="dummy_mod")
    assert "import dummy_mod as target" in test_suite
    ast.parse(test_suite)


def test_test_gen_node_langgraph_integration():
    state = {
        "current_code": "def double(val: int) -> int:\n    if val > 0:\n        return val * 2\n    return 0\n",
    }
    result = invoke_test_gen_node(state)
    assert "current_tests" in result
    assert "def test_double_happy_path" in result["current_tests"]
    ast.parse(result["current_tests"])


def test_test_gen_node_error_resilience():
    broken_state = {
        "current_code": "def broken(: pass",
    }
    result = invoke_test_gen_node(broken_state)
    # Generates safe fallback or sets error
    assert "current_tests" in result or "error" in result
