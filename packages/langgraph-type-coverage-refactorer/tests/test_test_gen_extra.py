"""Additional tests for Test Generator to achieve 95%+ coverage."""

from __future__ import annotations

import ast
import pytest

from refactorer.nodes.test_gen import TestGenerator


def test_test_generator_all_param_types():
    code = """def all_types(
    f: float,
    b: bool,
    l: list[int],
    d: dict[str, str],
    s: set[str],
    t: tuple[int, int],
    custom: Any
):
    if custom is None:
        return 0
    if f > 10.0:
        return 1
    return 2
"""
    generator = TestGenerator()
    suite = generator.generate_tests_for_source(code, module_name="types_mod")
    assert "def test_all_types_happy_path():" in suite
    assert "test_all_types_branch" in suite
    ast.parse(suite)


def test_test_generator_async_branches_and_exceptions():
    code = """async def complex_async(flag: bool, num: int):
    if not flag:
        raise ValueError("Flag must be True")
    if num > 50:
        return num * 2
    return num
"""
    generator = TestGenerator()
    suite = generator.generate_tests_for_source(code, module_name="async_mod")
    assert "@pytest.mark.asyncio" in suite
    assert "async def test_complex_async_branch_" in suite
    ast.parse(suite)


def test_test_generator_class_with_async_methods_and_init_args():
    code = """class DatabaseClient:
    def __init__(self, host: str, port: int = 5432, secure: bool = True):
        self.host = host
        self.port = port
        self.secure = secure

    async def execute_query(self, query: str) -> list:
        if not query:
            raise ValueError("Empty query")
        return [query]

    def close(self) -> bool:
        return True
"""
    generator = TestGenerator()
    suite = generator.generate_tests_for_source(code, module_name="db_mod")
    assert "def test_DatabaseClient_instantiation():" in suite
    assert "@pytest.mark.asyncio" in suite
    assert "async def test_DatabaseClient_execute_query_call():" in suite
    assert "def test_DatabaseClient_close_call():" in suite
    ast.parse(suite)


def test_test_generator_edge_values_coverage():
    generator = TestGenerator()
    params = [
        {"name": "i", "inferred_type": "int"},
        {"name": "fl", "inferred_type": "float"},
        {"name": "st", "inferred_type": "str"},
        {"name": "bo", "inferred_type": "bool"},
        {"name": "li", "inferred_type": "list[str]"},
        {"name": "di", "inferred_type": "dict[str, Any]"},
        {"name": "se", "inferred_type": "set[int]"},
        {"name": "tu", "inferred_type": "tuple[int]"},
        {"name": "op", "inferred_type": "Optional[str]"},
        {"name": "un", "inferred_type": "Unknown"},
    ]

    for p in params:
        def_val = generator._default_arg_value(p)
        edge_val = generator._edge_arg_value(p)
        err_val = generator._error_trigger_value(p)
        assert isinstance(def_val, str)
        assert isinstance(edge_val, str)
        assert isinstance(err_val, str)
