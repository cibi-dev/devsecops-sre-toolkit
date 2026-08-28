"""Unit tests for Type Annotator node.

Tests AST transformation, type hint synthesis, and import injection.
Adheres to SECURITY.md Standard #15.
"""

from __future__ import annotations

import ast
import pytest

from refactorer.nodes.annotator import TypeAnnotator, annotator_node


def test_annotator_simple_function():
    code = """def add_values(a=1, b=2):
    return a + b
"""
    annotator = TypeAnnotator()
    refactored = annotator.refactor_source(code)

    assert "def add_values(a: int=1, b: int=2)" in refactored or "def add_values(a: int = 1, b: int = 2)" in refactored
    assert "from __future__ import annotations" in refactored
    # Must be valid syntax
    parsed = ast.parse(refactored)
    assert parsed is not None


def test_annotator_preserves_docstrings():
    code = """\"\"\"Module header docstring.\"\"\"

def greet(name="world"):
    \"\"\"Function docstring explaining greet.\"\"\"
    return f"Hello, {name}!"
"""
    annotator = TypeAnnotator()
    refactored = annotator.refactor_source(code)

    assert '"""Module header docstring."""' in refactored
    assert '"""Function docstring explaining greet."""' in refactored
    assert "def greet(name: str='world') -> str:" in refactored or 'def greet(name: str="world") -> str:' in refactored or "def greet(name: str = 'world')" in refactored


def test_annotator_class_methods():
    code = """class Calculator:
    def __init__(self, initial_val=0):
        self.val = initial_val

    def add(self, amount):
        self.val += amount
        return self.val
"""
    annotator = TypeAnnotator()
    refactored = annotator.refactor_source(code)

    assert "def __init__(self, initial_val: int=0) -> None:" in refactored or "def __init__(self, initial_val: int = 0) -> None:" in refactored
    assert "def add(self, amount: " in refactored
    parsed = ast.parse(refactored)
    assert parsed is not None


def test_annotator_already_typed_module():
    code = """from __future__ import annotations
from typing import Any

def already_typed(x: int) -> int:
    return x * 2
"""
    annotator = TypeAnnotator()
    refactored = annotator.refactor_source(code)
    # Shouldn't corrupt or add redundant imports
    assert "def already_typed(x: int) -> int:" in refactored


def test_annotator_varargs_and_kwargs():
    code = """def flexible_call(first, *args, **kwargs):
    return len(args)
"""
    annotator = TypeAnnotator()
    refactored = annotator.refactor_source(code)
    assert "*args: Any" in refactored
    assert "**kwargs: Any" in refactored


def test_annotator_node_langgraph_integration():
    initial_state = {
        "source_code": "def square(n=2):\n    return n * n\n",
        "target_path": "math_square.py",
    }
    result = annotator_node(initial_state)

    assert "current_code" in result
    assert "def square(n: int=2)" in result["current_code"] or "def square(n: int = 2)" in result["current_code"]
    assert "type_issues" in result
    assert "missing_branches" in result


def test_annotator_node_error_handling():
    broken_state = {
        "source_code": "def broken(: pass",
        "target_path": "broken.py",
    }
    result = annotator_node(broken_state)
    assert "error" in result
    assert "Annotator failed" in result["error"]
