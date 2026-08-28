"""Unit and integration tests for LangGraph StateGraph workflow.

Tests node chaining, conditional routing, SQLite checkpointing, and recursion limits.
Adheres to SECURITY.md Standard #15 and #17.
"""

from __future__ import annotations

import os
import tempfile
import pytest
from langgraph.graph import END

from refactorer.graph import (
    create_refactorer_graph,
    evaluator_router,
    inspector_node,
    run_refactorer,
    run_refactorer_async,
)


def test_inspector_node():
    state = {
        "source_code": "def subtract(a, b):\n    return a - b\n",
        "target_path": "math_sub.py",
    }
    result = inspector_node(state)
    assert "current_code" in result
    assert len(result["type_issues"]) >= 2
    assert "missing_branches" in result


def test_inspector_node_syntax_error():
    state = {
        "source_code": "def broken(:",
        "target_path": "broken.py",
    }
    result = inspector_node(state)
    assert "error" in result
    assert result["is_complete"] is False


def test_evaluator_router_conditions():
    # 1. Error present -> END
    assert evaluator_router({"error": "Failed", "is_complete": False}) == END

    # 2. Complete -> END
    assert evaluator_router({"is_complete": True, "iterations": 1, "max_iterations": 3}) == END

    # 3. Max iterations reached -> END
    assert evaluator_router({"is_complete": False, "iterations": 3, "max_iterations": 3}) == END

    # 4. Incomplete & within bounds -> loop to annotator
    assert evaluator_router({"is_complete": False, "iterations": 1, "max_iterations": 3}) == "annotator"


def test_create_refactorer_graph_compilation():
    graph_app = create_refactorer_graph()
    assert graph_app is not None


def test_create_refactorer_graph_with_custom_sqlite_db():
    with tempfile.TemporaryDirectory() as temp_dir:
        db_file = os.path.join(temp_dir, "checkpoints.db")
        graph_app = create_refactorer_graph(db_path=db_file)
        assert graph_app is not None
        assert os.path.isfile(db_file)


def test_run_refactorer_end_to_end_sync():
    code = """def calc_discount(price, discount=0.1):
    if price <= 0:
        raise ValueError("Invalid price")
    return price * (1.0 - discount)
"""
    final_state = run_refactorer(
        source_code=code,
        target_path="calc.py",
        target_coverage=90.0,
        strict_mode=True,
        max_iterations=2,
    )

    assert final_state.target_path == "calc.py"
    assert "def calc_discount(" in final_state.current_code
    assert final_state.iterations >= 1
    assert len(final_state.verification_history) >= 1
    assert final_state.error is None


@pytest.mark.asyncio
async def test_run_refactorer_end_to_end_async():
    code = """def is_even(n=2):
    return n % 2 == 0
"""
    final_state = await run_refactorer_async(
        source_code=code,
        target_path="even_checker.py",
        target_coverage=90.0,
        strict_mode=True,
        max_iterations=2,
    )

    assert final_state.target_path == "even_checker.py"
    assert final_state.iterations >= 1
    assert len(final_state.verification_history) >= 1


def test_run_refactorer_max_iterations_bound():
    code = """def complex_function(a, b, c):
    if a > 0:
        return b
    return c
"""
    # Max iterations is hard-bounded to <= 4
    final_state = run_refactorer(
        source_code=code,
        target_path="complex.py",
        max_iterations=1,
    )
    assert final_state.iterations == 1
