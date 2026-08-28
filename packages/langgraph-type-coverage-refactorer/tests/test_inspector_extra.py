"""Additional tests for AST Inspector to achieve 95%+ coverage."""

from __future__ import annotations

import ast
import pytest

from refactorer.inspector import ASTBranchVisitor, ASTInspector


def test_inspector_unparse_safe_fallback():
    visitor = ASTBranchVisitor("test.py", "func")
    assert visitor._unparse_safe(None) == ""
    # Passing a non-AST object to trigger exception handling
    assert visitor._unparse_safe("not_an_ast"  # type: ignore
    ) == "<expr>"


def test_inspector_all_param_defaults_types():
    code = """def all_defaults(
    a=1,
    b=2.5,
    c="str",
    d=True,
    e=[1, 2],
    f={"k": "v"},
    g=(1, 2),
    h=None,
    *,
    kw1=100,
    kw2="kw_val",
    kw3=None
):
    pass
"""
    inspector = ASTInspector()
    issues, _, _ = inspector.inspect_source(code)
    types_map = {iss.param_name: iss.suggested_type for iss in issues if iss.param_name}
    assert types_map["a"] == "int"
    assert types_map["b"] == "float"
    assert types_map["c"] == "str"
    assert types_map["d"] == "bool"
    assert types_map["e"] == "list[Any]"
    assert types_map["f"] == "dict[str, Any]"
    assert types_map["g"] == "tuple[Any, ...]"
    assert types_map["h"] == "Optional[Any]"
    assert types_map["kw1"] == "int"
    assert types_map["kw2"] == "str"


def test_inspector_all_body_heuristics():
    code = """def body_heuristics(a, b, c, d, e):
    if isinstance(a, str):
        a_len = len(a)
    b.append(10)
    k = c.keys()
    d.add("item")
    e.split(",")
"""
    inspector = ASTInspector()
    issues, _, _ = inspector.inspect_source(code)
    types_map = {iss.param_name: iss.suggested_type for iss in issues if iss.param_name}
    assert types_map["a"] == "str"
    assert types_map["b"] == "list[Any]"
    assert types_map["c"] == "dict[str, Any]"
    assert types_map["d"] == "set[Any]"
    assert types_map["e"] == "str"


def test_inspector_all_return_types():
    # Constant types: float, bytes, bool
    code1 = """def ret_bytes(x):
    if x > 0:
        return b"data"
    elif x == 0:
        return True
    return 3.14
"""
    issues, _, _ = ASTInspector().inspect_source(code1)
    ret_issue = next(iss for iss in issues if iss.param_name is None)
    assert "Union" in ret_issue.suggested_type

    # Containers: list, dict, set, tuple, string f-string, compare, binop
    code2 = """def ret_containers(mode, a, b):
    if mode == 1:
        return [1, 2]
    elif mode == 2:
        return {"a": 1}
    elif mode == 3:
        return {1, 2}
    elif mode == 4:
        return (1, 2)
    elif mode == 5:
        return f"mode_{mode}"
    elif mode == 6:
        return a == b
    return a / b
"""
    issues2, _, _ = ASTInspector().inspect_source(code2)
    ret_issue2 = next(iss for iss in issues2 if iss.param_name is None)
    assert "Union" in ret_issue2.suggested_type or "Any" in ret_issue2.suggested_type


def test_inspector_typing_import_variants():
    inspector = ASTInspector()
    # typing
    _, _, meta1 = inspector.inspect_source("import typing\ndef f(): pass")
    assert meta1["has_typing_import"] is True

    # collections.abc
    _, _, meta2 = inspector.inspect_source("from collections.abc import Sequence\ndef f(): pass")
    assert meta2["has_typing_import"] is True

    # typing_extensions
    _, _, meta3 = inspector.inspect_source("from typing_extensions import TypedDict\ndef f(): pass")
    assert meta3["has_typing_import"] is True


def test_inspector_async_methods_in_class():
    code = """class AsyncWorker:
    async def process_task(self, task_id):
        if task_id < 0:
            raise ValueError("Negative task_id")
        return {"task": task_id}
"""
    issues, branches, meta = ASTInspector().inspect_source(code)
    assert meta["classes"][0]["methods"][0]["is_async"] is True
    assert len(branches) >= 2
