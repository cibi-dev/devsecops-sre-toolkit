"""Unit tests for AST Inspector.

Tests signature parsing, type inference heuristics, and branch coverage discovery.
Adheres to SECURITY.md Standard #3 and #15.
"""

from __future__ import annotations

import os
import tempfile
import pytest

from refactorer.inspector import (
    ASTInspector,
    InspectionError,
    safe_read_file,
)


def test_inspect_simple_untyped_function():
    code = """def multiply(x, y):
    return x * y
"""
    inspector = ASTInspector(file_path="math_ops.py")
    issues, branches, meta = inspector.inspect_source(code)

    assert len(issues) == 3  # param x, param y, return
    param_names = {iss.param_name for iss in issues if iss.param_name}
    assert param_names == {"x", "y"}

    ret_issue = next(iss for iss in issues if iss.param_name is None)
    assert ret_issue.issue_type == "missing_return_type"
    assert "Union[int, float]" in ret_issue.suggested_type or "int" in ret_issue.suggested_type

    assert meta["total_functions"] == 1
    assert meta["total_classes"] == 0


def test_inspect_typed_function():
    code = """def add_numbers(a: int, b: int) -> int:
    return a + b
"""
    inspector = ASTInspector()
    issues, branches, meta = inspector.inspect_source(code)
    assert len(issues) == 0
    assert meta["top_level_functions"][0]["is_fully_typed"] is True


def test_inspect_default_param_type_inference():
    code = """def configure(timeout=30, ratio=1.5, debug=False, name="default", tags=[], config={}):
    pass
"""
    inspector = ASTInspector()
    issues, _, meta = inspector.inspect_source(code)

    issues_by_name = {iss.param_name: iss.suggested_type for iss in issues if iss.param_name}
    assert issues_by_name["timeout"] == "int"
    assert issues_by_name["ratio"] == "float"
    assert issues_by_name["debug"] == "bool"
    assert issues_by_name["name"] == "str"
    assert issues_by_name["tags"] == "list[Any]"
    assert issues_by_name["config"] == "dict[str, Any]"


def test_inspect_heuristics_from_body():
    code = """def process_text(raw):
    trimmed = raw.strip()
    return trimmed.lower()
"""
    inspector = ASTInspector()
    issues, _, _ = inspector.inspect_source(code)
    param_issue = next(iss for iss in issues if iss.param_name == "raw")
    assert param_issue.suggested_type == "str"


def test_inspect_return_type_variations():
    # 1. None return
    code_none = """def log_event(msg: str) -> None:
    print(msg)
"""
    _, _, meta_none = ASTInspector().inspect_source(code_none)
    assert meta_none["top_level_functions"][0]["inferred_return"] == "None"

    # 2. Optional return
    code_opt = """def find_user(user_id: int):
    if user_id > 0:
        return "Alice"
    return None
"""
    issues_opt, _, _ = ASTInspector().inspect_source(code_opt)
    ret_issue = next(iss for iss in issues_opt if iss.param_name is None)
    assert "Optional[str]" in ret_issue.suggested_type

    # 3. Generator return
    code_gen = """def number_stream(limit: int):
    for i in range(limit):
        yield i
"""
    issues_gen, _, _ = ASTInspector().inspect_source(code_gen)
    ret_gen = next(iss for iss in issues_gen if iss.param_name is None)
    assert "Generator" in ret_gen.suggested_type


def test_inspect_classes_and_methods():
    code = """class DataProcessor:
    \"\"\"Docstring for class.\"\"\"
    def __init__(self, data_source):
        self.data_source = data_source

    @classmethod
    def create(cls, path):
        return cls(path)

    async def fetch_async(self, query):
        return [query]
"""
    inspector = ASTInspector()
    issues, branches, meta = inspector.inspect_source(code)

    assert meta["total_classes"] == 1
    cls_info = meta["classes"][0]
    assert cls_info["name"] == "DataProcessor"
    assert len(cls_info["methods"]) == 3

    # Ensure self and cls were skipped from param issues
    param_issues = [iss.param_name for iss in issues if iss.param_name]
    assert "self" not in param_issues
    assert "cls" not in param_issues
    assert "data_source" in param_issues
    assert "query" in param_issues

    # __init__ return annotation should be None
    init_ret_issue = next(
        (iss for iss in issues if iss.function_name == "DataProcessor.__init__" and iss.param_name is None),
        None,
    )
    assert init_ret_issue is not None
    assert init_ret_issue.suggested_type == "None"


def test_inspect_branch_discovery():
    code = """def complex_logic(val, items):
    if val > 100:
        res = "high"
    elif val > 50:
        res = "medium"
    else:
        res = "low"

    short = "yes" if val > 0 else "no"

    try:
        parsed = int(val)
    except ValueError:
        parsed = 0
    else:
        parsed += 1

    for x in items:
        print(x)

    while val < 10:
        val += 1

    if val == -999:
        raise ValueError("Invalid flag")

    return res
"""
    inspector = ASTInspector()
    _, branches, meta = inspector.inspect_source(code)

    branch_types = [b.branch_type for b in branches]
    assert "if_true" in branch_types
    assert "if_false" in branch_types
    assert "ternary_true" in branch_types
    assert "ternary_false" in branch_types
    assert "try_body" in branch_types
    assert "try_except" in branch_types
    assert "try_else" in branch_types
    assert "for_body" in branch_types
    assert "for_empty" in branch_types
    assert "while_body" in branch_types
    assert "exception_raise" in branch_types
    assert len(branches) >= 10


def test_inspect_match_case_branches():
    code = """def handle_command(cmd):
    match cmd:
        case "start":
            return 1
        case "stop":
            return 0
        case _:
            return -1
"""
    inspector = ASTInspector()
    _, branches, _ = inspector.inspect_source(code)
    match_branches = [b for b in branches if b.branch_type == "match_case"]
    assert len(match_branches) == 3


def test_inspect_syntax_error_handling():
    invalid_code = "def broken_syntax(x, : return x"
    inspector = ASTInspector()
    with pytest.raises(InspectionError) as exc_info:
        inspector.inspect_source(invalid_code)
    assert "Syntax error" in str(exc_info.value)


def test_safe_read_file_path_traversal():
    with tempfile.TemporaryDirectory() as temp_dir:
        test_file = os.path.join(temp_dir, "test.py")
        with open(test_file, "w", encoding="utf-8") as f:
            f.write("def foo(): pass")

        # Legitimate read
        content = safe_read_file(temp_dir, "test.py")
        assert content == "def foo(): pass"

        # Traversal attempt
        with pytest.raises(ValueError) as exc_info:
            safe_read_file(temp_dir, "../../etc/passwd")
        assert "Path Traversal detected" in str(exc_info.value)

        # Non-existent file
        with pytest.raises(FileNotFoundError):
            safe_read_file(temp_dir, "nonexistent.py")


def test_inspect_file_on_disk():
    with tempfile.TemporaryDirectory() as temp_dir:
        test_file = os.path.join(temp_dir, "module_sample.py")
        with open(test_file, "w", encoding="utf-8") as f:
            f.write("def square(n): return n * n\n")

        inspector = ASTInspector()
        issues, branches, meta = inspector.inspect_file(test_file, base_dir=temp_dir)
        assert len(issues) == 2  # param n + return
        assert meta["total_functions"] == 1
