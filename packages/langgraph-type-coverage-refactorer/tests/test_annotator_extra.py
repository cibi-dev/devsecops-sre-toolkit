"""Additional tests for Type Annotator to achieve 95%+ coverage."""

from __future__ import annotations

import ast
import pytest

from refactorer.nodes.annotator import AnnotationTransformer, TypeAnnotator
from refactorer.state import TypeIssue


def test_annotator_async_function():
    code = """async def fetch_async(url="http://example.com", timeout=30):
    return url
"""
    annotator = TypeAnnotator()
    refactored = annotator.refactor_source(code)
    assert "async def fetch_async(url: str" in refactored
    assert "timeout: int" in refactored
    ast.parse(refactored)


def test_annotator_kwonly_and_varargs():
    code = """def complex_sig(a=1, *args, kw1="test", **kwargs):
    return len(args) + len(kwargs)
"""
    annotator = TypeAnnotator()
    refactored = annotator.refactor_source(code)
    assert "*args: Any" in refactored
    assert "**kwargs: Any" in refactored
    assert "kw1: str" in refactored
    ast.parse(refactored)


def test_annotator_transformer_parse_fallback():
    issues = [
        TypeIssue(
            file_path="mod.py",
            function_name="bad_annot",
            param_name="x",
            issue_type="missing_param_type",
            line_number=1,
            suggested_type="Invalid<Type>[Syntax",
            description="Broken syntax type",
        )
    ]
    transformer = AnnotationTransformer(issues)
    parsed_node = transformer._parse_type_annotation("Invalid<Type>[Syntax")
    assert isinstance(parsed_node, ast.Name)
    assert parsed_node.id == "Any"


def test_annotator_complex_types_import_injection():
    code = """def handle_callbacks(cb, gen, mapping):
    return 1
"""
    issues = [
        TypeIssue(
            file_path="mod.py",
            function_name="handle_callbacks",
            param_name="cb",
            issue_type="missing_param_type",
            line_number=1,
            suggested_type="Callable[[int], str]",
            description="",
        ),
        TypeIssue(
            file_path="mod.py",
            function_name="handle_callbacks",
            param_name="gen",
            issue_type="missing_param_type",
            line_number=1,
            suggested_type="Generator[int, None, None]",
            description="",
        ),
        TypeIssue(
            file_path="mod.py",
            function_name="handle_callbacks",
            param_name="mapping",
            issue_type="missing_param_type",
            line_number=1,
            suggested_type="Dict[str, Tuple[int, str]]",
            description="",
        ),
    ]
    tree = ast.parse(code)
    transformer = AnnotationTransformer(issues)
    transformer.visit(tree)
    assert "Callable" in transformer.needed_typing_imports
    assert "Generator" in transformer.needed_typing_imports
    assert "Dict" in transformer.needed_typing_imports
    assert "Tuple" in transformer.needed_typing_imports
