"""Type Annotator node for LangGraph workflow.

Transforms untyped Python code into strictly typed Python compatible with MyPy Strict.
Adheres to SECURITY.md Standard #15 (AST Guardrails) and #17.
"""

from __future__ import annotations

import ast
from typing import Any, Dict, List, Optional, Set

from refactorer.inspector import ASTInspector
from refactorer.state import TypeIssue


class AnnotationTransformer(ast.NodeTransformer):
    """AST Transformer that attaches inferred type annotations to functions and methods."""

    def __init__(self, issues: List[TypeIssue]) -> None:
        super().__init__()
        self.issues_by_func: Dict[str, List[TypeIssue]] = {}
        for issue in issues:
            self.issues_by_func.setdefault(issue.function_name, []).append(issue)
        self.current_class: Optional[str] = None
        self.needed_typing_imports: Set[str] = set()

    def visit_ClassDef(self, node: ast.ClassDef) -> ast.AST:
        prev_class = self.current_class
        self.current_class = node.name
        self.generic_visit(node)
        self.current_class = prev_class
        return node

    def visit_FunctionDef(self, node: ast.FunctionDef) -> ast.AST:
        return self._annotate_function(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> ast.AST:
        return self._annotate_function(node)

    def _annotate_function(
        self, node: ast.FunctionDef | ast.AsyncFunctionDef
    ) -> ast.FunctionDef | ast.AsyncFunctionDef:
        qualified_name = f"{self.current_class}.{node.name}" if self.current_class else node.name
        func_issues = self.issues_by_func.get(qualified_name, [])

        issues_by_param = {iss.param_name: iss for iss in func_issues if iss.param_name}
        return_issue = next((iss for iss in func_issues if iss.param_name is None), None)

        # 1. Annotate positional / regular arguments
        for idx, arg in enumerate(node.args.posonlyargs + node.args.args):
            is_self_cls = bool(self.current_class) and idx == 0 and arg.arg in ("self", "cls")
            if not is_self_cls and arg.annotation is None:
                if arg.arg in issues_by_param:
                    suggested = issues_by_param[arg.arg].suggested_type
                    arg.annotation = self._parse_type_annotation(suggested)

        # 2. Annotate keyword-only arguments
        for arg in node.args.kwonlyargs:
            if arg.annotation is None and arg.arg in issues_by_param:
                suggested = issues_by_param[arg.arg].suggested_type
                arg.annotation = self._parse_type_annotation(suggested)

        # 3. Annotate varargs / kwargs
        if node.args.vararg and node.args.vararg.annotation is None:
            node.args.vararg.annotation = self._parse_type_annotation("Any")
        if node.args.kwarg and node.args.kwarg.annotation is None:
            node.args.kwarg.annotation = self._parse_type_annotation("Any")

        # 4. Annotate return type
        if node.returns is None:
            if node.name == "__init__":
                node.returns = ast.Constant(value=None)
            elif return_issue:
                node.returns = self._parse_type_annotation(return_issue.suggested_type)
            else:
                node.returns = self._parse_type_annotation("None")

        self.generic_visit(node)
        return node

    def _parse_type_annotation(self, type_str: str) -> ast.expr:
        # Register needed imports
        for token in ("Any", "Optional", "Union", "Callable", "Generator", "Dict", "List", "Tuple", "Set"):
            if token in type_str:
                self.needed_typing_imports.add(token)

        try:
            parsed = ast.parse(type_str, mode="eval")
            return parsed.body
        except Exception:
            self.needed_typing_imports.add("Any")
            return ast.Name(id="Any", ctx=ast.Load())


class TypeAnnotator:
    """Refactors Python source code by injecting strict MyPy-compatible type annotations."""

    def __init__(self) -> None:
        self.inspector = ASTInspector()

    def refactor_source(self, source_code: str, file_path: str = "module.py") -> str:
        """Annotate source code with strict type signatures.

        Args:
            source_code: Original Python source code.
            file_path: Relative or display file path.

        Returns:
            Refactored Python source code string with strict type annotations.
        """
        self.inspector.file_path = file_path
        issues, _, metadata = self.inspector.inspect_source(source_code)

        if not issues and metadata.get("has_typing_import"):
            return source_code

        tree = ast.parse(source_code, filename=file_path)
        transformer = AnnotationTransformer(issues)
        annotated_tree = transformer.visit(tree)
        ast.fix_missing_locations(annotated_tree)

        # Inject necessary imports at top if missing
        needed_imports = transformer.needed_typing_imports
        if "Any" not in needed_imports:
            needed_imports.add("Any")

        # Check existing imports in tree
        existing_typing_names: Set[str] = set()
        has_future_annotations = False

        for node in tree.body:
            if isinstance(node, ast.ImportFrom):
                if node.module == "__future__":
                    for alias in node.names:
                        if alias.name == "annotations":
                            has_future_annotations = True
                elif node.module == "typing":
                    for alias in node.names:
                        existing_typing_names.add(alias.name)

        missing_typing = needed_imports - existing_typing_names
        import_nodes: List[ast.AST] = []

        if not has_future_annotations:
            future_node = ast.ImportFrom(
                module="__future__",
                names=[ast.alias(name="annotations", asname=None)],
                level=0,
            )
            import_nodes.append(future_node)

        if missing_typing:
            typing_node = ast.ImportFrom(
                module="typing",
                names=[ast.alias(name=name, asname=None) for name in sorted(list(missing_typing))],
                level=0,
            )
            import_nodes.append(typing_node)

        if import_nodes:
            # Preserve module docstring if present
            insert_idx = 0
            if tree.body and isinstance(tree.body[0], ast.Expr) and isinstance(tree.body[0].value, ast.Constant):
                if isinstance(tree.body[0].value.value, str):
                    insert_idx = 1
            for imp in reversed(import_nodes):
                annotated_tree.body.insert(insert_idx, imp)

        ast.fix_missing_locations(annotated_tree)
        refactored = ast.unparse(annotated_tree)

        # Sanity verification: output must parse cleanly
        ast.parse(refactored, filename=file_path)
        return refactored


def annotator_node(state: Dict[str, Any]) -> Dict[str, Any]:
    """LangGraph node execution function for Type Annotator.

    Args:
        state: LangGraph state dictionary.

    Returns:
        Updated state dictionary with candidate refactored code.
    """
    source_code = state.get("current_code") or state.get("source_code", "")
    target_path = state.get("target_path", "module.py")

    annotator = TypeAnnotator()
    try:
        refactored = annotator.refactor_source(source_code, file_path=target_path)
        # Re-inspect to update remaining issues
        inspector = ASTInspector(file_path=target_path)
        remaining_issues, remaining_branches, _ = inspector.inspect_source(refactored)

        return {
            "current_code": refactored,
            "type_issues": [iss.model_dump() for iss in remaining_issues],
            "missing_branches": [br.model_dump() for br in remaining_branches],
        }
    except Exception as e:
        return {
            "error": f"Annotator failed: {str(e)}",
        }
