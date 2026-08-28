"""AST Inspector module for Python code analysis and type/branch discovery.

Extracts function signatures, docstrings, missing type annotations,
and execution branch paths using Python's abstract syntax tree (AST).
Adheres strictly to SECURITY.md Standard #3 (Path Traversal) and #15 (AST Guardrails).
"""

from __future__ import annotations

import ast
import os
from typing import Any, Dict, List, Optional, Set, Tuple

from refactorer.state import MissingCoverageBranch, TypeIssue


class InspectionError(Exception):
    """Raised when source code inspection fails."""


def safe_read_file(base_dir: str, relative_path: str) -> str:
    """Read a file securely guaranteeing path containment (CWE-22 defense).

    Args:
        base_dir: Base root directory.
        relative_path: User or caller provided path.

    Returns:
        Content of the file as string.

    Raises:
        ValueError: If path traversal outside base_dir is detected.
        FileNotFoundError: If target file does not exist.
    """
    base = os.path.abspath(base_dir)
    target = os.path.abspath(os.path.join(base, relative_path))
    if os.path.commonpath([base, target]) != base:
        raise ValueError(f"Path Traversal detected: {relative_path!r}")
    if not os.path.isfile(target):
        raise FileNotFoundError(f"File not found: {target}")
    with open(target, "r", encoding="utf-8") as f:
        return f.read()


class ASTBranchVisitor(ast.NodeVisitor):
    """Visitor that extracts all conditional and execution branches from a function."""

    def __init__(self, file_path: str, func_name: str) -> None:
        self.file_path = file_path
        self.func_name = func_name
        self.branches: List[MissingCoverageBranch] = []

    def visit_If(self, node: ast.If) -> None:
        cond_str = self._unparse_safe(node.test)
        # True branch
        self.branches.append(
            MissingCoverageBranch(
                file_path=self.file_path,
                function_name=self.func_name,
                branch_id=f"{self.func_name}:{node.lineno}:if_true",
                branch_type="if_true",
                line_number=node.lineno,
                condition_code=f"if {cond_str}",
                description=f"Branch taken when condition '{cond_str}' evaluates to True",
            )
        )
        # False / Else branch
        if node.orelse:
            self.branches.append(
                MissingCoverageBranch(
                    file_path=self.file_path,
                    function_name=self.func_name,
                    branch_id=f"{self.func_name}:{node.lineno}:if_false",
                    branch_type="if_false",
                    line_number=node.lineno,
                    condition_code=f"if not ({cond_str})",
                    description=f"Else/Elif branch taken when condition '{cond_str}' evaluates to False",
                )
            )
        else:
            self.branches.append(
                MissingCoverageBranch(
                    file_path=self.file_path,
                    function_name=self.func_name,
                    branch_id=f"{self.func_name}:{node.lineno}:if_fallthrough",
                    branch_type="if_fallthrough",
                    line_number=node.lineno,
                    condition_code=f"if not ({cond_str}) [fallthrough]",
                    description=f"Fallthrough when condition '{cond_str}' evaluates to False without explicit else",
                )
            )
        self.generic_visit(node)

    def visit_IfExp(self, node: ast.IfExp) -> None:
        cond_str = self._unparse_safe(node.test)
        self.branches.append(
            MissingCoverageBranch(
                file_path=self.file_path,
                function_name=self.func_name,
                branch_id=f"{self.func_name}:{node.lineno}:ternary_true",
                branch_type="ternary_true",
                line_number=node.lineno,
                condition_code=f"{cond_str} ? true",
                description=f"Ternary expression True branch: '{cond_str}'",
            )
        )
        self.branches.append(
            MissingCoverageBranch(
                file_path=self.file_path,
                function_name=self.func_name,
                branch_id=f"{self.func_name}:{node.lineno}:ternary_false",
                branch_type="ternary_false",
                line_number=node.lineno,
                condition_code=f"{cond_str} ? false",
                description=f"Ternary expression False branch: '{cond_str}'",
            )
        )
        self.generic_visit(node)

    def visit_Try(self, node: ast.Try) -> None:
        self.branches.append(
            MissingCoverageBranch(
                file_path=self.file_path,
                function_name=self.func_name,
                branch_id=f"{self.func_name}:{node.lineno}:try_body",
                branch_type="try_body",
                line_number=node.lineno,
                condition_code="try block",
                description="Normal execution through try body",
            )
        )
        for handler in node.handlers:
            exc_str = self._unparse_safe(handler.type) if handler.type else "Exception"
            self.branches.append(
                MissingCoverageBranch(
                    file_path=self.file_path,
                    function_name=self.func_name,
                    branch_id=f"{self.func_name}:{handler.lineno}:except_{exc_str}",
                    branch_type="try_except",
                    line_number=handler.lineno,
                    condition_code=f"except {exc_str}",
                    description=f"Exception handling branch catching '{exc_str}'",
                )
            )
        if node.orelse:
            self.branches.append(
                MissingCoverageBranch(
                    file_path=self.file_path,
                    function_name=self.func_name,
                    branch_id=f"{self.func_name}:{node.lineno}:try_else",
                    branch_type="try_else",
                    line_number=node.lineno,
                    condition_code="try ... else",
                    description="Execution through try else block when no exception is raised",
                )
            )
        self.generic_visit(node)

    def visit_For(self, node: ast.For) -> None:
        iter_str = self._unparse_safe(node.iter)
        self.branches.append(
            MissingCoverageBranch(
                file_path=self.file_path,
                function_name=self.func_name,
                branch_id=f"{self.func_name}:{node.lineno}:for_body",
                branch_type="for_body",
                line_number=node.lineno,
                condition_code=f"for in {iter_str}",
                description=f"Iteration branch over non-empty sequence: {iter_str}",
            )
        )
        self.branches.append(
            MissingCoverageBranch(
                file_path=self.file_path,
                function_name=self.func_name,
                branch_id=f"{self.func_name}:{node.lineno}:for_empty",
                branch_type="for_empty",
                line_number=node.lineno,
                condition_code=f"empty sequence {iter_str}",
                description=f"Zero-iteration edge case for empty sequence: {iter_str}",
            )
        )
        self.generic_visit(node)

    def visit_While(self, node: ast.While) -> None:
        cond_str = self._unparse_safe(node.test)
        self.branches.append(
            MissingCoverageBranch(
                file_path=self.file_path,
                function_name=self.func_name,
                branch_id=f"{self.func_name}:{node.lineno}:while_body",
                branch_type="while_body",
                line_number=node.lineno,
                condition_code=f"while {cond_str}",
                description=f"While loop body entry on True: {cond_str}",
            )
        )
        self.generic_visit(node)

    def visit_Match(self, node: ast.Match) -> None:
        for idx, case in enumerate(node.cases):
            pattern_str = self._unparse_safe(case.pattern)
            guard_str = f" if {self._unparse_safe(case.guard)}" if case.guard else ""
            self.branches.append(
                MissingCoverageBranch(
                    file_path=self.file_path,
                    function_name=self.func_name,
                    branch_id=f"{self.func_name}:{case.pattern.lineno}:case_{idx}",
                    branch_type="match_case",
                    line_number=case.pattern.lineno,
                    condition_code=f"case {pattern_str}{guard_str}",
                    description=f"Match case pattern '{pattern_str}' matched",
                )
            )
        self.generic_visit(node)

    def visit_Raise(self, node: ast.Raise) -> None:
        exc_str = self._unparse_safe(node.exc) if node.exc else "re-raise"
        self.branches.append(
            MissingCoverageBranch(
                file_path=self.file_path,
                function_name=self.func_name,
                branch_id=f"{self.func_name}:{node.lineno}:raise",
                branch_type="exception_raise",
                line_number=node.lineno,
                condition_code=f"raise {exc_str}",
                description=f"Explicit exception raising path: {exc_str}",
            )
        )
        self.generic_visit(node)

    def _unparse_safe(self, node: Optional[ast.AST]) -> str:
        if node is None:
            return ""
        try:
            return ast.unparse(node)
        except Exception:
            return "<expr>"


class ASTInspector:
    """Core AST inspector discovering function metadata, type issues, and branch paths."""

    def __init__(self, file_path: str = "module.py") -> None:
        self.file_path = file_path

    def inspect_source(
        self, source_code: str
    ) -> Tuple[List[TypeIssue], List[MissingCoverageBranch], Dict[str, Any]]:
        """Inspect Python source code string and return structured findings.

        Args:
            source_code: Python source code.

        Returns:
            Tuple of (type_issues, missing_branches, metadata_dict).

        Raises:
            InspectionError: When source code has syntax errors or cannot be parsed.
        """
        try:
            tree = ast.parse(source_code, filename=self.file_path)
        except SyntaxError as e:
            raise InspectionError(
                f"Syntax error parsing Python code at line {e.lineno}: {e.msg}"
            ) from e

        type_issues: List[TypeIssue] = []
        missing_branches: List[MissingCoverageBranch] = []
        functions_meta: List[Dict[str, Any]] = []
        classes_meta: List[Dict[str, Any]] = []

        for node in ast.iter_child_nodes(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                f_issues, f_branches, f_meta = self._inspect_function(
                    node, is_method=False, parent_class=None
                )
                type_issues.extend(f_issues)
                missing_branches.extend(f_branches)
                functions_meta.append(f_meta)
            elif isinstance(node, ast.ClassDef):
                c_meta, c_issues, c_branches = self._inspect_class(node)
                classes_meta.append(c_meta)
                type_issues.extend(c_issues)
                missing_branches.extend(c_branches)

        total_funcs = len(functions_meta) + sum(len(c["methods"]) for c in classes_meta)
        total_type_issues = len(type_issues)
        total_branches = len(missing_branches)

        metadata: Dict[str, Any] = {
            "file_path": self.file_path,
            "module_docstring": ast.get_docstring(tree),
            "total_functions": total_funcs,
            "total_classes": len(classes_meta),
            "classes": classes_meta,
            "top_level_functions": functions_meta,
            "total_type_issues": total_type_issues,
            "total_branches": total_branches,
            "has_typing_import": self._check_typing_import(tree),
        }

        return type_issues, missing_branches, metadata

    def inspect_file(
        self, file_path: str, base_dir: Optional[str] = None
    ) -> Tuple[List[TypeIssue], List[MissingCoverageBranch], Dict[str, Any]]:
        """Inspect a file on disk securely.

        Args:
            file_path: Absolute or relative file path.
            base_dir: Optional root sandbox directory for path traversal validation.

        Returns:
            Tuple of (type_issues, missing_branches, metadata_dict).
        """
        if base_dir:
            source = safe_read_file(base_dir, file_path)
            self.file_path = file_path
        else:
            abs_path = os.path.abspath(file_path)
            if not os.path.isfile(abs_path):
                raise FileNotFoundError(f"Source file not found: {abs_path}")
            with open(abs_path, "r", encoding="utf-8") as f:
                source = f.read()
            self.file_path = file_path

        return self.inspect_source(source)

    def _inspect_class(
        self, node: ast.ClassDef
    ) -> Tuple[Dict[str, Any], List[TypeIssue], List[MissingCoverageBranch]]:
        c_issues: List[TypeIssue] = []
        c_branches: List[MissingCoverageBranch] = []
        methods_meta: List[Dict[str, Any]] = []

        for item in node.body:
            if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                m_issues, m_branches, m_meta = self._inspect_function(
                    item, is_method=True, parent_class=node.name
                )
                c_issues.extend(m_issues)
                c_branches.extend(m_branches)
                methods_meta.append(m_meta)

        class_meta: Dict[str, Any] = {
            "name": node.name,
            "lineno": node.lineno,
            "docstring": ast.get_docstring(node),
            "bases": [ast.unparse(b) for b in node.bases],
            "methods": methods_meta,
        }
        return class_meta, c_issues, c_branches

    def _inspect_function(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
        is_method: bool = False,
        parent_class: Optional[str] = None,
    ) -> Tuple[List[TypeIssue], List[MissingCoverageBranch], Dict[str, Any]]:
        issues: List[TypeIssue] = []
        qualified_name = f"{parent_class}.{node.name}" if parent_class else node.name

        # 1. Parameter Inspection
        all_args = list(node.args.posonlyargs) + list(node.args.args) + list(node.args.kwonlyargs)
        defaults_map = self._extract_defaults(node.args)

        params_meta: List[Dict[str, Any]] = []
        for idx, arg in enumerate(all_args):
            is_self_cls = is_method and idx == 0 and arg.arg in ("self", "cls")
            annotation_str = ast.unparse(arg.annotation) if arg.annotation else None
            default_val = defaults_map.get(arg.arg)

            inferred_type = self._infer_param_type(arg.arg, default_val, node)

            params_meta.append(
                {
                    "name": arg.arg,
                    "annotation": annotation_str,
                    "default": default_val,
                    "inferred_type": inferred_type,
                    "is_self_cls": is_self_cls,
                }
            )

            if not is_self_cls and annotation_str is None:
                issues.append(
                    TypeIssue(
                        file_path=self.file_path,
                        function_name=qualified_name,
                        param_name=arg.arg,
                        issue_type="missing_param_type",
                        line_number=node.lineno,
                        suggested_type=inferred_type,
                        description=f"Parameter '{arg.arg}' in function '{qualified_name}' is missing type annotation. Inferred: {inferred_type}",
                    )
                )

        # Varargs (*args, **kwargs)
        if node.args.vararg and not node.args.vararg.annotation:
            issues.append(
                TypeIssue(
                    file_path=self.file_path,
                    function_name=qualified_name,
                    param_name=node.args.vararg.arg,
                    issue_type="missing_param_type",
                    line_number=node.lineno,
                    suggested_type="Any",
                    description=f"Vararg *{node.args.vararg.arg} in '{qualified_name}' missing type annotation.",
                )
            )
        if node.args.kwarg and not node.args.kwarg.annotation:
            issues.append(
                TypeIssue(
                    file_path=self.file_path,
                    function_name=qualified_name,
                    param_name=node.args.kwarg.arg,
                    issue_type="missing_param_type",
                    line_number=node.lineno,
                    suggested_type="Any",
                    description=f"Kwarg **{node.args.kwarg.arg} in '{qualified_name}' missing type annotation.",
                )
            )

        # 2. Return Type Inspection
        return_annot = ast.unparse(node.returns) if node.returns else None
        inferred_return = self._infer_return_type(node)

        if return_annot is None:
            # Special case: __init__ should return None
            if node.name == "__init__":
                suggested_ret = "None"
            else:
                suggested_ret = inferred_return

            issues.append(
                TypeIssue(
                    file_path=self.file_path,
                    function_name=qualified_name,
                    param_name=None,
                    issue_type="missing_return_type",
                    line_number=node.lineno,
                    suggested_type=suggested_ret,
                    description=f"Function '{qualified_name}' is missing a return type annotation. Inferred: {suggested_ret}",
                )
            )

        # 3. Branch Discovery
        branch_visitor = ASTBranchVisitor(self.file_path, qualified_name)
        for item in node.body:
            branch_visitor.visit(item)

        func_meta: Dict[str, Any] = {
            "name": node.name,
            "qualified_name": qualified_name,
            "lineno": node.lineno,
            "end_lineno": getattr(node, "end_lineno", node.lineno),
            "is_async": isinstance(node, ast.AsyncFunctionDef),
            "is_method": is_method,
            "parent_class": parent_class,
            "docstring": ast.get_docstring(node),
            "parameters": params_meta,
            "return_annotation": return_annot,
            "inferred_return": inferred_return,
            "branches_count": len(branch_visitor.branches),
            "is_fully_typed": len(issues) == 0,
        }

        return issues, branch_visitor.branches, func_meta

    def _extract_defaults(self, args_node: ast.arguments) -> Dict[str, str]:
        defaults: Dict[str, str] = {}
        # Positional defaults match the tail of args
        num_defaults = len(args_node.defaults)
        if num_defaults > 0:
            target_args = args_node.args[-num_defaults:]
            for arg, default in zip(target_args, args_node.defaults):
                try:
                    defaults[arg.arg] = ast.unparse(default)
                except Exception:
                    defaults[arg.arg] = "..."

        # Kwonly defaults match 1-to-1 with kwonlyargs
        for arg, def_node in zip(args_node.kwonlyargs, args_node.kw_defaults):
            if def_node is not None:
                try:
                    defaults[arg.arg] = ast.unparse(def_node)
                except Exception:
                    defaults[arg.arg] = "..."

        return defaults

    def _infer_param_type(
        self, param_name: str, default_val: Optional[str], func_node: ast.AST
    ) -> str:
        if default_val is not None:
            val = default_val.strip()
            if val in ("True", "False"):
                return "bool"
            if val == "None":
                return "Optional[Any]"
            if val.isdigit() or (val.startswith("-") and val[1:].isdigit()):
                return "int"
            try:
                float(val)
                return "float"
            except ValueError:
                pass
            if (val.startswith('"') and val.endswith('"')) or (
                val.startswith("'") and val.endswith("'")
            ):
                return "str"
            if val.startswith("[") and val.endswith("]"):
                return "list[Any]"
            if val.startswith("{") and val.endswith("}"):
                return "dict[str, Any]"
            if val.startswith("(") and val.endswith(")"):
                return "tuple[Any, ...]"

        # Body heuristic: check for isinstance or operations on param_name
        for node in ast.walk(func_node):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                if node.func.id == "isinstance" and len(node.args) >= 2:
                    first_arg = node.args[0]
                    if isinstance(first_arg, ast.Name) and first_arg.id == param_name:
                        try:
                            return ast.unparse(node.args[1])
                        except Exception:
                            pass
            elif isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
                if node.value.id == param_name:
                    if node.attr in (
                        "startswith",
                        "endswith",
                        "split",
                        "strip",
                        "lower",
                        "upper",
                        "replace",
                    ):
                        return "str"
                    if node.attr in ("append", "extend", "pop", "insert"):
                        return "list[Any]"
                    if node.attr in ("keys", "values", "items", "get"):
                        return "dict[str, Any]"
                    if node.attr in ("add", "discard", "difference", "intersection"):
                        return "set[Any]"
            elif isinstance(node, ast.Compare):
                if isinstance(node.left, ast.Name) and node.left.id == param_name:
                    return "float"
                for comp in node.comparators:
                    if isinstance(comp, ast.Name) and comp.id == param_name:
                        return "float"
            elif isinstance(node, ast.BinOp):
                if isinstance(node.left, ast.Name) and node.left.id == param_name:
                    return "float"
                if isinstance(node.right, ast.Name) and node.right.id == param_name:
                    return "float"

        return "Any"

    def _infer_return_type(self, func_node: ast.AST) -> str:
        returns: List[ast.Return] = []
        yields: List[ast.Yield | ast.YieldFrom] = []

        for node in ast.walk(func_node):
            if isinstance(node, ast.Return):
                returns.append(node)
            elif isinstance(node, (ast.Yield, ast.YieldFrom)):
                yields.append(node)

        if yields:
            return "Generator[Any, None, None]"

        if not returns:
            return "None"

        inferred_types: Set[str] = set()
        for ret in returns:
            if ret.value is None:
                inferred_types.add("None")
            elif isinstance(ret.value, ast.Constant):
                val = ret.value.value
                if isinstance(val, bool):
                    inferred_types.add("bool")
                elif isinstance(val, int):
                    inferred_types.add("int")
                elif isinstance(val, float):
                    inferred_types.add("float")
                elif isinstance(val, str):
                    inferred_types.add("str")
                elif isinstance(val, bytes):
                    inferred_types.add("bytes")
                elif val is None:
                    inferred_types.add("None")
                else:
                    inferred_types.add("Any")
            elif isinstance(ret.value, ast.List):
                inferred_types.add("list[Any]")
            elif isinstance(ret.value, ast.Dict):
                inferred_types.add("dict[str, Any]")
            elif isinstance(ret.value, ast.Set):
                inferred_types.add("set[Any]")
            elif isinstance(ret.value, ast.Tuple):
                inferred_types.add("tuple[Any, ...]")
            elif isinstance(ret.value, ast.JoinedStr):
                inferred_types.add("str")
            elif isinstance(ret.value, ast.Compare):
                inferred_types.add("bool")
            elif isinstance(ret.value, ast.BinOp):
                if isinstance(ret.value.op, (ast.Add, ast.Sub, ast.Mult, ast.Div, ast.FloorDiv)):
                    inferred_types.add("Union[int, float]")
                else:
                    inferred_types.add("Any")
            else:
                inferred_types.add("Any")

        if not inferred_types:
            return "None"
        if len(inferred_types) == 1:
            return next(iter(inferred_types))
        if "None" in inferred_types and len(inferred_types) == 2:
            other = (inferred_types - {"None"}).pop()
            return f"Optional[{other}]" if other != "Any" else "Optional[Any]"

        # Multiple types -> Union
        sorted_types = sorted(list(inferred_types))
        if "Any" in sorted_types:
            return "Any"
        return f"Union[{', '.join(sorted_types)}]"

    def _check_typing_import(self, tree: ast.AST) -> bool:
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name == "typing":
                        return True
            elif isinstance(node, ast.ImportFrom):
                if node.module in ("typing", "typing_extensions", "collections.abc"):
                    return True
        return False
