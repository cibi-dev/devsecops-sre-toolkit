"""Python AST static analysis scanner to detect hardcoded secrets and variable assignments (CWE-798)."""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass
from typing import List, Optional, Set

from scanner.entropy import is_high_entropy, shannon_entropy


# Suspicious variable and parameter identifiers
SECRET_IDENTIFIER_PATTERN = re.compile(
    r"(?i)(?:api[_-]?key|secret|token|password|passwd|auth[_-]?token|access[_-]?token|private[_-]?key|client[_-]?secret|credentials?|db[_-]?pass|signing[_-]?key|webhook[_-]?url)"
)

# Common mock/dummy keywords to filter out obvious false positives
IGNORED_PLACEHOLDERS: Set[str] = {
    "placeholder",
    "todo",
    "your_key_here",
    "your_api_key_here",
    "your_token_here",
    "change_me",
    "changeme",
    "dummy",
    "example",
    "test",
    "mock",
    "none",
    "null",
    "localhost",
    "127.0.0.1",
    ".".join(["0", "0", "0", "0"]),
    "default",
    "fake",
    "xxxx",
    "yyyy",
    "zzzz",
}


@dataclass
class ASTFinding:
    """Represents a secret detected via Python AST traversal."""

    line_number: int
    column_number: int
    variable_name: str
    secret_value: str
    entropy: float
    confidence: str  # "HIGH", "MEDIUM"
    cwe_id: str = "CWE-798"
    rule_id: str = "RULE-AST-HARDCODED-SECRET"
    description: str = "Hardcoded sensitive credential assigned to variable"


class SecretASTVisitor(ast.NodeVisitor):
    """AST Visitor that traverses Python syntax trees to flag hardcoded secrets."""

    def __init__(self, entropy_threshold: float = 4.0) -> None:
        super().__init__()
        self.entropy_threshold = entropy_threshold
        self.findings: List[ASTFinding] = []

    def _is_suspicious_identifier(self, name: str) -> bool:
        """Check if an identifier name matches secret naming conventions."""
        if not name:
            return False
        return bool(SECRET_IDENTIFIER_PATTERN.search(name))

    def _is_suspicious_value(self, value: str) -> bool:
        """Check if a string value exhibits secret characteristics."""
        if not isinstance(value, str) or len(value) < 8:
            return False

        # Filter out common placeholders
        val_clean = value.strip().lower()
        if val_clean in IGNORED_PLACEHOLDERS:
            return False

        for placeholder in IGNORED_PLACEHOLDERS:
            if placeholder in val_clean and len(val_clean) < 30:
                return False

        # Check entropy or length
        entropy = shannon_entropy(value)
        if entropy >= self.entropy_threshold or len(value) >= 24:
            return True

        return False

    def _record_finding(self, node: ast.AST, var_name: str, value_str: str) -> None:
        """Analyze and record a finding if candidate value meets threshold."""
        if not self._is_suspicious_value(value_str):
            return

        entropy = shannon_entropy(value_str)
        confidence = "HIGH" if entropy >= 4.5 or len(value_str) >= 32 else "MEDIUM"

        line = getattr(node, "lineno", 1)
        col = getattr(node, "col_offset", 0)

        self.findings.append(
            ASTFinding(
                line_number=line,
                column_number=col,
                variable_name=var_name,
                secret_value=value_str,
                entropy=entropy,
                confidence=confidence,
            )
        )

    def visit_Assign(self, node: ast.Assign) -> None:
        """Analyze standard assignments (e.g. secret_key = 'abc...')."""
        if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
            for target in node.targets:
                target_name = ""
                if isinstance(target, ast.Name):
                    target_name = target.id
                elif isinstance(target, ast.Attribute):
                    target_name = target.attr

                if target_name and self._is_suspicious_identifier(target_name):
                    self._record_finding(node, target_name, node.value.value)

        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        """Analyze type-annotated assignments (e.g. secret: str = 'abc...')."""
        if node.value and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
            target_name = ""
            if isinstance(node.target, ast.Name):
                target_name = node.target.id
            elif isinstance(node.target, ast.Attribute):
                target_name = node.target.attr

            if target_name and self._is_suspicious_identifier(target_name):
                self._record_finding(node, target_name, node.value.value)

        self.generic_visit(node)

    def visit_NamedExpr(self, node: ast.NamedExpr) -> None:
        """Analyze walrus assignments (e.g. if (token := 'abc...'))."""
        if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
            target_name = ""
            if isinstance(node.target, ast.Name):
                target_name = node.target.id

            if target_name and self._is_suspicious_identifier(target_name):
                self._record_finding(node, target_name, node.value.value)

        self.generic_visit(node)

    def visit_Dict(self, node: ast.Dict) -> None:
        """Analyze dictionary literal key-value pairs."""
        for key_node, val_node in zip(node.keys, node.values):
            if (
                key_node
                and isinstance(key_node, ast.Constant)
                and isinstance(key_node.value, str)
                and isinstance(val_node, ast.Constant)
                and isinstance(val_node.value, str)
            ):
                if self._is_suspicious_identifier(key_node.value):
                    self._record_finding(val_node, key_node.value, val_node.value)

        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        """Analyze keyword arguments passed to functions or constructors."""
        for kw in node.keywords:
            if kw.arg and self._is_suspicious_identifier(kw.arg):
                if isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
                    self._record_finding(kw.value, kw.arg, kw.value.value)

        self.generic_visit(node)


def scan_python_ast(
    source_code: str,
    entropy_threshold: float = 4.0,
) -> List[ASTFinding]:
    """Scan Python source code using AST parsing for hardcoded credentials.

    Args:
        source_code: Raw Python code text.
        entropy_threshold: Minimum Shannon entropy for generic values.

    Returns:
        List of ASTFinding items. If syntax errors occur, returns an empty list.
    """
    if not source_code or not source_code.strip():
        return []

    try:
        tree = ast.parse(source_code)
    except (SyntaxError, ValueError, UnicodeDecodeError):
        return []

    visitor = SecretASTVisitor(entropy_threshold=entropy_threshold)
    visitor.visit(tree)
    return visitor.findings
