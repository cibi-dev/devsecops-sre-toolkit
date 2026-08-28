"""Unit tests for Python AST static credential scanner (CWE-798)."""

from scanner.ast_scanner import (
    SecretASTVisitor,
    scan_python_ast,
)


def test_ast_scan_assign():
    """Detects hardcoded secrets in direct variable assignments."""
    code = """
import os

api_key = "mock_secret_key_long_value_1234567890"
def get_client():
    return api_key
"""
    findings = scan_python_ast(code)
    assert len(findings) == 1
    assert findings[0].variable_name == "api_key"
    assert findings[0].cwe_id == "CWE-798"
    assert findings[0].line_number == 4


def test_ast_scan_annotated_assign():
    """Detects secrets in type-annotated assignments."""
    code = """
secret_token: str = "mock_secret_key_long_value_1234567890"
"""
    findings = scan_python_ast(code)
    assert len(findings) == 1
    assert findings[0].variable_name == "secret_token"
    assert findings[0].line_number == 2


def test_ast_scan_attribute_assign():
    """Detects secrets assigned to class attributes or self attributes."""
    code = """
class Config:
    def __init__(self):
        self.api_key = "mock_secret_key_long_value_1234567890"
        self.secret_token: str = "mock_secret_key_long_value_1234567890"
"""
    findings = scan_python_ast(code)
    assert len(findings) >= 1
    var_names = [f.variable_name for f in findings]
    assert "api_key" in var_names


def test_ast_scan_walrus_assign():
    """Detects secrets in named expression (walrus operator) assignments."""
    code = """
if (db_password := "mock_db_password_long_value_1234567890"):
    connect(db_password)
"""
    findings = scan_python_ast(code)
    assert len(findings) == 1
    assert findings[0].variable_name == "db_password"


def test_ast_scan_dict_literals():
    """Detects secrets stored inside dictionary literals."""
    code = """
config = {
    "host": "localhost",
    "api_key": "mock_secret_key_long_value_1234567890",
    "port": 8080
}
"""
    findings = scan_python_ast(code)
    assert len(findings) == 1
    assert findings[0].variable_name == "api_key"


def test_ast_scan_function_call_kwargs():
    """Detects secrets passed as hardcoded keyword arguments to functions."""
    code = """
client = SDKClient(
    timeout=30,
    api_key="mock_secret_key_long_value_1234567890"
)
"""
    findings = scan_python_ast(code)
    assert len(findings) == 1
    assert findings[0].variable_name == "api_key"


def test_ast_scan_ignores_placeholders():
    """Ignores common mock and placeholder tokens to reduce false positives."""
    code = """
api_key = "YOUR_API_KEY_HERE"
secret = "placeholder"
token = "TODO"
password = "dummy"
"""
    findings = scan_python_ast(code)
    assert len(findings) == 0


def test_ast_scan_ignores_short_and_non_string_values():
    """Ignores very short strings or non-string values."""
    code = """
api_key = "123"
secret = 987654321
token = None
"""
    findings = scan_python_ast(code)
    assert len(findings) == 0


def test_ast_visitor_edge_cases():
    """Direct visitor method unit tests for full branch coverage."""
    visitor = SecretASTVisitor()
    assert not visitor._is_suspicious_identifier("")
    assert not visitor._is_suspicious_value(123)  # type: ignore
    assert not visitor._is_suspicious_value("abc")
    assert not visitor._is_suspicious_value("placeholder_token_short")


def test_ast_scan_handles_syntax_errors_gracefully():
    """Broken Python code does not crash the scanner and returns empty list."""
    broken_code = "def broken_syntax(:"
    findings = scan_python_ast(broken_code)
    assert findings == []


def test_ast_scan_empty_input():
    """Empty or None input returns empty list."""
    assert scan_python_ast("") == []
    assert scan_python_ast("   \n\t  ") == []
