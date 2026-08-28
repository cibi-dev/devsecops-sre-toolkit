"""Unit tests for healer.nodes.analyzer AST validation and Bandit SAST parsing."""

from __future__ import annotations

import json
from healer.nodes.analyzer import (
    BANDIT_TO_CWE,
    analyzer_node,
    find_ast_nodes_at_lines,
    parse_bandit_json,
    run_sast_scan,
    validate_python_ast,
)
from healer.state import CodePatchState


def test_validate_python_ast_valid():
    """Test AST validation with syntactically valid Python code."""
    valid_code = "def add(a: int, b: int) -> int:\n    return a + b\n"
    is_valid, err_msg, tree = validate_python_ast(valid_code)
    assert is_valid is True
    assert err_msg is None
    assert tree is not None


def test_validate_python_ast_invalid():
    """Test AST validation with syntax errors."""
    broken_code = "def broken(:\n    pass"
    is_valid, err_msg, tree = validate_python_ast(broken_code)
    assert is_valid is False
    assert err_msg is not None
    assert "SyntaxError" in err_msg
    assert tree is None


def test_find_ast_nodes_at_lines():
    """Test AST node localization by line numbers."""
    code = "x = 10\ny = 20\nz = x + y\n"
    _, _, tree = validate_python_ast(code)
    assert tree is not None
    matched = find_ast_nodes_at_lines(tree, {2})
    assert len(matched) > 0


def test_parse_bandit_json_valid_string():
    """Test parsing Bandit JSON output string."""
    raw_json = json.dumps(
        {
            "generated_at": "2026-08-27T12:00:00Z",
            "results": [
                {
                    "filename": "vuln.py",
                    "test_name": "subprocess_popen_with_shell_equals_true",
                    "test_id": "B602",
                    "issue_severity": "HIGH",
                    "issue_confidence": "HIGH",
                    "issue_text": "subprocess call with shell=True",
                    "issue_cwe": {"id": 78, "link": "https://cwe.mitre.org/data/definitions/78.html"},
                    "line_number": 5,
                    "line_range": [5],
                    "code": "subprocess.call('cmd', shell=True)",
                }
            ],
            "metrics": {"_totals": {"loc": 20}},
        }
    )

    report = parse_bandit_json(raw_json)
    assert len(report.results) == 1
    assert report.results[0].test_id == "B602"
    assert report.results[0].cwe_id == 78


def test_parse_bandit_json_missing_cwe_catalog_enrichment():
    """Test enrichment of missing CWE from catalog."""
    raw_dict = {
        "results": [
            {
                "filename": "test.py",
                "test_name": "try_except_pass",
                "test_id": "B110",
                "issue_severity": "LOW",
                "issue_confidence": "HIGH",
                "issue_text": "Try, Except, Pass detected.",
                "line_number": 3,
                "code": "except: pass",
            }
        ]
    }

    report = parse_bandit_json(raw_dict)
    assert len(report.results) == 1
    assert report.results[0].cwe_id == 703  # Enriched from BANDIT_TO_CWE


def test_parse_bandit_json_invalid_string():
    """Test parsing invalid JSON string returns report with error entry."""
    report = parse_bandit_json("INVALID_NON_JSON_DATA {{{")
    assert len(report.errors) == 1
    assert len(report.results) == 0


def test_run_sast_scan_clean_code():
    """Test SAST scan on clean code produces 0 actionable findings."""
    clean_code = "def multiply(x: int, y: int) -> int:\n    return x * y\n"
    report = run_sast_scan(clean_code, filename="clean.py")
    assert len(report.actionable_findings) == 0


def test_run_sast_scan_syntax_error():
    """Test SAST scan on code with syntax error returns error."""
    broken_code = "def error_func(:"
    report = run_sast_scan(broken_code, filename="broken.py")
    assert len(report.errors) > 0
    assert len(report.results) == 0


def test_run_sast_scan_vulnerable_code():
    """Test SAST scan on vulnerable code detects security issues."""
    vuln_code = (
        "import subprocess\n"
        "def run_cmd(user_input):\n"
        "    subprocess.call(user_input, shell=True)\n"
    )
    report = run_sast_scan(vuln_code, filename="vuln.py")
    assert len(report.results) > 0
    test_ids = {f.test_id for f in report.results}
    assert "B602" in test_ids or "B404" in test_ids


def test_analyzer_node_with_clean_code():
    """Test analyzer_node execution on clean code sets is_clean to True."""
    state: CodePatchState = {
        "source_file": "clean.py",
        "original_code": "x = 42\n",
        "current_code": "x = 42\n",
        "bandit_report": {},
        "findings": [],
        "proposed_patch": "x = 42\n",
        "patch_history": [],
        "test_output": "",
        "test_passed": False,
        "is_clean": False,
        "iterations": 0,
        "max_iterations": 3,
        "error_message": None,
        "dry_run": False,
        "diff": "",
    }

    result = analyzer_node(state)
    assert result["is_clean"] is True
    assert result["error_message"] is None


def test_analyzer_node_with_syntax_error():
    """Test analyzer_node on invalid code returns AST syntax finding."""
    state: CodePatchState = {
        "source_file": "bad.py",
        "original_code": "def func(:\n",
        "current_code": "def func(:\n",
        "bandit_report": {},
        "findings": [],
        "proposed_patch": "def func(:\n",
        "patch_history": [],
        "test_output": "",
        "test_passed": False,
        "is_clean": False,
        "iterations": 0,
        "max_iterations": 3,
        "error_message": None,
        "dry_run": False,
        "diff": "",
    }

    result = analyzer_node(state)
    assert result["is_clean"] is False
    assert len(result["findings"]) == 1
    assert result["findings"][0]["test_id"] == "SYNTAX_ERR"
