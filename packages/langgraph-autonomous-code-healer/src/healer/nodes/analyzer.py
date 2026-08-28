"""AST-based SAST Analyzer Node for Bandit vulnerability reports and Python AST inspection."""

from __future__ import annotations

import ast
import json
import logging
import os
import tempfile
from typing import Any

from bandit.core import config as b_config
from bandit.core import manager as b_manager

from healer.state import BanditFinding, BanditReport, CodePatchState

logger = logging.getLogger(__name__)

# Fallback mapping for Bandit test IDs to CWE classifications
BANDIT_TO_CWE: dict[str, int] = {
    "B101": 703,  # assert used
    "B102": 78,   # exec used
    "B103": 732,  # set_bad_file_permissions
    "B104": 1188, # hardcoded_bind_all_interfaces
    "B105": 798,  # hardcoded_password_string
    "B106": 798,  # hardcoded_password_funcarg
    "B107": 798,  # hardcoded_password_default
    "B108": 22,   # hardcoded_tmp_directory
    "B110": 703,  # try_except_pass
    "B112": 703,  # try_except_continue
    "B201": 20,   # flask_debug_true
    "B301": 502,  # pickle
    "B302": 502,  # marshal
    "B303": 327,  # md5
    "B304": 327,  # ciphers (des, rc4)
    "B305": 327,  # cipher_modes (ecb)
    "B306": 377,  # mktemp_q
    "B307": 78,   # eval
    "B324": 327,  # hashlib_new_insecure_functions
    "B325": 377,  # tempnam
    "B403": 502,  # import_pickle
    "B404": 78,   # import_subprocess
    "B405": 611,  # import_xml_etree
    "B506": 502,  # yaml_load
    "B601": 78,   # paramiko_calls
    "B602": 78,   # subprocess_popen_with_shell_equals_true
    "B603": 78,   # subprocess_without_shell_equals_true
    "B604": 78,   # any_other_function_with_shell_equals_true
    "B605": 78,   # start_process_with_a_shell
    "B606": 78,   # start_process_with_no_shell
    "B607": 78,   # start_process_with_partial_path
    "B608": 89,   # hardcoded_sql_expressions
}


def validate_python_ast(code: str) -> tuple[bool, str | None, ast.AST | None]:
    """Validate that the given Python code string is syntactically valid AST.
    
    Returns:
        tuple (is_valid, error_message, ast_tree)
    """
    try:
        tree = ast.parse(code)
        return True, None, tree
    except SyntaxError as e:
        msg = f"SyntaxError at line {e.lineno}, col {e.offset}: {e.msg}"
        return False, msg, None
    except Exception as e:
        return False, f"AST parse error: {e}", None


def parse_bandit_json(raw_data: str | dict[str, Any]) -> BanditReport:
    """Parse raw Bandit JSON string or dictionary into a validated BanditReport."""
    if isinstance(raw_data, str):
        try:
            data = json.loads(raw_data)
        except Exception as e:
            return BanditReport(
                generated_at="",
                errors=[{"error": f"Invalid JSON format: {e}"}],
                results=[],
                metrics={},
            )
    else:
        data = raw_data

    raw_results = data.get("results", [])
    parsed_findings: list[BanditFinding] = []

    for item in raw_results:
        try:
            test_id = str(item.get("test_id", ""))
            issue_cwe = item.get("issue_cwe")

            # Enrich missing CWE if available in catalog
            if issue_cwe is None and test_id in BANDIT_TO_CWE:
                issue_cwe = {
                    "id": BANDIT_TO_CWE[test_id],
                    "link": f"https://cwe.mitre.org/data/definitions/{BANDIT_TO_CWE[test_id]}.html",
                }

            finding = BanditFinding(
                filename=str(item.get("filename", "unknown.py")),
                test_name=str(item.get("test_name", "unknown_test")),
                test_id=test_id,
                issue_severity=str(item.get("issue_severity", "LOW")).upper(),
                issue_confidence=str(item.get("issue_confidence", "HIGH")).upper(),
                issue_text=str(item.get("issue_text", "")),
                issue_cwe=issue_cwe,
                line_number=int(item.get("line_number", 1)),
                line_range=list(item.get("line_range", [item.get("line_number", 1)])),
                code=str(item.get("code", "")),
                col_offset=item.get("col_offset"),
                end_col_offset=item.get("end_col_offset"),
                more_info=item.get("more_info"),
            )
            parsed_findings.append(finding)
        except Exception as e:
            logger.warning("Skipping unparseable bandit finding: %s", e)

    return BanditReport(
        generated_at=str(data.get("generated_at", "")),
        errors=list(data.get("errors", [])),
        results=parsed_findings,
        metrics=dict(data.get("metrics", {})),
    )


def run_sast_scan(code: str, filename: str = "target.py") -> BanditReport:
    """Execute in-memory Bandit SAST scan safely using Python BanditManager API."""
    is_valid, err_msg, _ = validate_python_ast(code)
    if not is_valid:
        return BanditReport(
            generated_at="",
            errors=[{"error": f"Cannot run SAST on invalid Python syntax: {err_msg}"}],
            results=[],
            metrics={},
        )

    # Use secure temporary file with guaranteed cleanup (Guardrail #8)
    fd, temp_path = tempfile.mkstemp(suffix=".py", prefix="healer_scan_")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(code)

        conf = b_config.BanditConfig()
        mgr = b_manager.BanditManager(conf, "file")
        mgr.discover_files([temp_path])
        mgr.run_tests()

        issues = mgr.get_issue_list()
        raw_results: list[dict[str, Any]] = []

        for issue in issues:
            d = issue.as_dict()
            # Normalize filename back to target filename for consistency
            d["filename"] = filename
            raw_results.append(d)

        return parse_bandit_json({"results": raw_results})
    finally:
        try:
            if os.path.exists(temp_path):
                os.unlink(temp_path)
        except OSError:
            pass


def find_ast_nodes_at_lines(tree: ast.AST, lines: set[int]) -> list[ast.AST]:
    """Find AST nodes that span the specified line numbers."""
    matched: list[ast.AST] = []
    for node in ast.walk(tree):
        lineno = getattr(node, "lineno", None)
        if lineno is not None and lineno in lines:
            matched.append(node)
    return matched


def analyzer_node(state: CodePatchState) -> dict[str, Any]:
    """LangGraph node: Analyzes code with AST parser and Bandit SAST."""
    code_to_analyze = state.get("current_code") or state.get("original_code", "")
    source_file = state.get("source_file", "target.py")

    # Step 1: AST validation
    is_valid_ast, ast_err, _ = validate_python_ast(code_to_analyze)
    if not is_valid_ast:
        return {
            "is_clean": False,
            "test_passed": False,
            "error_message": ast_err,
            "findings": [
                {
                    "filename": source_file,
                    "test_name": "ast_syntax_error",
                    "test_id": "SYNTAX_ERR",
                    "issue_severity": "HIGH",
                    "issue_confidence": "HIGH",
                    "issue_text": f"Syntax Error: {ast_err}",
                    "issue_cwe": {"id": 20, "link": "https://cwe.mitre.org/data/definitions/20.html"},
                    "line_number": 1,
                    "line_range": [1],
                    "code": code_to_analyze[:200],
                }
            ],
            "bandit_report": {"results": [], "errors": [{"error": ast_err}]},
        }

    # Step 2: SAST scan
    report = run_sast_scan(code_to_analyze, filename=source_file)
    actionable = [f.model_dump() for f in report.results if f.is_actionable or f.test_id in BANDIT_TO_CWE]

    # Clean if 0 actionable findings
    is_clean = len(actionable) == 0

    return {
        "bandit_report": report.model_dump(),
        "findings": actionable,
        "is_clean": is_clean,
        "error_message": None if is_clean else f"Found {len(actionable)} security findings",
    }
