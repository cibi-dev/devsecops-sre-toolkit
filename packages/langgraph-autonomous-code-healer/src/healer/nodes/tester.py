"""Process sandboxing execution node with asyncio timeout for SAST and AST validation."""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any

from healer.nodes.analyzer import run_sast_scan, validate_python_ast
from healer.state import CodePatchState

logger = logging.getLogger(__name__)

# Hard execution timeout for process sandboxing (Guardrail #10 & #17)
EXECUTION_TIMEOUT_SECONDS: float = 30.0


async def evaluate_code_sandboxed_async(
    code: str,
    filename: str = "target.py",
    timeout_seconds: float = EXECUTION_TIMEOUT_SECONDS,
) -> dict[str, Any]:
    """Asynchronously evaluate code in an isolated sandbox with timeout and SAST scan."""
    start_time = time.perf_counter()

    try:
        async with asyncio.timeout(timeout_seconds):
            # 1. AST Validation
            is_valid_ast, ast_err, _ = validate_python_ast(code)
            if not is_valid_ast:
                duration = time.perf_counter() - start_time
                return {
                    "is_clean": False,
                    "test_passed": False,
                    "test_output": f"AST Syntax Check FAILED: {ast_err}",
                    "findings": [
                        {
                            "filename": filename,
                            "test_name": "ast_syntax_error",
                            "test_id": "SYNTAX_ERR",
                            "issue_severity": "HIGH",
                            "issue_confidence": "HIGH",
                            "issue_text": f"Syntax Error: {ast_err}",
                            "issue_cwe": {"id": 20, "link": "https://cwe.mitre.org/data/definitions/20.html"},
                            "line_number": 1,
                            "line_range": [1],
                            "code": code[:200],
                        }
                    ],
                    "bandit_report": {"results": [], "errors": [{"error": ast_err}]},
                    "duration_seconds": duration,
                }

            # 2. In-memory Bandit SAST scan
            # Run scan in thread executor to avoid blocking the async event loop
            loop = asyncio.get_running_loop()
            report = await loop.run_in_executor(None, run_sast_scan, code, filename)

            # Filter remaining actionable findings
            remaining_actionable = [f.model_dump() for f in report.actionable_findings]
            is_clean = len(remaining_actionable) == 0
            test_passed = is_clean and is_valid_ast

            duration = time.perf_counter() - start_time
            if is_clean:
                test_output = f"ALL CHECKS PASSED: 0 actionable SAST findings remaining in {filename} (elapsed: {duration:.3f}s)"
            else:
                test_output = f"SAST CHECKS FAILED: {len(remaining_actionable)} security findings remaining (elapsed: {duration:.3f}s)"

            return {
                "is_clean": is_clean,
                "test_passed": test_passed,
                "test_output": test_output,
                "findings": remaining_actionable,
                "bandit_report": report.model_dump(),
                "duration_seconds": duration,
            }

    except TimeoutError:
        duration = time.perf_counter() - start_time
        logger.error("Sandbox execution exceeded timeout (%ss)", timeout_seconds)
        return {
            "is_clean": False,
            "test_passed": False,
            "test_output": f"EXECUTION TIMEOUT: Sandbox test exceeded {timeout_seconds}s limit",
            "findings": [],
            "bandit_report": {"errors": [{"error": f"Timeout after {timeout_seconds}s"}]},
            "duration_seconds": duration,
        }


def evaluate_code_sandboxed_sync(
    code: str,
    filename: str = "target.py",
    timeout_seconds: float = EXECUTION_TIMEOUT_SECONDS,
) -> dict[str, Any]:
    """Synchronous fallback wrapper for sandbox evaluation."""
    start_time = time.perf_counter()

    # 1. AST Validation
    is_valid_ast, ast_err, _ = validate_python_ast(code)
    if not is_valid_ast:
        duration = time.perf_counter() - start_time
        return {
            "is_clean": False,
            "test_passed": False,
            "test_output": f"AST Syntax Check FAILED: {ast_err}",
            "findings": [
                {
                    "filename": filename,
                    "test_name": "ast_syntax_error",
                    "test_id": "SYNTAX_ERR",
                    "issue_severity": "HIGH",
                    "issue_confidence": "HIGH",
                    "issue_text": f"Syntax Error: {ast_err}",
                    "issue_cwe": {"id": 20, "link": "https://cwe.mitre.org/data/definitions/20.html"},
                    "line_number": 1,
                    "line_range": [1],
                    "code": code[:200],
                }
            ],
            "bandit_report": {"results": [], "errors": [{"error": ast_err}]},
            "duration_seconds": duration,
        }

    # 2. In-memory Bandit SAST scan
    report = run_sast_scan(code, filename)
    remaining_actionable = [f.model_dump() for f in report.actionable_findings]
    is_clean = len(remaining_actionable) == 0
    test_passed = is_clean and is_valid_ast

    duration = time.perf_counter() - start_time
    if is_clean:
        test_output = f"ALL CHECKS PASSED: 0 actionable SAST findings remaining in {filename} (elapsed: {duration:.3f}s)"
    else:
        test_output = f"SAST CHECKS FAILED: {len(remaining_actionable)} security findings remaining (elapsed: {duration:.3f}s)"

    return {
        "is_clean": is_clean,
        "test_passed": test_passed,
        "test_output": test_output,
        "findings": remaining_actionable,
        "bandit_report": report.model_dump(),
        "duration_seconds": duration,
    }


def tester_node(state: CodePatchState) -> dict[str, Any]:
    """LangGraph node: Evaluates the patched code in the sandbox."""
    current_code = state.get("current_code") or state.get("original_code", "")
    source_file = state.get("source_file", "target.py")

    result = evaluate_code_sandboxed_sync(current_code, filename=source_file)

    return {
        "is_clean": result["is_clean"],
        "test_passed": result["test_passed"],
        "test_output": result["test_output"],
        "findings": result["findings"],
        "bandit_report": result["bandit_report"],
        "iterations": 1,  # Increments operator.add counter in StateGraph
    }


async def tester_node_async(state: CodePatchState) -> dict[str, Any]:
    """LangGraph async node: Asynchronously evaluates the patched code in the sandbox."""
    current_code = state.get("current_code") or state.get("original_code", "")
    source_file = state.get("source_file", "target.py")

    result = await evaluate_code_sandboxed_async(current_code, filename=source_file)

    return {
        "is_clean": result["is_clean"],
        "test_passed": result["test_passed"],
        "test_output": result["test_output"],
        "findings": result["findings"],
        "bandit_report": result["bandit_report"],
        "iterations": 1,
    }
