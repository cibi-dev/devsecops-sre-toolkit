"""Sandbox Verifier node executing MyPy strict mode and Pytest coverage.

Adheres strictly to SECURITY.md:
- #3: Safe paths & CWE-22 traversal prevention.
- #4: Subprocess execution with list arguments, shell=False, and timeout.
- #8: Isolated temporary directories with guaranteed cleanup.
- #10 / #17: Bounded execution with asyncio.timeout(30.0).
- #13: Sanitized error handling.
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import subprocess
import sys
import tempfile
import time
from typing import Any, Dict, Optional

from refactorer.state import VerificationResult


class SandboxVerifier:
    """Isolated execution sandbox for validating type annotations and test coverage."""

    def __init__(self, timeout_seconds: float = 30.0) -> None:
        self.timeout_seconds = timeout_seconds

    def verify_code_and_tests(
        self,
        refactored_code: str,
        test_suite_code: str,
        strict_mypy: bool = True,
    ) -> VerificationResult:
        """Execute MyPy strict check and Pytest coverage suite in an isolated temp directory.

        Args:
            refactored_code: Candidate Python code.
            test_suite_code: Synthesized Pytest code.
            strict_mypy: Whether to enforce MyPy strict flags.

        Returns:
            VerificationResult containing execution status, coverage, and output diagnostics.
        """
        start_time = time.perf_counter()

        with tempfile.TemporaryDirectory(prefix="refactor_sandbox_") as sandbox_dir:
            target_file = os.path.join(sandbox_dir, "target_module.py")
            test_file = os.path.join(sandbox_dir, "test_target.py")
            cov_json_file = os.path.join(sandbox_dir, "coverage.json")

            with open(target_file, "w", encoding="utf-8") as f:
                f.write(refactored_code)

            with open(test_file, "w", encoding="utf-8") as f:
                f.write(test_suite_code)

            # 1. Run MyPy
            mypy_cmd = [
                sys.executable,
                "-m",
                "mypy",
                "--python-version",
                "3.10",
                "--ignore-missing-imports",
                "--no-error-summary",
            ]
            if strict_mypy:
                mypy_cmd.extend([
                    "--disallow-untyped-defs",
                    "--disallow-incomplete-defs",
                    "--check-untyped-defs",
                    "--no-implicit-optional",
                    "--warn-redundant-casts",
                    "--warn-unused-ignores",
                ])
            mypy_cmd.append(target_file)
            sandbox_env = {
                k: v
                for k, v in os.environ.items()
                if not k.startswith("COV_")
                and not k.startswith("COVERAGE_")
                and k != "PYTEST_CURRENT_TEST"
            }
            sandbox_env["PYTHONPATH"] = sandbox_dir

            mypy_passed = False
            mypy_output = ""
            try:
                mypy_res = subprocess.run(
                    mypy_cmd,
                    cwd=sandbox_dir,
                    env=sandbox_env,
                    capture_output=True,
                    text=True,
                    shell=False,
                    timeout=self.timeout_seconds,
                    check=False,
                )
                mypy_passed = mypy_res.returncode == 0
                mypy_output = (mypy_res.stdout + "\n" + mypy_res.stderr).strip()
            except subprocess.TimeoutExpired:
                mypy_output = f"MyPy verification timed out after {self.timeout_seconds}s"
            except Exception as e:
                mypy_output = f"MyPy execution error: {str(e)}"

            # 2. Run Pytest with coverage
            pytest_cmd = [
                sys.executable,
                "-m",
                "pytest",
                "-v",
                "--cov=target_module",
                f"--cov-report=json:{cov_json_file}",
                "--cov-report=term",
                test_file,
            ]

            pytest_passed = False
            pytest_output = ""
            coverage_pct = 0.0
            error_msg: Optional[str] = None

            try:
                pytest_res = subprocess.run(
                    pytest_cmd,
                    cwd=sandbox_dir,
                    env=sandbox_env,
                    capture_output=True,
                    text=True,
                    shell=False,
                    timeout=self.timeout_seconds,
                    check=False,
                )
                pytest_passed = pytest_res.returncode == 0
                pytest_output = (pytest_res.stdout + "\n" + pytest_res.stderr).strip()

                # Extract coverage from coverage.json or parse from stdout
                if os.path.isfile(cov_json_file):
                    try:
                        with open(cov_json_file, "r", encoding="utf-8") as jf:
                            cov_data = json.load(jf)
                            coverage_pct = float(
                                cov_data.get("totals", {}).get("percent_covered", 0.0)
                            )
                    except Exception:
                        coverage_pct = self._parse_coverage_stdout(pytest_output)
                else:
                    coverage_pct = self._parse_coverage_stdout(pytest_output)

            except subprocess.TimeoutExpired:
                pytest_output = f"Pytest verification timed out after {self.timeout_seconds}s"
                error_msg = "Verification timeout exceeded"
            except Exception as e:
                pytest_output = f"Pytest execution error: {str(e)}"
                error_msg = str(e)

            elapsed_ms = (time.perf_counter() - start_time) * 1000.0

            # Sanitize paths in outputs to avoid leaking local sandbox directories
            sanitized_mypy = mypy_output.replace(sandbox_dir, "/sandbox")
            sanitized_pytest = pytest_output.replace(sandbox_dir, "/sandbox")

            return VerificationResult(
                mypy_passed=mypy_passed,
                mypy_output=sanitized_mypy,
                pytest_passed=pytest_passed,
                pytest_output=sanitized_pytest,
                coverage_pct=round(coverage_pct, 2),
                execution_time_ms=round(elapsed_ms, 2),
                error_message=error_msg,
            )

    async def verify_async(
        self,
        refactored_code: str,
        test_suite_code: str,
        strict_mypy: bool = True,
    ) -> VerificationResult:
        """Asynchronous execution with asyncio.timeout bounding (Guardrail #10/#17)."""
        async with asyncio.timeout(self.timeout_seconds + 5.0):
            loop = asyncio.get_running_loop()
            return await loop.run_in_executor(
                None, self.verify_code_and_tests, refactored_code, test_suite_code, strict_mypy
            )

    def _parse_coverage_stdout(self, stdout: str) -> float:
        """Fallback regex parser for coverage terminal output."""
        match = re.search(r"TOTAL\s+\d+\s+\d+\s+(\d+)%", stdout)
        if match:
            return float(match.group(1))
        # Match target_module.py line
        match_line = re.search(r"target_module\.py\s+\d+\s+\d+\s+(\d+)%", stdout)
        if match_line:
            return float(match_line.group(1))
        return 0.0


def verifier_node(state: Dict[str, Any]) -> Dict[str, Any]:
    """LangGraph node execution function for Sandbox Verifier.

    Args:
        state: LangGraph state dictionary.

    Returns:
        Updated state dictionary with verification result and updated history.
    """
    current_code = state.get("current_code") or state.get("source_code", "")
    current_tests = state.get("current_tests", "")
    strict_mode = state.get("strict_mode", True)
    target_cov = state.get("target_coverage", 90.0)
    iterations = state.get("iterations", 0) + 1

    verifier = SandboxVerifier(timeout_seconds=30.0)
    res = verifier.verify_code_and_tests(
        refactored_code=current_code,
        test_suite_code=current_tests,
        strict_mypy=strict_mode,
    )

    history = list(state.get("verification_history", []))
    history.append(res.model_dump())

    # Success criteria: both mypy and pytest pass, and coverage meets target
    is_complete = res.mypy_passed and res.pytest_passed and (res.coverage_pct >= target_cov)

    return {
        "verification_history": history,
        "iterations": iterations,
        "is_complete": is_complete,
    }
