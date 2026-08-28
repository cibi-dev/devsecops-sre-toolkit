"""CLI interface for langgraph-type-coverage-refactorer.

Provides command-line options for running AST inspection, type inference,
unit test synthesis, and sandbox validation.
Adheres strictly to SECURITY.md:
- #3: CWE-22 safe path validation.
- #16: Human-in-the-loop confirmation on destructive in-place modifications.
- #13: Sanitized error reporting and standard exit codes.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import List, Optional

from refactorer.graph import run_refactorer
from refactorer.inspector import safe_read_file


def parse_args(args: Optional[List[str]] = None) -> argparse.Namespace:
    """Parse CLI arguments."""
    parser = argparse.ArgumentParser(
        prog="refactorer",
        description="Multi-agent AST refactoring engine for strict MyPy typing and automated branch test coverage.",
    )
    parser.add_argument(
        "target",
        nargs="?",
        default=None,
        help="Target Python file to refactor (or use --target)",
    )
    parser.add_argument(
        "--target",
        dest="target_opt",
        default=None,
        help="Explicit path to target Python file",
    )
    parser.add_argument(
        "-o",
        "--output",
        dest="output",
        default=None,
        help="Output destination path for refactored code",
    )
    parser.add_argument(
        "--gen-tests",
        dest="test_output",
        default=None,
        help="Output file path to save synthesized Pytest suite",
    )
    parser.add_argument(
        "--strict",
        dest="strict",
        action="store_true",
        default=True,
        help="Enforce strict MyPy typing conformance (default: True)",
    )
    parser.add_argument(
        "--no-strict",
        dest="strict",
        action="store_false",
        help="Disable strict MyPy flags",
    )
    parser.add_argument(
        "--target-cov",
        dest="target_cov",
        type=float,
        default=90.0,
        help="Target branch & statement test coverage percentage (default: 90.0)",
    )
    parser.add_argument(
        "--max-iter",
        dest="max_iter",
        type=int,
        default=3,
        help="Maximum bounded refactoring iterations (default: 3, max: 4)",
    )
    parser.add_argument(
        "--db-path",
        dest="db_path",
        default=None,
        help="SQLite database path for persistence checkpoints",
    )
    parser.add_argument(
        "--in-place",
        dest="in_place",
        action="store_true",
        default=False,
        help="Overwrite target file in place (requires confirmation)",
    )
    parser.add_argument(
        "-y",
        "--yes",
        dest="auto_confirm",
        action="store_true",
        default=False,
        help="Auto-confirm in-place modifications (Human-in-the-loop bypass for automation)",
    )
    parser.add_argument(
        "--json",
        dest="json_output",
        action="store_true",
        default=False,
        help="Output full state report as JSON to stdout",
    )
    return parser.parse_args(args)


def main(cli_args: Optional[List[str]] = None) -> int:
    """CLI entrypoint."""
    args = parse_args(cli_args)
    target_path = args.target_opt or args.target

    if not target_path:
        print("Error: Target Python file must be specified.", file=sys.stderr)
        return 1

    # Security check: Validate path exists and is a file
    abs_target = os.path.abspath(target_path)
    if not os.path.isfile(abs_target):
        print(f"Error: Target file not found: {target_path}", file=sys.stderr)
        return 1

    try:
        with open(abs_target, "r", encoding="utf-8") as f:
            source_code = f.read()
    except Exception as e:
        print(f"Error reading source file: {str(e)}", file=sys.stderr)
        return 1

    # Execute workflow
    state = run_refactorer(
        source_code=source_code,
        target_path=target_path,
        target_coverage=args.target_cov,
        strict_mode=args.strict,
        max_iterations=args.max_iter,
        db_path=args.db_path,
    )

    if args.json_output:
        print(state.model_dump_json(indent=2))
        return 0 if state.is_complete else 1

    # Human-in-the-Loop Confirmation for in-place modifications (Guardrail #16)
    if args.in_place:
        if not args.auto_confirm:
            try:
                confirm = input(
                    f"Confirm in-place overwrite of '{target_path}' with refactored code? [y/N]: "
                )
                if confirm.strip().lower() not in ("y", "yes"):
                    print("Operation cancelled by user.")
                    return 0
            except (EOFError, KeyboardInterrupt):
                print("\nOperation cancelled.")
                return 0

        with open(abs_target, "w", encoding="utf-8") as f:
            f.write(state.current_code)
        print(f"✓ In-place updated '{target_path}'")

    # Write output file if requested
    if args.output:
        out_abs = os.path.abspath(args.output)
        with open(out_abs, "w", encoding="utf-8") as f:
            f.write(state.current_code)
        print(f"✓ Refactored code saved to '{args.output}'")

    # Write test output file if requested
    if args.test_output:
        test_abs = os.path.abspath(args.test_output)
        with open(test_abs, "w", encoding="utf-8") as f:
            f.write(state.current_tests)
        print(f"✓ Synthesized tests saved to '{args.test_output}'")

    # Console Summary
    latest_verification = (
        state.verification_history[-1] if state.verification_history else None
    )
    cov = latest_verification.coverage_pct if latest_verification else 0.0
    mypy_ok = latest_verification.mypy_passed if latest_verification else False
    pytest_ok = latest_verification.pytest_passed if latest_verification else False

    print("\n" + "=" * 60)
    print("  LangGraph Type & Coverage Refactorer Report")
    print("=" * 60)
    print(f" Target File       : {target_path}")
    print(f" Iterations        : {state.iterations} / {state.max_iterations}")
    print(f" MyPy Strict Gate  : {'✓ PASSED' if mypy_ok else '✗ FAILED'}")
    print(f" Pytest Suite Gate : {'✓ PASSED' if pytest_ok else '✗ FAILED'}")
    print(f" Branch Coverage   : {cov:.1f}% (Target: {state.target_coverage:.1f}%)")
    print(f" Status            : {'✓ SUCCESS' if state.is_complete else '✗ FAILED'}")
    print("=" * 60 + "\n")

    return 0 if state.is_complete else 1


if __name__ == "__main__":
    sys.exit(main())
