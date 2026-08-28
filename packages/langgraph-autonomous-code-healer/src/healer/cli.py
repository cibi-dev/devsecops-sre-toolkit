"""Command-line interface (CLI) for the Autonomous Code Healer."""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from pathlib import Path
from typing import Sequence

from healer import __version__
from healer.graph import run_healer
from healer.nodes.analyzer import parse_bandit_json

logger = logging.getLogger("healer.cli")


def build_parser() -> argparse.ArgumentParser:
    """Build the command-line argument parser."""
    parser = argparse.ArgumentParser(
        prog="healer",
        description="Autonomous Cyclic Multi-Agent Code Healer powered by LangGraph and Bandit SAST.",
    )
    parser.add_argument(
        "-f",
        "--file",
        type=str,
        help="Path to the target Python source file to heal.",
    )
    parser.add_argument(
        "-r",
        "--report",
        type=str,
        help="Optional path to a pre-generated Bandit JSON report file.",
    )
    parser.add_argument(
        "--max-iterations",
        type=int,
        default=3,
        help="Maximum healing loop iterations (default: 3).",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Simulate healing without modifying the source file on disk.",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=str,
        help="Optional output file path to write the healed code.",
    )
    parser.add_argument(
        "--db-path",
        type=str,
        default=":memory:",
        help="Path to SQLite checkpointer database (default: in-memory).",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable detailed debug logging.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Main CLI entry point."""
    parser = build_parser()
    args = parser.parse_args(argv)

    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )

    if not args.file:
        parser.print_help()
        return 1

    target_path = Path(args.file).resolve()
    if not target_path.exists():
        print(f"Error: Target file not found: {target_path}", file=sys.stderr)
        return 1

    if not target_path.is_file():
        print(f"Error: Target path is not a file: {target_path}", file=sys.stderr)
        return 1

    try:
        source_code = target_path.read_text(encoding="utf-8")
    except Exception as e:
        print(f"Error reading source file: {e}", file=sys.stderr)
        return 1

    bandit_report_dict = None
    if args.report:
        report_path = Path(args.report).resolve()
        if not report_path.exists():
            print(f"Error: Report file not found: {report_path}", file=sys.stderr)
            return 1
        try:
            raw_report = report_path.read_text(encoding="utf-8")
            report_obj = parse_bandit_json(raw_report)
            bandit_report_dict = report_obj.model_dump()
        except Exception as e:
            print(f"Error reading report file: {e}", file=sys.stderr)
            return 1

    print(f"🏥 Autonomous Code Healer v{__version__}")
    print(f"Auditing file: {target_path}")
    print(f"Max iterations: {args.max_iterations} | Mode: {'DRY RUN' if args.dry_run else 'LIVE REMEDIATION'}")
    print("-" * 60)

    try:
        result = run_healer(
            code=source_code,
            source_file=str(target_path),
            bandit_report=bandit_report_dict,
            max_iterations=args.max_iterations,
            db_path=args.db_path,
            dry_run=args.dry_run,
        )
    except Exception as e:
        print(f"Fatal error during graph execution: {e}", file=sys.stderr)
        return 1

    is_clean = result.get("is_clean", False)
    iterations = result.get("iterations", 0)
    diff = result.get("diff", "")
    healed_code = result.get("current_code", source_code)
    patches = result.get("patch_history", [])

    print(f"Iterations completed: {iterations}")
    print(f"Patches applied:     {len(patches)}")
    print(f"Final Status:        {'✅ CLEAN (0 findings)' if is_clean else '⚠️ REMAINING FINDINGS'}")

    if diff:
        print("\nUnified Diff:")
        print("=" * 60)
        print(diff)
        print("=" * 60)
    else:
        print("\nNo code changes were necessary.")

    if not args.dry_run and diff:
        out_path = Path(args.output).resolve() if args.output else target_path
        try:
            out_path.write_text(healed_code, encoding="utf-8")
            print(f"Successfully wrote remediated code to: {out_path}")
        except Exception as e:
            print(f"Error saving healed code to {out_path}: {e}", file=sys.stderr)
            return 1

    return 0 if is_clean else 2


if __name__ == "__main__":
    sys.exit(main())
