"""Command Line Interface (CLI) for container-secret-scanner."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import List, Optional

from scanner import __version__
from scanner.engine import ScanOptions, ScanSummary, SecretScannerEngine
from scanner.reporters.console import render_console_report
from scanner.reporters.sarif import export_sarif, generate_sarif_dict


def build_parser() -> argparse.ArgumentParser:
    """Construct the command line argument parser."""
    parser = argparse.ArgumentParser(
        prog="container-secret-scanner",
        description="High-performance static DevSecOps secret scanner for git repos, directories, and OCI container tar layers.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "-v", "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )

    subparsers = parser.add_subparsers(dest="command", help="Scan command to execute")

    # Common parent parser for shared flags
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument(
        "--format", "-f",
        choices=["console", "sarif", "json"],
        default="console",
        help="Report output format",
    )
    common.add_argument(
        "--output", "-o",
        type=str,
        default=None,
        help="Save report to specified output path",
    )
    common.add_argument(
        "--entropy", "-e",
        type=float,
        default=4.5,
        help="Minimum Shannon entropy threshold (bits)",
    )
    common.add_argument(
        "--workers", "-w",
        type=int,
        default=4,
        help="Concurrency worker threads (bounded between 1 and 32)",
    )
    common.add_argument(
        "--fail-on-secrets",
        action="store_true",
        default=False,
        help="Exit with code 1 if any secrets are detected",
    )
    common.add_argument(
        "--no-ast",
        action="store_true",
        default=False,
        help="Disable Python AST static assignment scanner",
    )
    common.add_argument(
        "--no-color",
        action="store_true",
        default=False,
        help="Disable ANSI colors in console output",
    )
    common.add_argument(
        "--quiet", "-q",
        action="store_true",
        default=False,
        help="Suppress terminal console output",
    )

    # 1. scan-dir
    p_dir = subparsers.add_parser(
        "scan-dir",
        parents=[common],
        help="Scan a local filesystem directory or file",
    )
    p_dir.add_argument(
        "path",
        type=str,
        help="Directory or file path to scan",
    )

    # 2. scan-tar
    p_tar = subparsers.add_parser(
        "scan-tar",
        parents=[common],
        help="Scan an OCI container layer or TAR archive safely in-memory",
    )
    p_tar.add_argument(
        "path",
        type=str,
        help="Path to .tar or .tar.gz container archive",
    )

    # 3. scan-git
    p_git = subparsers.add_parser(
        "scan-git",
        parents=[common],
        help="Scan tracked files in a Git repository",
    )
    p_git.add_argument(
        "path",
        type=str,
        default=".",
        nargs="?",
        help="Path to Git repository root (default: current directory)",
    )

    return parser


def run_scan(args: argparse.Namespace) -> int:
    """Execute scanning based on parsed arguments."""
    options = ScanOptions(
        max_workers=args.workers,
        entropy_threshold=args.entropy,
        enable_ast_scan=not args.no_ast,
    )
    engine = SecretScannerEngine(options=options)

    summary: Optional[ScanSummary] = None

    if args.command == "scan-dir":
        summary = engine.scan_directory(args.path)
    elif args.command == "scan-tar":
        summary = engine.scan_tar(args.path)
    elif args.command == "scan-git":
        summary = engine.scan_git(args.path)
    else:
        sys.stderr.write("Error: No command specified. Use --help for usage.\n")
        return 2

    # Render reports
    use_color = not args.no_color and sys.stdout.isatty() and "NO_COLOR" not in os.environ

    if args.format == "sarif":
        report_text = export_sarif(summary, output_path=args.output)
        if not args.quiet:
            print(report_text)
    elif args.format == "json":
        sarif_dict = generate_sarif_dict(summary)
        report_text = json.dumps(sarif_dict, indent=2)
        if args.output:
            Path(args.output).write_text(report_text, encoding="utf-8")
        if not args.quiet:
            print(report_text)
    else:  # console
        report_text = render_console_report(summary, use_color=use_color)
        if args.output:
            # Write plain text without color codes if saving to file
            plain_report = render_console_report(summary, use_color=False)
            Path(args.output).write_text(plain_report, encoding="utf-8")
        if not args.quiet:
            print(report_text)

    if args.fail_on_secrets and summary.has_findings:
        return 1

    return 0


def main(argv: Optional[List[str]] = None) -> int:
    """Main CLI entrypoint."""
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.command:
        parser.print_help()
        return 0

    try:
        return run_scan(args)
    except Exception as e:
        sys.stderr.write(f"Fatal error during execution: {e}\n")
        return 1


if __name__ == "__main__":
    sys.exit(main())
