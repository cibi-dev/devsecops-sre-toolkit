"""Command Line Interface (CLI) for linux-cis-hardener suite."""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import List, Optional

from cis.backup_manager import BackupManager
from cis.remediator import CISRemediator
from cis.report import ReportGenerator
from cis.rules import get_all_rules
from cis.scanner import CISScanner, ScanReport

__version__ = "0.1.0"


def build_parser() -> argparse.ArgumentParser:
    """Build command line argument parser with all subcommands."""
    parser = argparse.ArgumentParser(
        prog="cis-hardener",
        description="Enterprise Linux Security Auditing & Remediation Suite (CIS Benchmark Level 1)",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")

    subparsers = parser.add_subparsers(dest="command", help="Operational mode")

    # --- AUDIT SUBCOMMAND ---
    audit_parser = subparsers.add_parser("audit", help="Audit host or chroot against CIS Level 1 baseline")
    audit_parser.add_argument("--root-prefix", default="", help="Target root directory prefix (chroot / sandbox)")
    audit_parser.add_argument(
        "--format",
        choices=["console", "json", "markdown"],
        default="console",
        help="Output report format (default: console)",
    )
    audit_parser.add_argument("--output", "-o", help="Save report to specified file path")
    audit_parser.add_argument("--rule", action="append", help="Filter by rule ID (can be repeated)")
    audit_parser.add_argument("--section", action="append", help="Filter by CIS section (can be repeated)")
    audit_parser.add_argument(
        "--fail-under",
        type=float,
        default=0.0,
        help="Exit with non-zero code if score is below this threshold (0-100)",
    )
    audit_parser.add_argument("--no-color", action="store_true", help="Disable ANSI color formatting")

    # --- REMEDIATE SUBCOMMAND ---
    rem_parser = subparsers.add_parser("remediate", help="Remediate non-compliant configurations idempotently")
    rem_parser.add_argument("--dry-run", action="store_true", help="Simulate changes without modifying filesystem")
    rem_parser.add_argument("--root-prefix", default="", help="Target root directory prefix")
    rem_parser.add_argument("--rule", action="append", help="Filter by rule ID to remediate")
    rem_parser.add_argument("--section", action="append", help="Filter by section to remediate")
    rem_parser.add_argument("--backup-dir", help="Custom backup directory location")
    rem_parser.add_argument(
        "--no-root-check",
        action="store_true",
        help="Bypass root euid verification (sandbox/test only)",
    )
    rem_parser.add_argument("--format", choices=["console", "json"], default="console", help="Output format")
    rem_parser.add_argument("--no-color", action="store_true", help="Disable ANSI color formatting")

    # --- ROLLBACK SUBCOMMAND ---
    rb_parser = subparsers.add_parser("rollback", help="Revert changes made during a previous remediation session")
    rb_parser.add_argument("--session-id", help="Specific backup session ID to rollback (default: latest)")
    rb_parser.add_argument("--backup-dir", help="Custom backup directory location")
    rb_parser.add_argument("--root-prefix", default="", help="Target root directory prefix")
    rb_parser.add_argument("--list", action="store_true", help="List all available backup sessions")
    rb_parser.add_argument(
        "--no-root-check",
        action="store_true",
        help="Bypass root euid verification (sandbox/test only)",
    )

    # --- REPORT SUBCOMMAND ---
    rep_parser = subparsers.add_parser("report", help="Render or convert an existing JSON scan report")
    rep_parser.add_argument("--input", "-i", required=True, help="Input JSON scan report path")
    rep_parser.add_argument(
        "--format",
        choices=["console", "json", "markdown"],
        default="console",
        help="Target output format",
    )
    rep_parser.add_argument("--output", "-o", help="Write formatted report to destination file")
    rep_parser.add_argument("--no-color", action="store_true", help="Disable ANSI color formatting")

    # --- RULES SUBCOMMAND ---
    rules_parser = subparsers.add_parser("rules", help="List all registered CIS Benchmark Level 1 rules")
    rules_parser.add_argument("--section", help="Filter rules by section")
    rules_parser.add_argument("--json", action="store_true", help="Output rule catalogue as JSON")

    return parser


def handle_audit(args: argparse.Namespace) -> int:
    """Execute audit command."""
    scanner = CISScanner(root_prefix=args.root_prefix)
    report = scanner.audit(rule_ids=args.rule, sections=args.section)

    if args.format == "json":
        output_text = ReportGenerator.to_json(report)
    elif args.format == "markdown":
        output_text = ReportGenerator.to_markdown(report)
    else:
        output_text = ReportGenerator.to_console(report, color=not args.no_color)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(output_text)
        print(f"Report saved to {args.output}")
    else:
        print(output_text)

    if report.score < args.fail_under:
        print(
            f"ERROR: CIS Score {report.score}% is below threshold {args.fail_under}%",
            file=sys.stderr,
        )
        return 1
    return 0


def handle_remediate(args: argparse.Namespace) -> int:
    """Execute remediation command."""
    backup_mgr = BackupManager(backup_dir=args.backup_dir, root_prefix=args.root_prefix)

    try:
        remediator = CISRemediator(
            backup_manager=backup_mgr,
            enforce_root=not args.no_root_check,
            root_prefix=args.root_prefix,
        )
    except PermissionError as e:
        print(f"SECURITY ERROR: {e}", file=sys.stderr)
        return 1

    summary = remediator.remediate(
        rule_ids=args.rule,
        sections=args.section,
        dry_run=args.dry_run,
    )

    if args.format == "json":
        print(summary.model_dump_json(indent=2))
    else:
        print(ReportGenerator.remediation_to_console(summary, color=not args.no_color))

    return 1 if summary.failed_count > 0 else 0


def handle_rollback(args: argparse.Namespace) -> int:
    """Execute rollback command."""
    # CWE-250/269 Privilege verification
    if not args.no_root_check and not args.root_prefix and os.geteuid() != 0:
        print(
            "SECURITY ERROR: Rollback requires root privileges (os.geteuid() == 0).",
            file=sys.stderr,
        )
        return 1

    backup_mgr = BackupManager(backup_dir=args.backup_dir, root_prefix=args.root_prefix)

    if args.list:
        sessions = backup_mgr.list_sessions()
        if not sessions:
            print("No backup sessions found.")
            return 0
        print("Available Backup Sessions:")
        for s in sessions:
            print(f" • Session: {s['session_id']} | Date: {s['created_at']} | Files: {s['files_backed_up']}")
        return 0

    result = backup_mgr.rollback_session(session_id=args.session_id)
    if result["success"]:
        print(f"SUCCESS: Rollback complete for session '{result['session_id']}'.")
        print(f"Restored {result['restored_count']}/{result['total_count']} files:")
        for f in result["restored_files"]:
            print(f"  - {f}")
        return 0
    else:
        print(f"FAILURE: Rollback encountered errors in session '{result['session_id']}':", file=sys.stderr)
        for err in result["errors"]:
            print(f"  - {err}", file=sys.stderr)
        return 1


def handle_report(args: argparse.Namespace) -> int:
    """Execute report conversion command."""
    try:
        with open(args.input, "r", encoding="utf-8") as f:
            data = json.load(f)
        report = ScanReport.model_validate(data)
    except Exception as e:
        print(f"ERROR reading report file: {e}", file=sys.stderr)
        return 1

    if args.format == "json":
        output_text = ReportGenerator.to_json(report)
    elif args.format == "markdown":
        output_text = ReportGenerator.to_markdown(report)
    else:
        output_text = ReportGenerator.to_console(report, color=not args.no_color)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(output_text)
        print(f"Formatted report saved to {args.output}")
    else:
        print(output_text)
    return 0


def handle_rules(args: argparse.Namespace) -> int:
    """List registered rules."""
    rules = get_all_rules()
    if args.section:
        sec_lower = args.section.lower()
        rules = [r for r in rules if sec_lower in r.section.lower()]

    if args.json:
        catalog = [
            {
                "rule_id": r.rule_id,
                "title": r.title,
                "section": r.section,
                "severity": r.severity.value,
                "description": r.description,
                "remediation_supported": r.remediation_supported,
            }
            for r in rules
        ]
        print(json.dumps(catalog, indent=2))
        return 0

    print(f"Registered CIS Benchmark Level 1 Rules ({len(rules)} rules):")
    for r in rules:
        print(f" • [{r.rule_id}] ({r.severity.value}) {r.title} [{r.section}]")
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    """Main CLI entrypoint."""
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.command:
        parser.print_help()
        return 0

    if args.command == "audit":
        return handle_audit(args)
    elif args.command == "remediate":
        return handle_remediate(args)
    elif args.command == "rollback":
        return handle_rollback(args)
    elif args.command == "report":
        return handle_report(args)
    elif args.command == "rules":
        return handle_rules(args)
    return 0


if __name__ == "__main__":
    sys.exit(main())
