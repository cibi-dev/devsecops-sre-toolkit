"""Command line interface for infra-drift-detector (CWE-78, CWE-250)."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Sequence

from drift.comparator import DriftComparator
from drift.parser import ManifestParseError, parse_manifest
from drift.reporter import DriftReporter


def build_parser() -> argparse.ArgumentParser:
    """Construct CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="infra-drift",
        description="Enterprise read-only GitOps infrastructure drift detector for Linux.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # 1. Audit command
    audit_parser = subparsers.add_parser("audit", help="Audit live host against desired manifest.")
    audit_parser.add_argument("manifest", type=str, help="Path to desired state YAML manifest.")
    audit_parser.add_argument(
        "--format",
        choices=["text", "json", "markdown"],
        default="text",
        help="Report output format (default: text).",
    )
    audit_parser.add_argument(
        "--output",
        "-o",
        type=str,
        default=None,
        help="Optional file path to save the generated report.",
    )
    audit_parser.add_argument(
        "--exit-code",
        action="store_true",
        help="Exit with non-zero code (1) if configuration drift is detected.",
    )

    # 2. Diff command
    diff_parser = subparsers.add_parser("diff", help="Show unified diffs of drifted infrastructure.")
    diff_parser.add_argument("manifest", type=str, help="Path to desired state YAML manifest.")
    diff_parser.add_argument(
        "--output",
        "-o",
        type=str,
        default=None,
        help="Optional file path to write diff output.",
    )

    # 3. Validate command
    val_parser = subparsers.add_parser("validate", help="Validate manifest syntax and schema.")
    val_parser.add_argument("manifest", type=str, help="Path to desired state YAML manifest.")

    # 4. Report command (Markdown PR generator)
    rep_parser = subparsers.add_parser(
        "report", help="Generate GitHub PR-ready Markdown drift report."
    )
    rep_parser.add_argument("manifest", type=str, help="Path to desired state YAML manifest.")
    rep_parser.add_argument(
        "--output",
        "-o",
        type=str,
        default=None,
        help="Output file path (default: stdout).",
    )

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Main CLI entrypoint."""
    parser = build_parser()
    args = parser.parse_args(argv)

    manifest_path = Path(args.manifest)

    # Validate subcommand
    if args.command == "validate":
        try:
            manifest = parse_manifest(manifest_path)
            total = (
                len(manifest.users)
                + len(manifest.services)
                + len(manifest.sysctl)
                + len(manifest.ports)
                + len(manifest.files)
                + len(manifest.packages)
            )
            print(f"✅ Manifest '{manifest.name}' is valid. Defined resources: {total}")
            return 0
        except ManifestParseError as exc:
            print(f"❌ Manifest validation failed: {exc}", file=sys.stderr)
            return 2

    # Load manifest for audit/diff/report
    try:
        manifest = parse_manifest(manifest_path)
    except ManifestParseError as exc:
        print(f"❌ Error reading manifest: {exc}", file=sys.stderr)
        return 2

    comparator = DriftComparator()
    result = comparator.compare(manifest)

    # Handle commands
    if args.command == "diff":
        output_text = DriftReporter.to_unified_diff(result)
        if args.output:
            Path(args.output).write_text(output_text, encoding="utf-8")
        else:
            print(output_text)
        return 1 if result.drift_detected else 0

    if args.command == "report":
        output_text = DriftReporter.to_markdown(result)
        if args.output:
            Path(args.output).write_text(output_text, encoding="utf-8")
        else:
            print(output_text)
        return 0

    if args.command == "audit":
        if args.format == "json":
            output_text = DriftReporter.to_json(result)
        elif args.format == "markdown":
            output_text = DriftReporter.to_markdown(result)
        else:
            output_text = DriftReporter.to_text(result)

        if args.output:
            Path(args.output).write_text(output_text, encoding="utf-8")
        else:
            print(output_text)

        if args.exit_code and result.drift_detected:
            return 1
        return 0

    return 0


if __name__ == "__main__":
    sys.exit(main())
