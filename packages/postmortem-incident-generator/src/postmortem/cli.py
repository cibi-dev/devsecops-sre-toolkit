"""CLI Command Interface for Blameless Post-Mortem Automation.

Provides subcommands for evidence collection, timeline reconstruction,
metrics calculation, SQLite storage management, and SRE Markdown report generation.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

from postmortem.collector import EvidenceCollector
from postmortem.generator import IncidentReport, IncidentSeverity, IncidentStatus, PostmortemGenerator
from postmortem.rca_engine import ActionItemPriority, ActionItemType, ContributingFactorCategory, RCAEngine
from postmortem.sanitizer import sanitize_text
from postmortem.storage import IncidentStorage
from postmortem.timeline_builder import EventType, TimelineBuilder


def build_parser() -> argparse.ArgumentParser:
    """Construct argument parser with all SRE post-mortem subcommands."""
    parser = argparse.ArgumentParser(
        prog="postmortem",
        description="Automated Blameless Post-Mortem Incident Generator CLI",
    )
    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")

    # 1. list
    list_parser = subparsers.add_parser("list", help="List registered post-mortem incidents")
    list_parser.add_argument("--severity", choices=["SEV-1", "SEV-2", "SEV-3", "SEV-4"], help="Filter by severity")
    list_parser.add_argument("--status", choices=["INVESTIGATING", "IDENTIFIED", "MITIGATED", "RESOLVED", "CLOSED"], help="Filter by status")
    list_parser.add_argument("--limit", type=int, default=20, help="Maximum number of records")
    list_parser.add_argument("--db-path", type=str, default=None, help="Custom SQLite database path")

    # 2. record
    record_parser = subparsers.add_parser("record", help="Record a new incident into storage")
    record_parser.add_argument("--id", dest="incident_id", required=True, help="Unique Incident ID (e.g. INC-2026-0827-01)")
    record_parser.add_argument("--title", required=True, help="Short incident title")
    record_parser.add_argument("--severity", choices=["SEV-1", "SEV-2", "SEV-3", "SEV-4"], default="SEV-1", help="Severity level")
    record_parser.add_argument("--status", choices=["INVESTIGATING", "IDENTIFIED", "MITIGATED", "RESOLVED", "CLOSED"], default="RESOLVED", help="Status")
    record_parser.add_argument("--date", default=datetime.now(timezone.utc).strftime("%Y-%m-%d"), help="Incident date (YYYY-MM-DD)")
    record_parser.add_argument("--commander", default="On-Call SRE", help="Incident Commander")
    record_parser.add_argument("--lead", default="Tech Lead", help="Technical Lead")
    record_parser.add_argument("--summary", required=True, help="Executive summary")
    record_parser.add_argument("--user-impact", default="Degraded response times for users", help="Impact on users")
    record_parser.add_argument("--trigger", default="Configuration deployment or upstream latency spike", help="Trigger event")
    record_parser.add_argument("--root-cause", default="Latent configuration error under high concurrent load", help="Root cause summary")
    record_parser.add_argument("--collect-evidence", action="store_true", help="Auto-collect host saturation and git evidences")
    record_parser.add_argument("--db-path", type=str, default=None, help="Custom SQLite database path")

    # 3. timeline
    timeline_parser = subparsers.add_parser("timeline", help="View or append events to an incident timeline")
    timeline_parser.add_argument("--incident-id", required=True, help="Incident ID")
    timeline_parser.add_argument("--add-event", action="store_true", help="Append a new event milestone")
    timeline_parser.add_argument("--timestamp", default=datetime.now(timezone.utc).isoformat(), help="Event timestamp (ISO / UTC)")
    timeline_parser.add_argument("--event-type", default="INVESTIGATION", help="Event phase/type (DETECTION, ACKNOWLEDGEMENT, MITIGATION_ATTEMPT, RESOLVED, etc.)")
    timeline_parser.add_argument("--desc", default="Investigating system status", help="Event description")
    timeline_parser.add_argument("--source", default="CLI", help="Event source")
    timeline_parser.add_argument("--impact", default="INFO", choices=["INFO", "WARN", "CRITICAL"], help="Impact level")
    timeline_parser.add_argument("--db-path", type=str, default=None, help="Custom SQLite database path")

    # 4. metrics
    metrics_parser = subparsers.add_parser("metrics", help="Display calculated SRE metrics (TTD, MTTA, MTTR, TTM)")
    metrics_parser.add_argument("--incident-id", required=True, help="Incident ID")
    metrics_parser.add_argument("--db-path", type=str, default=None, help="Custom SQLite database path")

    # 5. generate
    gen_parser = subparsers.add_parser("generate", help="Generate auditable Markdown or JSON post-mortem report")
    gen_parser.add_argument("--incident-id", help="Incident ID in SQLite database")
    gen_parser.add_argument("--input-file", help="Input JSON file containing full IncidentReport data")
    gen_parser.add_argument("--output", "-o", help="Target output file path (e.g. postmortem.md)")
    gen_parser.add_argument("--format", choices=["markdown", "json"], default="markdown", help="Output format")
    gen_parser.add_argument("--db-path", type=str, default=None, help="Custom SQLite database path")

    # 6. collect
    col_parser = subparsers.add_parser("collect", help="Collect read-only host saturation, git and log evidences")
    col_parser.add_argument("--service", help="Systemd service unit name to filter logs")
    col_parser.add_argument("--repo", default=".", help="Path to git repository")
    col_parser.add_argument("--lines", type=int, default=50, help="Max log lines to capture")
    col_parser.add_argument("--output", "-o", help="Save evidence JSON to file")
    col_parser.add_argument("--no-sanitize", action="store_true", help="Disable redaction sanitizer")

    # 7. sanitize
    san_parser = subparsers.add_parser("sanitize", help="Sanitize tokens, private keys, and secrets from input text or file")
    san_parser.add_argument("--file", "-f", help="Input text or log file path")
    san_parser.add_argument("--text", "-t", help="Raw string to sanitize")
    san_parser.add_argument("--output", "-o", help="Output file path")

    return parser


def handle_list(args: argparse.Namespace) -> int:
    """Handle list subcommand."""
    storage = IncidentStorage(db_path=args.db_path)
    records = storage.list_incidents(limit=args.limit, severity=args.severity, status=args.status)
    if not records:
        print("[INFO] No incident post-mortems found in storage.")
        return 0

    print(f"\n{'INCIDENT ID':<22} | {'SEVERITY':<8} | {'STATUS':<12} | {'DATE':<10} | {'TITLE'}")
    print("-" * 80)
    for r in records:
        print(f"{r['incident_id']:<22} | {r['severity']:<8} | {r['status']:<12} | {r['date']:<10} | {r['title']}")
    print(f"\nTotal records: {len(records)}\n")
    return 0


def handle_record(args: argparse.Namespace) -> int:
    """Handle record subcommand."""
    storage = IncidentStorage(db_path=args.db_path)
    rca_eng = RCAEngine(sanitize=True)

    evidences = {}
    if args.collect_evidence:
        collector = EvidenceCollector(sanitize=True)
        evidences = collector.collect_all()

    timeline_b = TimelineBuilder(sanitize=True)
    # Add initial start and resolved events if not present
    now_str = datetime.now(timezone.utc).isoformat()
    timeline_b.add_event(timestamp=now_str, event_type=EventType.INCIDENT_START, description=f"Incident '{args.title}' initiated", source="System Monitor")
    timeline_b.add_event(timestamp=now_str, event_type=EventType.DETECTION, description="Automated monitor raised anomaly alert", source="Prometheus")
    timeline_b.add_event(timestamp=now_str, event_type=EventType.ACKNOWLEDGEMENT, description=f"Acknowledged by {args.commander}", source="PagerDuty")
    timeline_b.add_event(timestamp=now_str, event_type=EventType.RESOLVED, description="Full service recovery verified", source="SRE Team")

    metrics = timeline_b.compute_metrics()
    rca = rca_eng.generate_rca_result(trigger_event=args.trigger, root_cause_summary=args.root_cause)

    report = IncidentReport(
        incident_id=args.incident_id,
        title=args.title,
        severity=args.severity,
        status=args.status,
        date=args.date,
        commander=args.commander,
        lead=args.lead,
        summary=args.summary,
        user_impact=args.user_impact,
        timeline=timeline_b.get_chronological_timeline(),
        metrics=metrics,
        rca=rca,
        evidences=evidences,
    )

    saved_id = storage.save_incident(report)
    print(f"✅ Incident recorded successfully in storage: ID '{saved_id}'")
    return 0


def handle_timeline(args: argparse.Namespace) -> int:
    """Handle timeline subcommand."""
    storage = IncidentStorage(db_path=args.db_path)
    incident = storage.get_incident(args.incident_id)
    if not incident:
        print(f"[ERROR] Incident '{args.incident_id}' not found in database.", file=sys.stderr)
        return 1

    if args.add_event:
        tb = TimelineBuilder(sanitize=True)
        for ev in incident.timeline:
            tb.add_event_object(ev)
        tb.add_event(
            timestamp=args.timestamp,
            event_type=args.event_type,
            description=args.desc,
            source=args.source,
            impact_level=args.impact,
        )
        incident.timeline = tb.get_chronological_timeline()
        incident.metrics = tb.compute_metrics()
        storage.save_incident(incident)
        print(f"✅ Event added to timeline for incident '{args.incident_id}'.")
        return 0

    print(f"\n📅 Timeline for Incident: {incident.incident_id} - {incident.title}")
    print("-" * 80)
    for ev in incident.timeline:
        ts_str = ev.timestamp.strftime("%Y-%m-%d %H:%M:%S UTC")
        print(f"[{ts_str}] [{ev.event_type:<18}] ({ev.impact_level:<8}) {ev.description}")
    print("-" * 80)
    return 0


def handle_metrics(args: argparse.Namespace) -> int:
    """Handle metrics subcommand."""
    storage = IncidentStorage(db_path=args.db_path)
    incident = storage.get_incident(args.incident_id)
    if not incident:
        print(f"[ERROR] Incident '{args.incident_id}' not found in database.", file=sys.stderr)
        return 1

    m = incident.metrics
    print(f"\n⏱️ SRE Metrics for Incident: {incident.incident_id}")
    print("-" * 50)
    print(f"Time to Detect (TTD):       {m.ttd_formatted:<12} ({m.ttd_seconds or 0:.1f}s)")
    print(f"Time to Ack (MTTA):         {m.mtta_formatted:<12} ({m.mtta_seconds or 0:.1f}s)")
    print(f"Time to Mitigate (TTM):     {m.ttm_formatted:<12} ({m.ttm_seconds or 0:.1f}s)")
    print(f"Time to Resolve (MTTR):     {m.mttr_formatted:<12} ({m.mttr_seconds or 0:.1f}s)")
    print(f"Total Outage Duration:      {m.total_outage_formatted:<12} ({m.total_outage_seconds or 0:.1f}s)")
    print("-" * 50 + "\n")
    return 0


def handle_generate(args: argparse.Namespace) -> int:
    """Handle generate subcommand."""
    report: Optional[IncidentReport] = None

    if args.input_file:
        input_path = Path(args.input_file)
        if not input_path.is_file():
            print(f"[ERROR] Input file '{input_path}' does not exist.", file=sys.stderr)
            return 1
        with input_path.open("r", encoding="utf-8") as f:
            raw_data = json.load(f)
            report = IncidentReport(**raw_data)
    elif args.incident_id:
        storage = IncidentStorage(db_path=args.db_path)
        report = storage.get_incident(args.incident_id)
        if not report:
            print(f"[ERROR] Incident '{args.incident_id}' not found in database.", file=sys.stderr)
            return 1
    else:
        print("[ERROR] Please specify either --incident-id or --input-file.", file=sys.stderr)
        return 1

    generator = PostmortemGenerator()

    if args.format == "json":
        output_content = generator.render_json(report)
    else:
        output_content = generator.render_markdown(report)

    if args.output:
        out_path = Path(args.output).resolve()
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(output_content, encoding="utf-8")
        print(f"✅ Post-mortem report generated at: {out_path}")
    else:
        print(output_content)

    return 0


def handle_collect(args: argparse.Namespace) -> int:
    """Handle collect subcommand."""
    collector = EvidenceCollector(sanitize=not args.no_sanitize)
    evidence = collector.collect_all(
        service=args.service,
        repo_path=args.repo,
        lines=args.lines,
    )
    rendered = json.dumps(evidence, indent=2)

    if args.output:
        out_path = Path(args.output).resolve()
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(rendered, encoding="utf-8")
        print(f"✅ Sanitized evidence bundle saved to: {out_path}")
    else:
        print(rendered)

    return 0


def handle_sanitize(args: argparse.Namespace) -> int:
    """Handle sanitize subcommand."""
    raw_text = ""
    if args.file:
        file_path = Path(args.file)
        if not file_path.is_file():
            print(f"[ERROR] File '{file_path}' does not exist.", file=sys.stderr)
            return 1
        raw_text = file_path.read_text(encoding="utf-8", errors="replace")
    elif args.text:
        raw_text = args.text
    else:
        if not sys.stdin.isatty():
            raw_text = sys.stdin.read()
        else:
            print("[ERROR] No input provided to sanitize. Use --file, --text or pipe stdin.", file=sys.stderr)
            return 1

    cleaned = sanitize_text(raw_text)
    if args.output:
        out_path = Path(args.output).resolve()
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(cleaned, encoding="utf-8")
        print(f"✅ Sanitized content written to: {out_path}")
    else:
        print(cleaned)

    return 0


def main(argv: Optional[List[str]] = None) -> int:
    """CLI entrypoint dispatcher."""
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.command:
        parser.print_help()
        return 0

    command_handlers = {
        "list": handle_list,
        "record": handle_record,
        "timeline": handle_timeline,
        "metrics": handle_metrics,
        "generate": handle_generate,
        "collect": handle_collect,
        "sanitize": handle_sanitize,
    }

    handler = command_handlers.get(args.command)
    if handler:
        return handler(args)

    parser.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())
