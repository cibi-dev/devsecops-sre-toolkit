"""CLI interface for prometheus-metrics-exporter.

Subcommands:
- serve: Run background or foreground HTTP metrics server
- collect: Collect instant host metrics and print formatted output
- eval-alerts: Evaluate alert YAML rules against current host metrics
- status: Check health and active alerts of a running exporter
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
import time
from pathlib import Path
from typing import List, Optional

import httpx

from .alert_evaluator import AlertEvaluator, AlertState
from .formatter import OpenMetricsFormatter
from .http_server import MetricsHTTPServer
from .metrics_collector import MetricsCollector
from .notifiers.webhook import WebhookNotifier, sanitize_url

logger = logging.getLogger("exporter.cli")


def build_parser() -> argparse.ArgumentParser:
    """Builds and returns the top-level argument parser."""
    parser = argparse.ArgumentParser(
        prog="prometheus-exporter",
        description="Enterprise-grade native Prometheus/OpenMetrics host metrics exporter and alert evaluator.",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose debug logging",
    )

    subparsers = parser.add_subparsers(dest="subcommand", help="Available subcommands")

    # serve subcommand
    serve_parser = subparsers.add_parser("serve", help="Start the HTTP metrics exporter server")
    serve_parser.add_argument("--host", default="0.0.0.0", help="HTTP server bind host (default: 0.0.0.0)")  # nosec B104
    serve_parser.add_argument("-p", "--port", type=int, default=9100, help="HTTP server bind port (default: 9100)")
    serve_parser.add_argument("--proc-root", default="/proc", help="Linux /proc filesystem root path (default: /proc)")
    serve_parser.add_argument("--format", choices=["openmetrics", "prometheus"], default="openmetrics", help="Exposition format")
    serve_parser.add_argument("--alerts-config", help="Path to alert rules YAML configuration file")
    serve_parser.add_argument("--webhook-url", help="Target webhook URL for alert notifications")
    serve_parser.add_argument("--interval", type=float, default=15.0, help="Alert evaluation interval in seconds (default: 15.0)")

    # collect subcommand
    collect_parser = subparsers.add_parser("collect", help="Perform single host metrics collection and print to stdout")
    collect_parser.add_argument("--proc-root", default="/proc", help="Linux /proc filesystem root path (default: /proc)")
    collect_parser.add_argument("--format", choices=["openmetrics", "prometheus", "json"], default="openmetrics", help="Output format")

    # eval-alerts subcommand
    eval_parser = subparsers.add_parser("eval-alerts", help="Evaluate alert YAML rules against current host metrics")
    eval_parser.add_argument("-c", "--config", required=True, help="Path to alert rules YAML configuration file")
    eval_parser.add_argument("--webhook-url", help="Target webhook URL for alert notifications")
    eval_parser.add_argument("--dry-run", action="store_true", help="Evaluate rules without dispatching webhooks")
    eval_parser.add_argument("--proc-root", default="/proc", help="Linux /proc filesystem root path (default: /proc)")

    # status subcommand
    status_parser = subparsers.add_parser("status", help="Query status of a running exporter instance")
    status_parser.add_argument("--url", default="http://localhost:9100", help="Base URL of exporter instance (default: http://localhost:9100)")
    status_parser.add_argument("--timeout", type=float, default=5.0, help="Request timeout in seconds")

    return parser


def cmd_serve(args: argparse.Namespace) -> int:
    """Executes the 'serve' subcommand."""
    collector = MetricsCollector(proc_root=args.proc_root)
    evaluator: Optional[AlertEvaluator] = None
    notifier: Optional[WebhookNotifier] = None

    if args.alerts_config:
        cfg_path = Path(args.alerts_config)
        if not cfg_path.exists():
            sys.stderr.write(f"Error: Alert configuration file not found: {args.alerts_config}\n")
            return 1
        evaluator = AlertEvaluator(cfg_path)
        logger.info("Loaded %d alert rule(s) from %s", len(evaluator.alert_instances), args.alerts_config)

    if args.webhook_url:
        notifier = WebhookNotifier(url=args.webhook_url)
        logger.info("Configured alert webhook target: %s", sanitize_url(args.webhook_url))

    server = MetricsHTTPServer(
        host=args.host,
        port=args.port,
        collector=collector,
        evaluator=evaluator,
        notifier=notifier,
        openmetrics=(args.format == "openmetrics"),
        eval_interval_seconds=args.interval,
    )

    sys.stdout.write(f"Starting Prometheus Metrics Exporter on http://{args.host}:{args.port}/metrics\n")
    try:
        server.start(background=False)
    except KeyboardInterrupt:
        sys.stdout.write("\nShutting down server...\n")
        server.stop()
    except Exception as exc:
        sys.stderr.write(f"Fatal server error: {exc}\n")
        return 1
    return 0


def cmd_collect(args: argparse.Namespace) -> int:
    """Executes the 'collect' subcommand."""
    collector = MetricsCollector(proc_root=args.proc_root)
    families = collector.collect_all()

    if args.format == "openmetrics":
        output = OpenMetricsFormatter.format_openmetrics(families)
    elif args.format == "prometheus":
        output = OpenMetricsFormatter.format_prometheus(families)
    elif args.format == "json":
        output = OpenMetricsFormatter.format_json(families)
    else:
        sys.stderr.write(f"Unknown format: {args.format}\n")
        return 2

    sys.stdout.write(output)
    return 0


def cmd_eval_alerts(args: argparse.Namespace) -> int:
    """Executes the 'eval-alerts' subcommand."""
    cfg_path = Path(args.config)
    if not cfg_path.exists():
        sys.stderr.write(f"Error: Alert config file not found: {args.config}\n")
        return 1

    try:
        evaluator = AlertEvaluator(cfg_path)
    except Exception as exc:
        sys.stderr.write(f"Error loading alert configuration: {exc}\n")
        return 1

    collector = MetricsCollector(proc_root=args.proc_root)
    families = collector.collect_all()
    updated = evaluator.evaluate(families)

    firing = evaluator.get_firing_alerts()
    pending = evaluator.get_pending_alerts()

    sys.stdout.write(f"Evaluated {len(updated)} alert rule(s):\n")
    for inst in updated:
        state_symbol = "🔥 FIRING" if inst.state == AlertState.FIRING else ("⏳ PENDING" if inst.state == AlertState.PENDING else "✅ OK")
        val_str = f"{inst.current_value:.2f}" if inst.current_value is not None else "N/A"
        sys.stdout.write(f"  - [{state_symbol}] {inst.rule.alert}: {inst.metric_name} = {val_str} (Threshold: {inst.operator} {inst.threshold})\n")

    if firing and args.webhook_url and not args.dry_run:
        notifier = WebhookNotifier(url=args.webhook_url)
        sys.stdout.write(f"Dispatching {len(firing)} firing alert(s) to webhook {sanitize_url(args.webhook_url)}...\n")
        success = notifier.dispatch(firing)
        if success:
            sys.stdout.write("Webhook dispatched successfully.\n")
        else:
            sys.stderr.write("Webhook dispatch failed.\n")
            return 1

    return 0


def cmd_status(args: argparse.Namespace) -> int:
    """Executes the 'status' subcommand."""
    base_url = args.url.rstrip("/")
    health_url = f"{base_url}/health"
    status_url = f"{base_url}/status"

    try:
        with httpx.Client(timeout=args.timeout) as client:
            resp_health = client.get(health_url)
            if resp_health.status_code != 200:
                sys.stderr.write(f"Exporter health check failed (HTTP {resp_health.status_code})\n")
                return 1

            resp_status = client.get(status_url)
            if resp_status.status_code == 200:
                status_data = resp_status.json()
                sys.stdout.write(json.dumps(status_data, indent=2) + "\n")
            else:
                sys.stdout.write(f"Exporter is UP: {resp_health.text}\n")
            return 0
    except Exception as exc:
        sys.stderr.write(f"Connection failed to {base_url}: {exc}\n")
        return 1


def main(argv: Optional[List[str]] = None) -> int:
    """Main CLI entrypoint."""
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.verbose:
        logging.basicConfig(level=logging.DEBUG, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
    else:
        logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

    if not args.subcommand:
        parser.print_help()
        return 0

    if args.subcommand == "serve":
        return cmd_serve(args)
    elif args.subcommand == "collect":
        return cmd_collect(args)
    elif args.subcommand == "eval-alerts":
        return cmd_eval_alerts(args)
    elif args.subcommand == "status":
        return cmd_status(args)

    return 0


if __name__ == "__main__":
    sys.exit(main())
