"""Command-line interface for Linux SRE Watchdog.

Subcommands:
- check: Inspect system health and display active anomalies.
- dry-run: Evaluate thresholds and preview recommended remediations.
- run-daemon: Run continuous SRE monitoring and auto-remediation loop.
- status: Inspect circuit breaker anti-flapping states and thresholds.
"""

from __future__ import annotations

import argparse
import json
import signal
import sys
import time
from pathlib import Path
from typing import Any, Optional

from watchdog.circuit_breaker import CircuitBreaker, CircuitBreakerConfig
from watchdog.collectors.procfs import ProcfsCollector, SystemSnapshot
from watchdog.collectors.systemd import SystemdCollector
from watchdog.engine import AnomalyEngine, AnomalyEvent, WatchdogConfig
from watchdog.logger import StructuredAuditLogger
from watchdog.remediation import RemediationManager


def load_config_file(config_path: str) -> WatchdogConfig:
    """Load and validate configuration JSON file safely (< 1MB, CWE-502/CWE-20)."""
    p = Path(config_path)
    if not p.is_file():
        print(f"Error: Config file '{config_path}' not found.", file=sys.stderr)
        sys.exit(2)

    stat = p.stat()
    if stat.st_size > 1024 * 1024:
        print(f"Error: Config file '{config_path}' exceeds 1MB limit.", file=sys.stderr)
        sys.exit(2)

    try:
        with p.open("r", encoding="utf-8") as f:
            data = json.load(f)
        return WatchdogConfig.model_validate(data)
    except (json.JSONDecodeError, ValueError) as e:
        print(f"Error: Invalid configuration format: {e}", file=sys.stderr)
        sys.exit(2)


def format_snapshot_table(snapshot: SystemSnapshot, anomalies: list[AnomalyEvent]) -> str:
    """Format human-readable CLI table."""
    lines = [
        "===========================================================",
        "                 LINUX SRE WATCHDOG STATUS                 ",
        "===========================================================",
        f"Timestamp:       {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(snapshot.timestamp))}",
        f"CPU Cores:       {snapshot.core_count}",
        f"CPU Usage:       {snapshot.cpu.usage_percent:.1f}%",
        f"RAM Usage:       {snapshot.memory.usage_percent:.1f}% ({snapshot.memory.used_bytes / (1024**3):.2f} GB / {snapshot.memory.total_bytes / (1024**3):.2f} GB)",
        f"Swap Usage:      {snapshot.memory.swap_usage_percent:.1f}% ({snapshot.memory.swap_used_bytes / (1024**3):.2f} GB / {snapshot.memory.swap_total_bytes / (1024**3):.2f} GB)",
        f"Load Average:    {snapshot.loadavg.load1:.2f}, {snapshot.loadavg.load5:.2f}, {snapshot.loadavg.load15:.2f}",
        f"Total Procs:     {snapshot.total_processes}",
        f"Zombie Procs:    {len(snapshot.zombies)}",
        "-----------------------------------------------------------",
    ]

    if snapshot.zombies:
        lines.append("Detected Zombies:")
        for z in snapshot.zombies:
            lines.append(f"  - PID {z.pid} (comm: {z.comm}, PPID: {z.ppid})")
        lines.append("-----------------------------------------------------------")

    if not anomalies:
        lines.append("System Health:   ✅ HEALTHY (0 anomalies detected)")
    else:
        lines.append(f"Active Anomalies ({len(anomalies)}):")
        for a in anomalies:
            runbook_str = f" -> Action: [{a.recommended_runbook}]" if a.recommended_runbook else ""
            lines.append(f"  [{a.severity.value}] {a.message}{runbook_str}")

    lines.append("===========================================================")
    return "\n".join(lines)


def cmd_check(args: argparse.Namespace) -> int:
    """Execute one-time inspection check."""
    collector = ProcfsCollector(proc_root=args.proc_root)
    systemd = SystemdCollector()
    config = load_config_file(args.config) if args.config else WatchdogConfig()
    engine = AnomalyEngine(config)

    snapshot = collector.take_snapshot(sample_interval=0.1)
    service_statuses = systemd.inspect_services(config.monitored_services) if config.monitored_services else None
    anomalies = engine.evaluate_snapshot(snapshot, service_statuses)

    if args.json:
        output = {
            "snapshot": snapshot.model_dump(),
            "anomalies": [a.model_dump() for a in anomalies],
            "healthy": len(anomalies) == 0,
        }
        print(json.dumps(output, indent=2))
    else:
        print(format_snapshot_table(snapshot, anomalies))

    return 1 if anomalies else 0


def cmd_dry_run(args: argparse.Namespace) -> int:
    """Execute inspection with dry-run remediation simulation."""
    collector = ProcfsCollector(proc_root=args.proc_root)
    systemd = SystemdCollector()
    config = load_config_file(args.config) if args.config else WatchdogConfig()
    engine = AnomalyEngine(config)
    circuit_breaker = CircuitBreaker()
    remediation = RemediationManager(circuit_breaker=circuit_breaker)
    logger = StructuredAuditLogger(log_file=args.log_file)

    snapshot = collector.take_snapshot(sample_interval=0.1)
    service_statuses = systemd.inspect_services(config.monitored_services) if config.monitored_services else None
    anomalies = engine.evaluate_snapshot(snapshot, service_statuses)

    print("\n--- [DRY-RUN] System Saturation Evaluation ---")
    print(format_snapshot_table(snapshot, anomalies))

    if not anomalies:
        print("\nNo remediation actions needed.")
        return 0

    print("\n--- [DRY-RUN] Planned Remediation Actions ---")
    for anomaly in anomalies:
        if anomaly.recommended_runbook:
            logger.log_pre_remediation(
                runbook_name=anomaly.recommended_runbook,
                circuit_breaker_state=circuit_breaker.get_state(anomaly.recommended_runbook).value,
                anomaly_payload=anomaly.model_dump(),
                dry_run=True,
            )
            result = remediation.execute_for_anomaly(anomaly, dry_run=True)
            if result:
                status_icon = "✅" if result.success else "❌"
                print(f"{status_icon} Action: {result.runbook_name}")
                print(f"   Output: {result.stdout or result.stderr}")
                logger.log_post_remediation(
                    runbook_name=result.runbook_name,
                    success=result.success,
                    circuit_breaker_state=circuit_breaker.get_state(result.runbook_name).value,
                    execution_time_ms=result.execution_time_ms,
                    stdout=result.stdout,
                    stderr=result.stderr,
                    details={"dry_run": True},
                )
    return 0


def cmd_status(args: argparse.Namespace) -> int:
    """Display circuit breaker states and health summary."""
    collector = ProcfsCollector(proc_root=args.proc_root)
    circuit_breaker = CircuitBreaker()
    snapshot = collector.take_snapshot(sample_interval=0.0)

    known_runbooks = [
        "clear_pagecache",
        "reap_zombies",
        "trim_journal",
        "throttle_high_cpu_tasks",
    ]

    print("===========================================================")
    print("             CIRCUIT BREAKER ANTI-FLAPPING STATUS          ")
    print("===========================================================")
    for runbook in known_runbooks:
        metrics = circuit_breaker.get_metrics(runbook)
        state = metrics["state"]
        icon = "🟢" if state == "CLOSED" else ("🔴" if state == "OPEN" else "🟡")
        print(f"{icon} Runbook: {runbook:<25} State: {state:<10} Failures in window: {metrics['recent_failures_in_window']}")

    print("-----------------------------------------------------------")
    print(f"System Cores: {snapshot.core_count} | RAM Total: {snapshot.memory.total_bytes / (1024**3):.2f} GB")
    print("===========================================================")
    return 0


def cmd_run_daemon(args: argparse.Namespace) -> int:
    """Run continuous monitoring loop."""
    collector = ProcfsCollector(proc_root=args.proc_root)
    systemd = SystemdCollector()
    config = load_config_file(args.config) if args.config else WatchdogConfig()
    engine = AnomalyEngine(config)
    circuit_breaker = CircuitBreaker()
    remediation = RemediationManager(circuit_breaker=circuit_breaker)
    logger = StructuredAuditLogger(log_file=args.log_file)

    stop_requested = False

    def handle_signal(signum: int, frame: Any) -> None:
        nonlocal stop_requested
        stop_requested = True
        print("\nDaemon shutdown requested. Exiting gracefully...", file=sys.stderr)

    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    interval = max(0.5, float(args.interval))
    max_iterations = getattr(args, "iterations", None)
    current_iter = 0

    print(f"Starting Linux SRE Watchdog daemon (interval={interval}s)...", file=sys.stderr)

    while not stop_requested:
        if max_iterations is not None and current_iter >= max_iterations:
            break

        current_iter += 1
        snapshot = collector.take_snapshot(sample_interval=0.0)
        service_statuses = systemd.inspect_services(config.monitored_services) if config.monitored_services else None
        anomalies = engine.evaluate_snapshot(snapshot, service_statuses)

        logger.log_check(
            snapshot_summary={
                "cpu_usage": snapshot.cpu.usage_percent,
                "ram_usage": snapshot.memory.usage_percent,
                "zombies": len(snapshot.zombies),
            },
            anomalies_count=len(anomalies),
        )

        for anomaly in anomalies:
            if anomaly.recommended_runbook:
                cb_state = circuit_breaker.get_state(anomaly.recommended_runbook).value
                logger.log_pre_remediation(
                    runbook_name=anomaly.recommended_runbook,
                    circuit_breaker_state=cb_state,
                    anomaly_payload=anomaly.model_dump(),
                )

                result = remediation.execute_for_anomaly(anomaly, dry_run=False)
                if result:
                    new_cb_state = circuit_breaker.get_state(result.runbook_name).value
                    logger.log_post_remediation(
                        runbook_name=result.runbook_name,
                        success=result.success,
                        circuit_breaker_state=new_cb_state,
                        execution_time_ms=result.execution_time_ms,
                        stdout=result.stdout,
                        stderr=result.stderr,
                    )

        if not stop_requested and (max_iterations is None or current_iter < max_iterations):
            time.sleep(interval)

    return 0


def build_parser() -> argparse.ArgumentParser:
    """Construct CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="sre-watchdog",
        description="Lightweight Linux SRE Watchdog Daemon with Procfs Inspection and Circuit Breaker",
    )
    parser.add_argument("--proc-root", default="/proc", help="Path to procfs root (default: /proc)")
    parser.add_argument("--config", default=None, help="Path to JSON configuration file")
    parser.add_argument("--log-file", default=None, help="Path to structured audit log file")
    parser.add_argument("--json", action="store_true", help="Format output as JSON")

    subparsers = parser.add_subparsers(dest="subcommand", required=True)

    # Subcommand: check
    p_check = subparsers.add_parser("check", help="Run one-time system saturation check")
    p_check.set_defaults(func=cmd_check)

    # Subcommand: dry-run
    p_dry = subparsers.add_parser("dry-run", help="Simulate inspection and preview remediation runbooks")
    p_dry.set_defaults(func=cmd_dry_run)

    # Subcommand: status
    p_status = subparsers.add_parser("status", help="Display circuit breaker anti-flapping status")
    p_status.set_defaults(func=cmd_status)

    # Subcommand: run-daemon
    p_daemon = subparsers.add_parser("run-daemon", help="Run continuous SRE monitoring daemon")
    p_daemon.add_argument("--interval", type=float, default=5.0, help="Loop interval in seconds (default: 5.0)")
    p_daemon.add_argument("--iterations", type=int, default=None, help="Maximum loop iterations (for testing)")
    p_daemon.set_defaults(func=cmd_run_daemon)

    return parser


def main(argv: Optional[list[str]] = None) -> int:
    """Entry point for CLI execution."""
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
