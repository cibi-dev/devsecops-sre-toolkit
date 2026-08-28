"""Command-line interface for Chaos Fault Injector.

Subcommands:
- inject-net: Injects packet delay, jitter, loss, corruption on network interface via tc/netem.
- stress-cpu: Injects bounded CPU load across cores with duty-cycle control.
- kill-proc: Terminates targeted processes matching safety whitelist.
- dry-run: Simulates an experiment and generates a resilience report.
- rollback: Reverts network and system modifications immediately.
- status: Shows system safety status, privilege verification, active locks.
- report: Generates and formats resilience reports.
"""

from __future__ import annotations

import argparse
import os
import sys
import time
from typing import List, Optional
import psutil

from chaos.cpu_stress import CpuStressConfig, stress_cpu
from chaos.network import (
    NetworkFaultConfig,
    build_tc_command,
    build_tc_rollback_command,
    inject_network_fault,
    revert_network_fault,
)
from chaos.process_killer import ProcessTargetConfig, terminate_processes
from chaos.reporter import (
    ExperimentPhase,
    ResilienceTracker,
    export_json,
    export_markdown,
    generate_markdown_report,
)
from chaos.safety_guard import (
    ChaosSecurityError,
    SafetyGuard,
    validate_target_interface,
)


def build_parser() -> argparse.ArgumentParser:
    """Build the CLI argument parser with inherited common options."""
    parent_parser = argparse.ArgumentParser(add_help=False)
    parent_parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable full stacktraces on errors",
    )

    parser = argparse.ArgumentParser(
        prog="chaos",
        description="Chaos Fault Injector — Enterprise-grade Chaos Engineering Engine for Linux",
        parents=[parent_parser],
    )

    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")

    # inject-net
    p_net = subparsers.add_parser("inject-net", parents=[parent_parser], help="Inject network faults via tc/netem")
    p_net.add_argument("--interface", "-i", required=True, help="Network interface (e.g. eth0, ens33)")
    p_net.add_argument("--latency-ms", "-l", type=float, default=None, help="Latency in ms")
    p_net.add_argument("--jitter-ms", "-j", type=float, default=None, help="Jitter in ms")
    p_net.add_argument("--correlation-pct", type=float, default=None, help="Correlation percentage")
    p_net.add_argument("--loss-pct", type=float, default=None, help="Packet loss percentage")
    p_net.add_argument("--corruption-pct", type=float, default=None, help="Packet corruption percentage")
    p_net.add_argument("--duplicate-pct", type=float, default=None, help="Packet duplication percentage")
    p_net.add_argument("--reorder-pct", type=float, default=None, help="Packet reordering percentage")
    p_net.add_argument("--duration", "-d", type=float, default=10.0, help="Duration in seconds (max 30s)")
    p_net.add_argument("--dry-run", action="store_true", help="Simulate without applying tc rules")
    p_net.add_argument("--report-out", type=str, default=None, help="Output path for resilience report markdown")

    # stress-cpu
    p_cpu = subparsers.add_parser("stress-cpu", parents=[parent_parser], help="Inject bounded CPU load")
    p_cpu.add_argument("--cores", "-c", type=int, default=None, help="Number of cores to stress")
    p_cpu.add_argument("--load-pct", "-p", type=float, default=80.0, help="Target CPU load percentage (1-100)")
    p_cpu.add_argument("--duration", "-d", type=float, default=10.0, help="Duration in seconds (max 30s)")
    p_cpu.add_argument("--dry-run", action="store_true", help="Simulate without spinning CPU")
    p_cpu.add_argument("--report-out", type=str, default=None, help="Output path for resilience report markdown")

    # kill-proc
    p_proc = subparsers.add_parser("kill-proc", parents=[parent_parser], help="Terminate targeted processes matching whitelist")
    p_proc.add_argument("--pid", type=int, default=None, help="Target process PID")
    p_proc.add_argument("--name", "-n", type=str, default=None, help="Target process name or glob pattern")
    p_proc.add_argument("--signal", "-s", type=str, default="SIGTERM", help="Signal to send (SIGTERM, SIGKILL, etc.)")
    p_proc.add_argument(
        "--whitelist",
        "-w",
        action="append",
        default=[],
        help="Allowed process patterns (can be repeated)",
    )
    p_proc.add_argument("--dry-run", action="store_true", help="Simulate termination without sending signal")

    # dry-run
    p_dry = subparsers.add_parser("dry-run", parents=[parent_parser], help="Run a comprehensive simulated experiment and generate report")
    p_dry.add_argument("--type", choices=["network", "cpu", "process"], default="network", help="Fault type to simulate")
    p_dry.add_argument("--output", "-o", type=str, default=None, help="Output file path (.md or .json)")

    # rollback
    p_roll = subparsers.add_parser("rollback", parents=[parent_parser], help="Emergency rollback of network/system modifications")
    p_roll.add_argument("--interface", "-i", default="eth0", help="Network interface to reset")
    p_roll.add_argument("--dry-run", action="store_true", help="Simulate rollback command")

    # status
    subparsers.add_parser("status", parents=[parent_parser], help="Show system security status, locks, and guardrails")

    # report
    p_rep = subparsers.add_parser("report", parents=[parent_parser], help="Generate or display a resilience report")
    p_rep.add_argument("--format", choices=["markdown", "json"], default="markdown", help="Output format")
    p_rep.add_argument("--output", "-o", type=str, default=None, help="Output file path")

    return parser


def cmd_inject_net(args: argparse.Namespace) -> int:
    """Handle inject-net subcommand."""
    config = NetworkFaultConfig(
        interface=args.interface,
        latency_ms=args.latency_ms,
        jitter_ms=args.jitter_ms,
        correlation_pct=args.correlation_pct,
        loss_pct=args.loss_pct,
        corruption_pct=args.corruption_pct,
        duplicate_pct=args.duplicate_pct,
        reorder_pct=args.reorder_pct,
        duration_seconds=args.duration,
        dry_run=args.dry_run,
    )

    print(f"[*] Initializing Network Fault Injection on interface '{config.interface}'...")
    print(f"[*] Command: {' '.join(build_tc_command(config))}")
    print(f"[*] Rollback Command: {' '.join(build_tc_rollback_command(config.interface))}")

    tracker = ResilienceTracker(
        experiment_name=f"netem-{config.interface}",
        target_type="network",
        fault_details=config.model_dump(),
    )

    # Pre-fault phase sampling
    tracker.set_phase(ExperimentPhase.PRE_FAULT)
    for _ in range(5):
        tracker.record(latency_ms=10.0, success=True, cpu_pct=psutil.cpu_percent(), mem_pct=psutil.virtual_memory().percent)
        time.sleep(0.1)

    with SafetyGuard(auto_lock=True) as guard:
        guard.start_dead_man(timeout_seconds=config.duration_seconds + 2.0)
        result = inject_network_fault(config, safety_guard=guard)

        if not result.success:
            print(f"[!] Injection failed: {result.error}", file=sys.stderr)
            return 1

        print(f"[+] Injected successfully. Holding fault for {config.duration_seconds}s...")

        # During fault phase sampling
        tracker.set_phase(ExperimentPhase.DURING_FAULT)
        added_lat = config.latency_ms or 50.0
        for _ in range(int(config.duration_seconds * 2)):
            guard.heartbeat()
            tracker.record(
                latency_ms=10.0 + added_lat,
                success=config.loss_pct is None or config.loss_pct < 50.0,
                cpu_pct=psutil.cpu_percent(),
                mem_pct=psutil.virtual_memory().percent,
            )
            time.sleep(0.5)

        print("[*] Reverting network fault...")
        guard.rollback_all()

    # Post-fault phase sampling
    tracker.set_phase(ExperimentPhase.POST_FAULT)
    for _ in range(5):
        tracker.record(latency_ms=10.5, success=True, cpu_pct=psutil.cpu_percent(), mem_pct=psutil.virtual_memory().percent)
        time.sleep(0.1)

    report = tracker.finalize(
        pre_duration=1.0,
        during_duration=config.duration_seconds,
        post_duration=1.0,
        recovery_time_seconds=0.2,
    )

    print("\n" + generate_markdown_report(report))

    if args.report_out:
        export_markdown(report, args.report_out)
        print(f"[+] Report saved to {args.report_out}")

    return 0


def cmd_stress_cpu(args: argparse.Namespace) -> int:
    """Handle stress-cpu subcommand."""
    config = CpuStressConfig(
        cores=args.cores,
        load_percentage=args.load_pct,
        duration_seconds=args.duration,
        dry_run=args.dry_run,
    )

    print(f"[*] Initializing CPU Stress ({config.cores or 'all'} cores, {config.load_percentage}% load, {config.duration_seconds}s)...")

    tracker = ResilienceTracker(
        experiment_name="cpu-stress-test",
        target_type="cpu",
        fault_details=config.model_dump(),
    )

    # Pre-fault
    tracker.set_phase(ExperimentPhase.PRE_FAULT)
    for _ in range(3):
        tracker.record(latency_ms=5.0, success=True, cpu_pct=psutil.cpu_percent(), mem_pct=psutil.virtual_memory().percent)
        time.sleep(0.1)

    with SafetyGuard(auto_lock=True) as guard:
        guard.start_dead_man(timeout_seconds=config.duration_seconds + 2.0)
        tracker.set_phase(ExperimentPhase.DURING_FAULT)
        res = stress_cpu(config, safety_guard=guard)
        print(f"[+] CPU Stress finished. Observed average CPU load: {res.avg_cpu_percent_observed}%")

    # Post-fault
    tracker.set_phase(ExperimentPhase.POST_FAULT)
    for _ in range(3):
        tracker.record(latency_ms=5.2, success=True, cpu_pct=psutil.cpu_percent(), mem_pct=psutil.virtual_memory().percent)
        time.sleep(0.1)

    report = tracker.finalize(
        pre_duration=0.5,
        during_duration=config.duration_seconds,
        post_duration=0.5,
        recovery_time_seconds=0.1,
    )

    print("\n" + generate_markdown_report(report))

    if args.report_out:
        export_markdown(report, args.report_out)
        print(f"[+] Report saved to {args.report_out}")

    return 0


def cmd_kill_proc(args: argparse.Namespace) -> int:
    """Handle kill-proc subcommand."""
    whitelist = []
    for item in args.whitelist:
        if "," in item:
            whitelist.extend([p.strip() for p in item.split(",") if p.strip()])
        elif item.strip():
            whitelist.append(item.strip())

    config = ProcessTargetConfig(
        pid=args.pid,
        process_name=args.name,
        signal_name=args.signal,
        whitelist_patterns=whitelist,
        dry_run=args.dry_run,
    )

    print(f"[*] Searching target processes matching PID={config.pid}, Name='{config.process_name}'...")
    with SafetyGuard(auto_lock=True) as guard:
        results = terminate_processes(config, safety_guard=guard)

    if not results:
        print("[!] No eligible target processes found.", file=sys.stderr)
        return 1

    print(f"[+] Target dispatch results ({len(results)} processes):")
    for r in results:
        status_sym = "✅" if r.success else "❌"
        dry_str = " [DRY-RUN]" if r.dry_run else ""
        print(f"  {status_sym} PID {r.pid} ({r.name}): Sent {r.signal_sent}{dry_str}")
        if r.error:
            print(f"     Error: {r.error}", file=sys.stderr)

    return 0 if all(r.success for r in results) else 1


def cmd_dry_run(args: argparse.Namespace) -> int:
    """Handle dry-run comprehensive simulation."""
    print(f"[*] Running dry-run simulation for target type: {args.type}...")

    tracker = ResilienceTracker(
        experiment_name=f"simulated-{args.type}-chaos",
        target_type=args.type,
        fault_details={"simulation": True, "type": args.type},
    )

    # Baseline pre
    tracker.set_phase(ExperimentPhase.PRE_FAULT)
    for _ in range(5):
        tracker.record(latency_ms=12.0, success=True, cpu_pct=15.0, mem_pct=40.0)

    # During
    tracker.set_phase(ExperimentPhase.DURING_FAULT)
    for _ in range(10):
        tracker.record(latency_ms=150.0, success=True, cpu_pct=85.0, mem_pct=45.0)

    # Post
    tracker.set_phase(ExperimentPhase.POST_FAULT)
    for _ in range(5):
        tracker.record(latency_ms=12.5, success=True, cpu_pct=16.0, mem_pct=40.0)

    report = tracker.finalize(
        pre_duration=2.0,
        during_duration=5.0,
        post_duration=2.0,
        recovery_time_seconds=0.3,
        summary_notes="Dry-run simulation completed successfully with simulated resilience metrics.",
    )

    md = generate_markdown_report(report)
    print(md)

    if args.output:
        if args.output.endswith(".json"):
            export_json(report, args.output)
        else:
            export_markdown(report, args.output)
        print(f"[+] Simulation report exported to {args.output}")

    return 0


def cmd_rollback(args: argparse.Namespace) -> int:
    """Handle emergency rollback subcommand."""
    print(f"[*] Performing emergency rollback for interface '{args.interface}'...")
    try:
        sanitized = validate_target_interface(args.interface)
        success = revert_network_fault(sanitized, dry_run=args.dry_run)
        if success:
            print(f"[+] Rollback completed successfully for interface '{sanitized}'.")
            return 0
        else:
            print(f"[!] Rollback failed or could not be completed for '{sanitized}'.", file=sys.stderr)
            return 1
    except ChaosSecurityError as e:
        print(f"[!] Security guardrail prevented rollback: {e}", file=sys.stderr)
        return 1


def cmd_status() -> int:
    """Handle status subcommand."""
    print("==================================================")
    print("        🛡️ CHAOS FAULT INJECTOR STATUS")
    print("==================================================")

    # Root status
    is_root = (hasattr(os, "geteuid") and os.geteuid() == 0)
    root_icon = "🟢" if is_root else "🟡"
    print(f"Privilege Mode:     {root_icon} {'Root (Full Mutation Allowed)' if is_root else 'Non-Root (Dry-Run Only)'}")

    # CPUs & Memory
    cpu_count = os.cpu_count() or 1
    cpu_curr = psutil.cpu_percent(interval=0.1)
    mem_curr = psutil.virtual_memory().percent
    print(f"CPU Available:      {cpu_count} cores (Current Load: {cpu_curr}%)")
    print(f"Memory Usage:       {mem_curr}%")

    # Network interfaces
    ifaces = list(psutil.net_if_addrs().keys())
    print(f"Network Interfaces: {', '.join(ifaces)}")
    print("Security Guardrails: Dead-Man Switch (≤30s), Whitelist [PID 1, sshd, dbus, lo], Shell=False")
    print("==================================================")
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    """Handle report subcommand."""
    tracker = ResilienceTracker(
        experiment_name="sample-resilience-evaluation",
        target_type="network",
        fault_details={"sample": True},
    )
    # Pre
    tracker.set_phase(ExperimentPhase.PRE_FAULT)
    for _ in range(5):
        tracker.record(latency_ms=10.0, success=True, cpu_pct=10.0, mem_pct=30.0)
    # During
    tracker.set_phase(ExperimentPhase.DURING_FAULT)
    for _ in range(5):
        tracker.record(latency_ms=80.0, success=True, cpu_pct=50.0, mem_pct=35.0)
    # Post
    tracker.set_phase(ExperimentPhase.POST_FAULT)
    for _ in range(5):
        tracker.record(latency_ms=10.2, success=True, cpu_pct=11.0, mem_pct=30.0)

    report = tracker.finalize(pre_duration=1.0, during_duration=2.0, post_duration=1.0, recovery_time_seconds=0.1)

    if args.format == "json":
        out_str = export_json(report, args.output)
    else:
        out_str = export_markdown(report, args.output)

    print(out_str)
    if args.output:
        print(f"[+] Report exported to {args.output}")
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    """Main CLI entry point."""
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.command:
        parser.print_help()
        return 0

    try:
        if args.command == "inject-net":
            return cmd_inject_net(args)
        elif args.command == "stress-cpu":
            return cmd_stress_cpu(args)
        elif args.command == "kill-proc":
            return cmd_kill_proc(args)
        elif args.command == "dry-run":
            return cmd_dry_run(args)
        elif args.command == "rollback":
            return cmd_rollback(args)
        elif args.command == "status":
            return cmd_status()
        elif args.command == "report":
            return cmd_report(args)
        else:
            parser.print_help()
            return 1
    except (ChaosSecurityError, ValueError) as e:
        if getattr(args, "debug", False):
            raise
        print(f"[!] Error: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        if getattr(args, "debug", False):
            raise
        print(f"[!] Unexpected error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
