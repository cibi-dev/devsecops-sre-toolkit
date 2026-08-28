"""Command-Line Interface for Synthetic Blackbox Prober."""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from typing import Any, List, Optional

from prober.exporter import MetricsCollector, MetricsServer
from prober.probes.dns import DNSProbe
from prober.probes.http import HTTPProbe
from prober.probes.ssl_cert import SSLCertProbe
from prober.probes.tcp import TCPProbe
from prober.scheduler import ProbeScheduler, ProbeTarget


def create_parser() -> argparse.ArgumentParser:
    """Build argument parser for CLI commands."""
    parser = argparse.ArgumentParser(
        prog="synthetic-blackbox-prober",
        description="Asynchronous synthetic blackbox monitoring prober & Prometheus exporter",
    )
    subparsers = parser.add_subparsers(dest="subcommand", help="Available subcommands")

    # 1. probe
    probe_parser = subparsers.add_parser("probe", help="Execute an on-demand synthetic probe")
    probe_parser.add_argument("target", help="Target URL or Hostname to probe")
    probe_parser.add_argument(
        "--type",
        "-t",
        choices=["http", "https", "tcp", "ssl", "dns"],
        default="http",
        help="Probe type (default: http)",
    )
    probe_parser.add_argument("--port", "-p", type=int, default=None, help="Target TCP port")
    probe_parser.add_argument("--method", "-m", default="GET", help="HTTP Method for HTTP probes (default: GET)")
    probe_parser.add_argument("--record-type", "-r", default="A", help="DNS Record type (default: A)")
    probe_parser.add_argument("--timeout", type=float, default=5.0, help="Probe timeout in seconds (default: 5.0)")
    probe_parser.add_argument("--insecure", action="store_true", help="Skip TLS certificate verification")
    probe_parser.add_argument("--json", action="store_true", help="Output results in JSON format")

    # 2. watch-certs
    watch_parser = subparsers.add_parser("watch-certs", help="Inspect and monitor TLS certificates for expiration")
    watch_parser.add_argument("hosts", nargs="+", help="Hostnames to inspect")
    watch_parser.add_argument("--port", "-p", type=int, default=443, help="Port (default: 443)")
    watch_parser.add_argument("--timeout", type=float, default=5.0, help="Timeout in seconds")
    watch_parser.add_argument("--json", action="store_true", help="Output results in JSON format")

    # 3. run-server
    server_parser = subparsers.add_parser("run-server", help="Run Prometheus OpenMetrics exporter daemon")
    server_parser.add_argument("--host", default="127.0.0.1", help="Listen host (default: 127.0.0.1)")
    server_parser.add_argument("--port", "-p", type=int, default=9115, help="Listen port (default: 9115)")
    server_parser.add_argument("--config", "-c", help="Path to JSON file with targets")
    server_parser.add_argument("--targets", nargs="*", default=[], help="Targets to probe (e.g. https://google.com)")
    server_parser.add_argument("--interval", type=float, default=15.0, help="Probe interval seconds (default: 15.0)")

    # 4. status
    status_parser = subparsers.add_parser("status", help="Run quick health check across targets and print report")
    status_parser.add_argument("targets", nargs="+", help="Targets to probe")
    status_parser.add_argument("--json", action="store_true", help="Output results in JSON format")

    return parser


async def run_probe(args: argparse.Namespace) -> int:
    """Execute single probe subcommand."""
    probe_type = args.type.lower()
    target = args.target
    timeout = args.timeout
    verify_ssl = not args.insecure

    result: Any = None
    if probe_type in ("http", "https"):
        url = target
        if not (url.startswith("http://") or url.startswith("https://")):
            url = f"{probe_type}://{target}"
        prober = HTTPProbe(default_timeout=timeout)
        result = await prober.probe(url=url, method=args.method, timeout=timeout, verify_ssl=verify_ssl)
    elif probe_type == "tcp":
        port = args.port or 80
        prober_tcp = TCPProbe(default_timeout=timeout)
        result = await prober_tcp.probe(host=target, port=port, timeout=timeout)
    elif probe_type == "ssl":
        port = args.port or 443
        prober_ssl = SSLCertProbe(default_timeout=timeout)
        result = await prober_ssl.probe(host=target, port=port, timeout=timeout, verify_ssl=verify_ssl)
    elif probe_type == "dns":
        prober_dns = DNSProbe(default_timeout=timeout)
        result = await prober_dns.probe(target=target, record_type=args.record_type, timeout=timeout)
    else:
        print(f"Error: Unknown probe type {probe_type}", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps(result.model_dump(mode="json"), indent=2))
    else:
        print(f"=== Synthetic Probe Result [{result.__class__.__name__}] ===")
        for k, v in result.model_dump(mode="json").items():
            print(f"  {k:22s}: {v}")

    return 0 if getattr(result, "is_success", False) else 1


async def run_watch_certs(args: argparse.Namespace) -> int:
    """Execute watch-certs subcommand."""
    prober = SSLCertProbe(default_timeout=args.timeout)
    tasks = [prober.probe(host=h, port=args.port, timeout=args.timeout) for h in args.hosts]
    results = await asyncio.gather(*tasks)

    if args.json:
        print(json.dumps([r.model_dump(mode="json") for r in results], indent=2))
        return 0

    print(f"\n{'HOST':<30} {'STATUS':<15} {'ALERT LEVEL':<15} {'DAYS REMAINING':<15} {'EXPIRATION DATE':<25}")
    print("-" * 105)
    has_critical = False
    for r in results:
        days_str = f"{r.days_until_expiration:.1f}d" if r.days_until_expiration is not None else "N/A"
        expiry_str = r.not_after.strftime("%Y-%m-%d %H:%M:%S UTC") if r.not_after else "N/A"
        print(f"{r.host:<30} {r.status:<15} {r.alert_level:<15} {days_str:<15} {expiry_str:<25}")
        if r.alert_level in ("EXPIRED", "EMERGENCY_7D", "CRITICAL_15D"):
            has_critical = True

    return 1 if has_critical else 0


async def run_server_daemon(args: argparse.Namespace) -> int:
    """Run OpenMetrics Prometheus exporter daemon."""
    collector = MetricsCollector()
    server = MetricsServer(collector, host=args.host, port=args.port)
    await server.start()

    targets: List[ProbeTarget] = []
    if args.config:
        try:
            with open(args.config, "r") as f:
                cfg_data = json.load(f)
                for item in cfg_data:
                    targets.append(ProbeTarget(**item))
        except Exception as e:
            print(f"Failed to load config {args.config}: {e}", file=sys.stderr)
            await server.stop()
            return 1

    for t in args.targets:
        ptype = "http" if t.startswith("http") else "tcp"
        targets.append(ProbeTarget(name=t, probe_type=ptype, target=t, interval_seconds=args.interval))

    if not targets:
        print("Warning: No targets specified. Metrics server running with empty telemetry.", file=sys.stderr)

    scheduler = ProbeScheduler()

    async def _on_result(tgt: ProbeTarget, res: Any) -> None:
        await collector.record_result(tgt.name, res)

    print(f"Synthetic Blackbox Prober Exporter listening on http://{args.host}:{args.port}/metrics")
    try:
        await scheduler.run_loop(targets=targets, callback=_on_result)
    except (asyncio.CancelledError, KeyboardInterrupt):
        pass
    finally:
        await server.stop()

    return 0


async def run_status(args: argparse.Namespace) -> int:
    """Execute batch status check across targets."""
    targets = [
        ProbeTarget(
            name=t,
            probe_type="http" if (t.startswith("http://") or t.startswith("https://")) else "tcp",
            target=t,
            port=80 if not (t.startswith("http://") or t.startswith("https://")) else 443,
        )
        for t in args.targets
    ]
    scheduler = ProbeScheduler()
    results = await scheduler.run_batch(targets)

    if args.json:
        out = [{"target": t.target, "result": r.model_dump(mode="json")} for t, r in zip(targets, results)]
        print(json.dumps(out, indent=2))
        return 0

    print(f"\n{'TARGET':<40} {'STATUS':<15} {'LATENCY (ms)':<15} {'DETAIL'}")
    print("-" * 90)
    all_ok = True
    for t, r in zip(targets, results):
        lat = getattr(r, "total_latency_ms", getattr(r, "latency_ms", 0.0))
        err_or_detail = r.error if r.error else ("OK" if r.is_success else "FAIL")
        print(f"{t.target:<40} {r.status:<15} {lat:<15.2f} {err_or_detail}")
        if not r.is_success:
            all_ok = False

    return 0 if all_ok else 1


def main(argv: Optional[List[str]] = None) -> None:
    """CLI Entrypoint."""
    parser = create_parser()
    args = parser.parse_args(argv)

    if not args.subcommand:
        parser.print_help()
        sys.exit(0)

    try:
        if args.subcommand == "probe":
            code = asyncio.run(run_probe(args))
        elif args.subcommand == "watch-certs":
            code = asyncio.run(run_watch_certs(args))
        elif args.subcommand == "run-server":
            code = asyncio.run(run_server_daemon(args))
        elif args.subcommand == "status":
            code = asyncio.run(run_status(args))
        else:
            parser.print_help()
            code = 0
        sys.exit(code)
    except KeyboardInterrupt:
        sys.exit(130)


if __name__ == "__main__":
    main()
