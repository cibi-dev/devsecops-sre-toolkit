"""
Unified Command-Line Interface for Enterprise DevSecOps & SRE Resilience Toolkit.

Comprehensive multi-engine platform with 17 specialized modules:
- cis-audit: Linux CIS Benchmark Scanner & Automated Hardener
- scan-secrets: Container & Filesystem Secret Scanner with Shannon Entropy
- drift: Infrastructure State Drift Detector & Policy Enforcer
- backup: Encrypted Zero-Knowledge Backup Orchestrator (AES-256-GCM + Zstd)
- proxy: High-Performance Reverse Proxy, Rate Limiter & Circuit Breaker
- type-refactor: LangGraph Multi-Agent AST Type Coverage Refactorer
- code-healer: LangGraph Autonomous Self-Healing Code & Security Patcher
- slo-check: SRE Multi-Window Multi-Burn-Rate SLO Engine
- watchdog: Linux SRE Health Watchdog with Autonomous Circuit Breakers
- inject-fault: Chaos Engineering Fault Injector (Stress, Latency, Kill)
- metrics-exporter: Prometheus Metrics Exporter & Dynamic Alerting
- log-aggregator: Stream Log Aggregator, Grok Parser & PII Sanitizer
- probe: Blackbox Synthetic Prober (HTTP, TCP, DNS, TLS)
- deploy: Zero-Downtime Blue/Green Deployer with Automated Canary Rollback
- tracing: Distributed Tracing Profiler & OpenTelemetry Exporter
- ci-runner: Deterministic DAG-based Lightweight CI Runner
- postmortem: Automated Blameless Incident Postmortem & RCA Generator
- demo: Complete End-to-End DevSecOps, SRE & Resilience Pipeline Simulation
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sys
import tempfile
from typing import Sequence

# Register all package source directories to sys.path
_ROOT = Path(__file__).resolve().parent
_PACKAGES_DIR = _ROOT / "packages"

_MODULE_PATHS = [
    _ROOT,
    _PACKAGES_DIR / "blue-green-deployer" / "src",
    _PACKAGES_DIR / "chaos-fault-injector" / "src",
    _PACKAGES_DIR / "container-secret-scanner" / "src",
    _PACKAGES_DIR / "distributed-tracing-profiler" / "src",
    _PACKAGES_DIR / "encrypted-backup-orchestrator" / "src",
    _PACKAGES_DIR / "infra-drift-detector" / "src",
    _PACKAGES_DIR / "langgraph-autonomous-code-healer" / "src",
    _PACKAGES_DIR / "langgraph-type-coverage-refactorer" / "src",
    _PACKAGES_DIR / "lightweight-ci-runner" / "src",
    _PACKAGES_DIR / "linux-cis-hardener" / "src",
    _PACKAGES_DIR / "linux-sre-watchdog" / "src",
    _PACKAGES_DIR / "postmortem-incident-generator" / "src",
    _PACKAGES_DIR / "prometheus-metrics-exporter" / "src",
    _PACKAGES_DIR / "reverse-proxy-limiter" / "src",
    _PACKAGES_DIR / "slo-burnrate-engine" / "src",
    _PACKAGES_DIR / "stream-log-aggregator" / "src",
    _PACKAGES_DIR / "synthetic-blackbox-prober" / "src",
]

for p in _MODULE_PATHS:
    p_str = str(p)
    if p_str not in sys.path:
        sys.path.insert(0, p_str)

__version__ = "1.0.0"


def _run_cis(argv: list[str]) -> int:
    import cis.cli
    return cis.cli.main(argv)


def _run_secrets(argv: list[str]) -> int:
    import scanner.cli
    return scanner.cli.main(argv)


def _run_drift(argv: list[str]) -> int:
    import drift.cli
    return drift.cli.main(argv)


def _run_backup(argv: list[str]) -> int:
    import backup.cli
    return backup.cli.main(argv)


def _run_proxy(argv: list[str]) -> int:
    import proxy.cli
    return proxy.cli.main(argv)


def _run_type_refactor(argv: list[str]) -> int:
    import refactorer.cli
    return refactorer.cli.main(argv)


def _run_code_healer(argv: list[str]) -> int:
    import healer.cli
    return healer.cli.main(argv)


def _run_slo(argv: list[str]) -> int:
    import slo.cli
    return slo.cli.main(argv)


def _run_watchdog(argv: list[str]) -> int:
    import watchdog.cli
    return watchdog.cli.main(argv)


def _run_chaos(argv: list[str]) -> int:
    import chaos.cli
    return chaos.cli.main(argv)


def _run_metrics(argv: list[str]) -> int:
    import exporter.cli
    return exporter.cli.main(argv)


def _run_logs(argv: list[str]) -> int:
    import aggregator.cli
    return aggregator.cli.main(argv)


def _run_prober(argv: list[str]) -> int:
    import prober.cli
    try:
        prober.cli.main(argv)  # type: ignore[func-returns-value]
    except SystemExit as exc:
        return int(exc.code) if isinstance(exc.code, int) else 0
    return 0


def _run_deployer(argv: list[str]) -> int:
    import deployer.cli
    return deployer.cli.main(argv)


def _run_tracing(argv: list[str]) -> int:
    import tracing.cli
    return tracing.cli.main(argv)


def _run_ci_runner(argv: list[str]) -> int:
    import runner.cli
    return runner.cli.main(argv)


def _run_postmortem(argv: list[str]) -> int:
    import postmortem.cli
    return postmortem.cli.main(argv)


def _run_pipeline_demo() -> int:
    """Runs a complete end-to-end DevSecOps & SRE resilience demonstration."""
    print("=" * 78)
    print("🛡️ DEVSECOPS & SRE TOOLKIT - ENTERPRISE MULTI-ENGINE RESILIENCE PIPELINE")
    print("=" * 78)

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)

        # ---------------------------------------------------------
        # 1. Container & Secret Scanning
        # ---------------------------------------------------------
        print("\n[Step 1/7] 🔍 Security Audit: Container & Secret Scanner")
        from scanner.engine import SecretScannerEngine

        sample_file = tmp_path / "app_config.py"
        sample_file.write_text(
            '# Production app config\n'
            'API_KEY = "AKIAIOSFODNN7EXAMPLE12"\n'
            'AWS_SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"\n',
            encoding="utf-8"
        )
        scanner_engine = SecretScannerEngine()
        summary = scanner_engine.scan_directory(tmp_path)
        print(f"  ✓ Secret Scanner found {len(summary.findings)} sensitive credential(s) in codebase.")
        for finding in summary.findings:
            print(f"    - [{finding.severity}] {finding.rule_id} at line {finding.line_number}: {finding.redacted_text}")

        # ---------------------------------------------------------
        # 2. Linux CIS Benchmark Hardening Audit
        # ---------------------------------------------------------
        print("\n[Step 2/7] 📋 Compliance: Linux CIS Benchmark Security Audit")
        from cis.scanner import CISScanner
        from cis.rules import get_all_rules

        rules = get_all_rules()
        cis_scanner = CISScanner(rules, suppress_root_warning=True)
        report = cis_scanner.audit()
        print(f"  ✓ Evaluated {report.total_rules} CIS Benchmark controls across system baseline.")
        print(f"  ✓ CIS Compliance Score: {report.score:.1f}% (Passed: {report.passed_rules}, Failed: {report.failed_rules})")

        # ---------------------------------------------------------
        # 3. Encrypted Zero-Knowledge Backup Orchestrator
        # ---------------------------------------------------------
        print("\n[Step 3/7] 🔐 Resilience: Encrypted Backup & Integrity Check (AES-256-GCM + Zstandard)")
        from backup.crypto import CryptoEngine
        from backup.compress import Compressor, CompressionAlgorithm

        data_payload = b"CRITICAL_SYSTEM_STATE_DATA_2026_ENTERPRISE_SNAPSHOT"
        comp = Compressor()
        comp_bytes, stats = comp.compress(data_payload, CompressionAlgorithm.ZSTD)
        encrypted_pkg = CryptoEngine.encrypt(comp_bytes, passphrase="VaultMasterKey2026!SecOps", iterations=1000)
        decrypted_comp = CryptoEngine.decrypt(encrypted_pkg, passphrase="VaultMasterKey2026!SecOps", iterations=1000)
        decrypted_data = comp.decompress(decrypted_comp, CompressionAlgorithm.ZSTD)
        
        assert decrypted_data == data_payload
        print(f"  ✓ Encrypted snapshot: {len(data_payload)} bytes -> compressed {len(comp_bytes)} bytes -> AES-256-GCM ciphertext.")
        print("  ✓ Cryptographic integrity & zero-knowledge roundtrip validated 100%.")

        # ---------------------------------------------------------
        # 4. Stream Log Aggregation & Grok Sanitization
        # ---------------------------------------------------------
        print("\n[Step 4/7] 📊 Observability: Stream Log Aggregator & PII Masking")
        from aggregator.transformers.sanitizer import PIISanitizer

        sanitizer = PIISanitizer()
        raw_log = '2026-08-28 14:00:00 [ERROR] User john.doe@enterprise.corp (IP: 192.168.1.50) auth failed with card 4532-1234-5678-9010'
        sanitized_log = sanitizer.sanitize_text(raw_log)
        print(f"  ✓ Original log:  {raw_log}")
        print(f"  ✓ Sanitized log: {sanitized_log}")

        # ---------------------------------------------------------
        # 5. SRE Multi-Window Multi-Burn-Rate SLO Engine
        # ---------------------------------------------------------
        print("\n[Step 5/7] ⏱️ SRE Engineering: Multi-Window Multi-Burn-Rate SLO Engine")
        from slo.burn_rate import calculate_burn_rate

        total_reqs = 60000
        bad_reqs = 1200
        good_reqs = total_reqs - bad_reqs
        burn_res = calculate_burn_rate(good_events=good_reqs, total_events=total_reqs, target_slo=0.99, window="1h")
        sli_val = (good_reqs / total_reqs) * 100.0
        print(f"  ✓ Evaluated 30-Day Target SLO: 99.00% | Current Window SLI: {sli_val:.2f}%")
        print(f"  ✓ Current Burn Rate: {burn_res.burn_rate:.2f}x (Threshold 14.4x for 1-hour critical pager)")

        # ---------------------------------------------------------
        # 6. SRE Watchdog Health Inspection & Self-Healing Circuit Breaker
        # ---------------------------------------------------------
        print("\n[Step 6/7] 🔄 Autonomous Resilience: Linux SRE Watchdog & Circuit Breaker")
        from watchdog.circuit_breaker import CircuitBreaker, CircuitBreakerConfig, CircuitBreakerState

        cb = CircuitBreaker(CircuitBreakerConfig(failure_threshold=3, window_seconds=300.0))
        action = "restart_auth_cluster"
        print(f"  ✓ Circuit Breaker initialized for '{action}': state={cb.get_state(action).value}")
        for _ in range(3):
            cb.record_failure(action, "Service timeout 504")
        print(f"  ✓ Simulated 3 consecutive subsystem faults -> Circuit state tripped: {cb.get_state(action).value} (Protected from flapping)")

        # ---------------------------------------------------------
        # 7. Blameless RCA Incident Postmortem Generation
        # ---------------------------------------------------------
        print("\n[Step 7/7] 📝 Governance: Automated Blameless Postmortem Incident Report")
        from postmortem.rca_engine import RCAEngine, ActionItem, ActionItemType, ActionItemPriority
        from postmortem.generator import PostmortemGenerator, IncidentReport, IncidentSeverity, IncidentStatus
        from postmortem.timeline_builder import TimelineBuilder, EventType

        builder = TimelineBuilder()
        builder.add_event(
            timestamp=datetime(2026, 8, 28, 14, 0, tzinfo=timezone.utc),
            event_type=EventType.INCIDENT_START,
            description="Elevated 5xx error rate detected on auth reverse proxy",
            source="reverse-proxy-limiter"
        )
        builder.add_event(
            timestamp=datetime(2026, 8, 28, 14, 2, tzinfo=timezone.utc),
            event_type=EventType.ALERT,
            description="SLO Burn Rate exceeded 14.4x on critical authentication service",
            source="slo-burnrate-engine"
        )
        builder.add_event(
            timestamp=datetime(2026, 8, 28, 14, 5, tzinfo=timezone.utc),
            event_type=EventType.RESOLVED,
            description="Watchdog triggered automated circuit breaker and rerouted traffic",
            source="linux-sre-watchdog"
        )
        timeline = builder.events
        metrics = builder.compute_metrics()

        rca = RCAEngine()
        rca.add_action_item(
            description="Scale connection pool and enforce circuit breaker threshold",
            item_type=ActionItemType.PREVENTATIVE,
            priority=ActionItemPriority.P1,
            owner="sre-infra"
        )
        rca_res = rca.generate_rca_result(
            trigger_event="Database connection pool saturation under traffic burst",
            root_cause_summary="Connection pool cap of 50 connections reached during campaign launch"
        )

        inc_report = IncidentReport(
            incident_id="INC-2026-0828",
            title="Authentication Cluster Latency Spike & Error Budget Burn",
            severity=IncidentSeverity.SEV_2.value,
            status=IncidentStatus.RESOLVED.value,
            date="2026-08-28",
            summary="Authentication service experienced transient latency spike mitigated by circuit breaker",
            user_impact="10% auth error rate for 5 minutes during traffic burst",
            timeline=timeline,
            metrics=metrics,
            rca=rca_res,
        )

        generator = PostmortemGenerator()
        doc = generator.render_markdown(inc_report)
        
        print("  ✓ Generated blameless postmortem report with Five-Whys & Action Items:")
        print(f"    - Incident ID: {inc_report.incident_id}")
        print(f"    - Severity:    {inc_report.severity}")
        print(f"    - Action Items: {len(inc_report.rca.action_items) if inc_report.rca else 0} preventative measures identified")

    print("\n" + "=" * 78)
    print("✅ DEVSECOPS & SRE RESILIENCE DEMONSTRATION COMPLETED SUCCESSFULLY (100% OPERATIONAL)")
    print("=" * 78)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="devsecops",
        description="Enterprise DevSecOps, SRE & Autonomous Resilience Toolkit (17 Modules)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "-v", "--version",
        action="version",
        version=f"%(prog)s {__version__}"
    )

    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")

    # Command registrations with aliases
    subparsers.add_parser("cis-audit", aliases=["cis", "cis-hardener"], help="Linux CIS Benchmark scanner & hardener", add_help=False)
    subparsers.add_parser("scan-secrets", aliases=["secrets", "secret-scanner"], help="Container & filesystem secret scanner", add_help=False)
    subparsers.add_parser("drift", aliases=["drift-detector"], help="Infrastructure state drift detector", add_help=False)
    subparsers.add_parser("backup", aliases=["backup-orchestrator"], help="Encrypted zero-knowledge backup orchestrator", add_help=False)
    subparsers.add_parser("proxy", aliases=["reverse-proxy"], help="Reverse proxy with rate limiting & circuit breaker", add_help=False)
    subparsers.add_parser("type-refactor", aliases=["refactorer"], help="LangGraph AST type coverage refactorer", add_help=False)
    subparsers.add_parser("code-healer", aliases=["healer"], help="LangGraph autonomous code & security healer", add_help=False)
    subparsers.add_parser("slo-check", aliases=["slo", "slo-engine"], help="SRE multi-window multi-burn-rate SLO engine", add_help=False)
    subparsers.add_parser("watchdog", aliases=["sre-watchdog"], help="Linux SRE health watchdog & remediation engine", add_help=False)
    subparsers.add_parser("inject-fault", aliases=["chaos"], help="Chaos engineering fault injector", add_help=False)
    subparsers.add_parser("metrics-exporter", aliases=["exporter", "metrics"], help="Prometheus metrics exporter & alert evaluator", add_help=False)
    subparsers.add_parser("log-aggregator", aliases=["aggregator", "logs"], help="Stream log aggregator & PII sanitizer", add_help=False)
    subparsers.add_parser("probe", aliases=["blackbox-prober"], help="Blackbox synthetic prober (HTTP, TCP, DNS, TLS)", add_help=False)
    subparsers.add_parser("deploy", aliases=["blue-green"], help="Zero-downtime blue/green deployment orchestrator", add_help=False)
    subparsers.add_parser("tracing", aliases=["profiler", "trace-profiler"], help="Distributed tracing profiler & OpenTelemetry exporter", add_help=False)
    subparsers.add_parser("ci-runner", aliases=["runner"], help="Lightweight DAG-based CI execution runner", add_help=False)
    subparsers.add_parser("postmortem", aliases=["rca-generator"], help="Automated blameless incident postmortem & RCA generator", add_help=False)
    subparsers.add_parser("demo", help="Run end-to-end multi-engine DevSecOps & SRE resilience demonstration", add_help=False)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Main CLI entrypoint router."""
    if argv is None:
        argv = sys.argv[1:]

    parser = build_parser()

    if not argv:
        parser.print_help()
        return 0

    cmd = argv[0]
    rest = list(argv[1:])

    # Route subcommands
    if cmd in ("cis-audit", "cis", "cis-hardener"):
        return _run_cis(rest)
    elif cmd in ("scan-secrets", "secrets", "secret-scanner"):
        return _run_secrets(rest)
    elif cmd in ("drift", "drift-detector"):
        return _run_drift(rest)
    elif cmd in ("backup", "backup-orchestrator"):
        return _run_backup(rest)
    elif cmd in ("proxy", "reverse-proxy"):
        return _run_proxy(rest)
    elif cmd in ("type-refactor", "refactorer"):
        return _run_type_refactor(rest)
    elif cmd in ("code-healer", "healer"):
        return _run_code_healer(rest)
    elif cmd in ("slo-check", "slo", "slo-engine"):
        return _run_slo(rest)
    elif cmd in ("watchdog", "sre-watchdog"):
        return _run_watchdog(rest)
    elif cmd in ("inject-fault", "chaos"):
        return _run_chaos(rest)
    elif cmd in ("metrics-exporter", "exporter", "metrics"):
        return _run_metrics(rest)
    elif cmd in ("log-aggregator", "aggregator", "logs"):
        return _run_logs(rest)
    elif cmd in ("probe", "blackbox-prober"):
        return _run_prober(rest)
    elif cmd in ("deploy", "blue-green"):
        return _run_deployer(rest)
    elif cmd in ("tracing", "profiler", "trace-profiler"):
        return _run_tracing(rest)
    elif cmd in ("ci-runner", "runner"):
        return _run_ci_runner(rest)
    elif cmd in ("postmortem", "rca-generator"):
        return _run_postmortem(rest)
    elif cmd == "demo":
        return _run_pipeline_demo()
    elif cmd in ("-v", "--version"):
        print(f"devsecops {__version__}")
        return 0
    elif cmd in ("-h", "--help"):
        parser.print_help()
        return 0
    else:
        print(f"Unknown command: '{cmd}'. Use 'devsecops --help' to see available tools.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
