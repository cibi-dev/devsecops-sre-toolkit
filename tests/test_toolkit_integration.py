"""
Comprehensive Integration Test Suite for DevSecOps & SRE Resilience Toolkit.

Validates end-to-end functionality, CLI subcommands routing, and individual
engine operations across all 17 consolidated modules.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import io
from pathlib import Path
import sys
import tempfile
import pytest

# Ensure toolkit and subpackages are in pythonpath
_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

import cli


# ==============================================================================
# CLI Entrypoint & Routing Tests
# ==============================================================================

def test_cli_version(capsys: pytest.CaptureFixture[str]) -> None:
    """Test CLI version command."""
    code = cli.main(["--version"])
    assert code == 0
    captured = capsys.readouterr()
    assert "devsecops 1.0.0" in captured.out


def test_cli_help(capsys: pytest.CaptureFixture[str]) -> None:
    """Test CLI help output without arguments and with --help."""
    code = cli.main([])
    assert code == 0
    captured = capsys.readouterr()
    assert "Enterprise DevSecOps, SRE & Autonomous Resilience Toolkit" in captured.out

    code = cli.main(["--help"])
    assert code == 0
    captured = capsys.readouterr()
    assert "demo" in captured.out


def test_cli_unknown_command(capsys: pytest.CaptureFixture[str]) -> None:
    """Test CLI response on unknown subcommand."""
    code = cli.main(["nonexistent-cmd"])
    assert code == 1
    captured = capsys.readouterr()
    assert "Unknown command" in captured.err


def test_cli_all_17_subcommands_dispatch() -> None:
    """Verify all 17 subcommands are properly mapped and callable."""
    subcommands = [
        "cis-audit", "scan-secrets", "drift", "backup", "proxy",
        "type-refactor", "code-healer", "slo-check", "watchdog", "inject-fault",
        "metrics-exporter", "log-aggregator", "probe", "deploy", "tracing",
        "ci-runner", "postmortem"
    ]
    for cmd in subcommands:
        with pytest.raises(SystemExit) as excinfo:
            cli.main([cmd, "--help"])
        assert excinfo.value.code == 0


def test_cli_pipeline_demo(capsys: pytest.CaptureFixture[str]) -> None:
    """Verify full end-to-end multi-engine DevSecOps & SRE resilience demonstration."""
    code = cli.main(["demo"])
    assert code == 0
    captured = capsys.readouterr()
    assert "DEVSECOPS & SRE TOOLKIT - ENTERPRISE MULTI-ENGINE RESILIENCE PIPELINE" in captured.out
    assert "Security Audit: Container & Secret Scanner" in captured.out
    assert "Compliance: Linux CIS Benchmark Security Audit" in captured.out
    assert "Resilience: Encrypted Backup & Integrity Check" in captured.out
    assert "Observability: Stream Log Aggregator & PII Masking" in captured.out
    assert "SRE Engineering: Multi-Window Multi-Burn-Rate SLO Engine" in captured.out
    assert "Autonomous Resilience: Linux SRE Watchdog & Circuit Breaker" in captured.out
    assert "Governance: Automated Blameless Postmortem Incident Report" in captured.out
    assert "COMPLETED SUCCESSFULLY (100% OPERATIONAL)" in captured.out


# ==============================================================================
# Security & Compliance Modules Tests
# ==============================================================================

def test_secret_scanner_integration() -> None:
    """Validate SecretScannerEngine regex & AST secret detection."""
    from scanner.engine import SecretScannerEngine

    with tempfile.TemporaryDirectory() as tmpdir:
        test_file = Path(tmpdir) / "credentials.py"
        test_file.write_text(
            'AWS_KEY = "AKIAIOSFODNN7EXAMPLE12"\n'
            'SECRET = "super_secret_token_123456789"\n',
            encoding="utf-8"
        )
        engine = SecretScannerEngine()
        summary = engine.scan_directory(tmpdir)
        assert summary.files_scanned >= 1
        assert len(summary.findings) >= 1
        assert any("RULE-AST-HARDCODED-SECRET" in f.rule_id or "RULE-" in f.rule_id for f in summary.findings)


def test_cis_hardener_integration() -> None:
    """Validate CISScanner audit report generation and score calculation."""
    from cis.scanner import CISScanner
    from cis.rules import get_all_rules

    rules = get_all_rules()
    assert len(rules) > 0
    scanner = CISScanner(rules, suppress_root_warning=True)
    report = scanner.audit()
    assert report.total_rules == len(rules)
    assert 0.0 <= report.score <= 100.0
    assert report.passed_rules + report.failed_rules + report.skipped_rules + report.error_rules == report.total_rules


def test_infra_drift_detector_integration() -> None:
    """Validate drift detector schema and comparison engine."""
    from drift.schema import Manifest, UserDesired
    from drift.comparator import DriftComparator

    manifest = Manifest(users=[UserDesired(name="nonexistent_audit_user_99", uid=9999)])
    comparator = DriftComparator()
    diff = comparator.compare(manifest)
    assert diff.drift_detected is True
    assert len(diff.drift_items) > 0


def test_encrypted_backup_orchestrator_integration() -> None:
    """Validate AES-256-GCM + Zstandard backup encryption roundtrip."""
    from backup.crypto import CryptoEngine
    from backup.compress import Compressor, CompressionAlgorithm

    payload = b"CRITICAL_DATA_BACKUP_SNAPSHOT_" * 50
    comp = Compressor()
    comp_bytes, stats = comp.compress(payload, CompressionAlgorithm.ZSTD)
    assert len(comp_bytes) < len(payload)

    passphrase = "SecurePassphrase2026!"
    encrypted = CryptoEngine.encrypt(comp_bytes, passphrase=passphrase, iterations=1000)
    decrypted_comp = CryptoEngine.decrypt(encrypted, passphrase=passphrase, iterations=1000)
    decompressed = comp.decompress(decrypted_comp, CompressionAlgorithm.ZSTD)
    assert decompressed == payload


# ==============================================================================
# SRE, Traffic & Resilience Modules Tests
# ==============================================================================

def test_slo_burnrate_engine_integration() -> None:
    """Validate Google SRE Multi-Burn-Rate formulation."""
    from slo.burn_rate import calculate_burn_rate

    # SLO = 99.0%, 1000 total, 10 errors -> 1.0% observed error rate -> Burn Rate = 1.0x
    res = calculate_burn_rate(good_events=990, total_events=1000, target_slo=0.99, window="1h")
    assert pytest.approx(res.burn_rate, 0.01) == 1.0
    assert res.time_to_exhaustion_days is not None
    assert pytest.approx(res.time_to_exhaustion_days, 0.1) == 30.0

    # Critical burn rate: 14.4x
    res_critical = calculate_burn_rate(good_events=856, total_events=1000, target_slo=0.99, window="1h")
    assert res_critical.burn_rate >= 14.4


def test_linux_sre_watchdog_circuit_breaker() -> None:
    """Validate watchdog anti-flapping circuit breaker state transitions."""
    from watchdog.circuit_breaker import CircuitBreaker, CircuitBreakerConfig, CircuitBreakerState

    config = CircuitBreakerConfig(failure_threshold=3, window_seconds=60.0, cooldown_seconds=0.1)
    cb = CircuitBreaker(config=config)
    action = "restart_nginx"

    assert cb.get_state(action) == CircuitBreakerState.CLOSED
    assert cb.can_execute(action) is True

    cb.record_failure(action, "failed 1")
    cb.record_failure(action, "failed 2")
    assert cb.get_state(action) == CircuitBreakerState.CLOSED

    cb.record_failure(action, "failed 3")
    assert cb.get_state(action) == CircuitBreakerState.OPEN
    assert cb.can_execute(action) is False


def test_stream_log_sanitizer_integration() -> None:
    """Validate PII and sensitive data masking in log stream."""
    from aggregator.transformers.sanitizer import PIISanitizer

    sanitizer = PIISanitizer()
    raw = "User admin@corp.internal from 10.0.0.1 token Bearer secret_abc_123 CC 4111-2222-3333-4444"
    clean = sanitizer.sanitize_text(raw)
    assert "admin@corp.internal" not in clean
    assert "10.0.0.1" not in clean
    assert "secret_abc_123" not in clean
    assert "4111-2222-3333-4444" not in clean
    assert "[REDACTED]" in clean


def test_postmortem_incident_generator_integration() -> None:
    """Validate blameless RCA and postmortem document generation."""
    from postmortem.rca_engine import RCAEngine, ActionItem, ActionItemType, ActionItemPriority
    from postmortem.generator import PostmortemGenerator, IncidentReport, IncidentSeverity, IncidentStatus
    from postmortem.timeline_builder import TimelineBuilder, EventType

    builder = TimelineBuilder()
    builder.add_event(datetime(2026, 8, 28, 12, 0, tzinfo=timezone.utc), EventType.INCIDENT_START, "Outage started")
    builder.add_event(datetime(2026, 8, 28, 12, 5, tzinfo=timezone.utc), EventType.RESOLVED, "Outage resolved")
    timeline = builder.events
    metrics = builder.compute_metrics()

    rca = RCAEngine()
    rca.add_action_item(ActionItem(
        id="ACT-100",
        description="Add automated canary rollout",
        item_type=ActionItemType.PREVENTATIVE.value,
        priority=ActionItemPriority.P0.value,
        owner="deploy-team"
    ))
    rca_res = rca.generate_rca_result(
        trigger_event="Config typo deployed to production",
        root_cause_summary="Missing pre-flight schema validation"
    )

    report = IncidentReport(
        incident_id="INC-2026-001",
        title="Production Configuration Outage",
        severity=IncidentSeverity.SEV_1.value,
        status=IncidentStatus.RESOLVED.value,
        date="2026-08-28",
        summary="Service interrupted due to invalid configuration",
        user_impact="Users saw 500 error for 5 minutes",
        timeline=timeline,
        metrics=metrics,
        rca=rca_res,
    )

    gen = PostmortemGenerator()
    md = gen.render_markdown(report)
    assert "# 📋 Post-Mortem Report: Production Configuration Outage" in md
    assert "INC-2026-001" in md
    assert "Add automated canary rollout" in md


def test_reverse_proxy_limiter_integration() -> None:
    """Validate token bucket rate limiter and circuit breaker in proxy."""
    from proxy.limiter import TokenBucketLimiter

    limiter = TokenBucketLimiter(rate=5.0, capacity=5.0)
    for _ in range(5):
        res = limiter.acquire("client-ip-1")
        assert res.allowed is True
    # 6th request immediately should be rejected
    res = limiter.acquire("client-ip-1")
    assert res.allowed is False


def test_chaos_safety_guard_integration() -> None:
    """Validate chaos fault injector safety guardrails."""
    from chaos.safety_guard import validate_target_process_name, ProtectedTargetError

    # Safe user process name
    validate_target_process_name("custom_worker_service")

    # Protected system process name must raise ProtectedTargetError
    with pytest.raises(ProtectedTargetError):
        validate_target_process_name("systemd")


def test_synthetic_blackbox_prober_integration() -> None:
    """Validate synthetic prober probe definition and execution."""
    from prober.probes.tcp import TCPProbe

    probe = TCPProbe(default_timeout=0.1)
    result = asyncio.run(probe.probe(host="127.0.0.1", port=65432))
    assert result.host == "127.0.0.1"
    assert result.port == 65432
    assert result.latency_ms >= 0.0


def test_blue_green_deployer_integration() -> None:
    """Validate blue/green deployer router state machine."""
    from deployer.router import TrafficRouter
    from deployer.config import DeployerConfig

    router = TrafficRouter(allow_unprivileged=True)
    cfg = DeployerConfig(blue_host="127.0.0.1", blue_port=8001, green_host="127.0.0.1", green_port=8002)
    slot = router.get_active_slot(cfg)
    assert slot is None or slot.value in ("blue", "green")


def test_distributed_tracing_integration() -> None:
    """Validate OpenTelemetry span creation and context propagation."""
    from tracing.span import Span
    from tracing.context import SpanContext

    ctx = SpanContext(trace_id="4bf92f3577b34da6a3ce929d0e0e4736", span_id="00f067aa0ba902b7")
    span = Span(name="auth_request", context=ctx)
    span.set_attribute("http.status_code", 200)
    span.end()
    assert span.is_ended is True
    assert span.duration_ms >= 0.0


def test_ci_runner_dag_integration() -> None:
    """Validate lightweight CI runner DAG step dependencies."""
    from runner.dag import DAG, JobDefinition

    dag = DAG()
    dag.add_job(JobDefinition(name="lint", original_name="lint", stage="test", script=["echo lint"]))
    dag.add_job(JobDefinition(name="test", original_name="test", stage="test", script=["echo test"], needs=["lint"]))
    layers = dag.get_execution_layers()
    assert len(layers) >= 1
    job_names = [j.name for layer in layers for j in layer]
    assert "lint" in job_names and "test" in job_names


def test_langgraph_healer_and_refactorer_modules_integration() -> None:
    """Validate LangGraph healer and refactorer state and graph structures."""
    from healer.state import CodePatchState
    from refactorer.state import RefactorState

    h_state = CodePatchState(source_code="def add(a, b): return a + b", file_path="calc.py", target_cwe="CWE-89")
    assert h_state["file_path"] == "calc.py"

    r_state = RefactorState(target_path="math_utils.py", source_code="def foo(): pass")
    assert r_state.target_path == "math_utils.py"
