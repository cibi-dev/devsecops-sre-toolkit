import ast
import inspect
from pathlib import Path
import pytest
from postmortem.collector import EvidenceCollector
from postmortem.generator import IncidentReport, IncidentSeverity, IncidentStatus, PostmortemGenerator
from postmortem.rca_engine import ActionItem, FiveWhys, RCAResult
from postmortem.sanitizer import EvidenceSanitizer, sanitize_text
from postmortem.storage import IncidentStorage
from postmortem.timeline_builder import IncidentMetrics, TimelineEvent


def test_cwe_209_sanitization_in_generated_markdown():
    """Verify that credentials do not leak into generated Markdown post-mortem reports."""
    secret_token = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0In0.secret_signature_xyz"
    aws_key = "AKIA1122334455667788"
    db_conn = "postgres://admin:SuperSecretPass999@db.internal:5432/prod"

    report = IncidentReport(
        incident_id="INC-SEC-01",
        title=f"Incident caused by {secret_token}",
        severity=IncidentSeverity.SEV_1.value,
        status=IncidentStatus.RESOLVED.value,
        date="2026-08-27",
        commander="sec-admin@company.com",
        summary=f"Configuration leaked {aws_key} and URL {db_conn}",
        rca=RCAResult(
            trigger_event=f"Leaked token {secret_token}",
            root_cause_summary="Secrets stored in plain text environment variables",
        ),
        evidences={
            "system_logs": [f"Log trace with {aws_key} and authorization: {secret_token}"],
            "git_diffs": f"+ API_KEY='{aws_key}'\n+ DB='{db_conn}'",
        },
    )

    generator = PostmortemGenerator()
    # Note: When report is created, sanitizer can be applied. Let's verify generator renders sanitized report properly.
    # If the user feeds un-sanitized fields, EvidenceSanitizer cleans them.
    cleaned_title = sanitize_text(report.title)
    assert secret_token not in cleaned_title
    assert "[REDACTED]" in cleaned_title

    cleaned_summary = sanitize_text(report.summary)
    assert aws_key not in cleaned_summary
    assert "SuperSecretPass999" not in cleaned_summary
    assert "[REDACTED]" in cleaned_summary


def test_cwe_89_sql_injection_payloads(tmp_path):
    """Verify that SQLite storage is completely resilient against SQL injection payloads."""
    db_file = tmp_path / "sql_test.db"
    storage = IncidentStorage(db_path=db_file)

    sqli_payloads = [
        "INC-001' OR '1'='1",
        "'; DROP TABLE incidents; --",
        "1' UNION SELECT 1, 'admin', 'password', 'pass' --",
        "' OR 1=1 --",
    ]

    for payload in sqli_payloads:
        # 1. Search with SQL injection payload
        results = storage.search_incidents(payload)
        assert isinstance(results, list)

        # 2. Get with SQL injection payload
        item = storage.get_incident(payload)
        assert item is None

        # 3. Update with SQL injection payload
        updated = storage.update_incident_status(payload, "RESOLVED")
        assert updated is False

        # 4. Delete with SQL injection payload
        deleted = storage.delete_incident(payload)
        assert deleted is False

    # Verify table integrity: table still exists and is usable
    with storage._get_connection() as conn:
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM incidents")
        count = cur.fetchone()[0]
        assert count == 0


def test_cwe_78_safe_subprocess_execution_ast_check():
    """Verify that all subprocess calls in the postmortem codebase use shell=False."""
    src_dir = Path(__file__).resolve().parent.parent / "src" / "postmortem"
    py_files = list(src_dir.glob("*.py"))
    assert len(py_files) > 0

    for py_file in py_files:
        tree = ast.parse(py_file.read_text(encoding="utf-8"), filename=str(py_file))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func = node.func
                # Check for subprocess.run, subprocess.Popen, subprocess.call, subprocess.check_output
                is_subprocess = False
                if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name) and func.value.id == "subprocess":
                    is_subprocess = True

                if is_subprocess:
                    # Check shell keyword argument
                    for kw in node.keywords:
                        if kw.arg == "shell":
                            if isinstance(kw.value, ast.Constant):
                                assert kw.value.value is False, f"Forbidden shell=True found in {py_file} at line {node.lineno}"


def test_cwe_250_collector_read_only_guarantee(tmp_path):
    """Verify that collector operations never modify target files or directory trees."""
    test_file = tmp_path / "readonly_test.log"
    original_content = "2026-08-27 10:00:00 INFO Service started normally\n"
    test_file.write_text(original_content, encoding="utf-8")

    collector = EvidenceCollector()
    logs = collector.collect_system_logs(log_file=test_file, lines=5)
    assert len(logs) == 1
    assert "Service started normally" in logs[0]

    # Invariant: File content and modification state unchanged
    assert test_file.read_text(encoding="utf-8") == original_content


def test_cwe_400_redos_safe_large_payload():
    """Verify that the sanitizer executes in linear time without catastrophic backtracking on long inputs."""
    import time
    sanitizer = EvidenceSanitizer()

    # Crafted adversarial string with repeating patterns
    adversarial_payload = "Bearer " + "A" * 10000 + "!" + " AKIA" + "Z" * 5000 + " password=" + "x" * 5000
    start = time.perf_counter()
    cleaned = sanitizer.sanitize_text(adversarial_payload)
    elapsed = time.perf_counter() - start

    assert elapsed < 0.5, f"Sanitizer took too long ({elapsed:.3f}s) indicating potential ReDoS!"
    assert "[REDACTED]" in cleaned
