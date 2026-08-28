"""Unit tests for SARIF v2.1.0 exporter and OASIS schema compliance."""

import json
from pathlib import Path
from scanner.engine import Finding, ScanSummary
from scanner.reporters.sarif import (
    _map_severity_to_sarif_level,
    _map_severity_to_score,
    export_sarif,
    generate_sarif_dict,
)


def test_severity_mappers():
    """Verify SARIF level and score mappings for all severity levels."""
    assert _map_severity_to_sarif_level("CRITICAL") == "error"
    assert _map_severity_to_sarif_level("HIGH") == "error"
    assert _map_severity_to_sarif_level("MEDIUM") == "warning"
    assert _map_severity_to_sarif_level("LOW") == "note"
    assert _map_severity_to_sarif_level("OTHER") == "note"

    assert _map_severity_to_score("CRITICAL") == "9.0"
    assert _map_severity_to_score("HIGH") == "7.5"
    assert _map_severity_to_score("MEDIUM") == "5.0"
    assert _map_severity_to_score("LOW") == "2.0"
    assert _map_severity_to_score("UNKNOWN") == "2.0"


def test_generate_sarif_dict_structure():
    """Verify SARIF schema conformance for empty scan."""
    summary = ScanSummary(
        files_scanned=5,
        bytes_scanned=1024,
        findings=[],
        duration_seconds=0.05,
    )
    sarif = generate_sarif_dict(summary)

    assert sarif["version"] == "2.1.0"
    assert "sarif-schema-2.1.0.json" in sarif["$schema"]
    assert len(sarif["runs"]) == 1

    driver = sarif["runs"][0]["tool"]["driver"]
    assert driver["name"] == "container-secret-scanner"
    assert driver["version"] == "0.1.0"
    assert len(driver["rules"]) >= 30
    assert sarif["runs"][0]["results"] == []


def test_generate_sarif_dict_with_findings():
    """Verify SARIF results mapping and data sanitization."""
    finding = Finding(
        rule_id="RULE-AWS-AKIA",
        rule_name="AWS Access Key ID",
        file_path="src/aws_client.py",
        line_number=10,
        column_number=5,
        matched_text="AKIA" + "IOSFODNN7EXAMPLE",
        redacted_text="[REDACTED]...MPLE",
        entropy=4.1,
        severity="HIGH",
        cwe_id="CWE-798",
        category="Cloud Providers",
        context_line="aws_key = '[REDACTED]...MPLE'",
    )
    summary = ScanSummary(
        files_scanned=1,
        bytes_scanned=500,
        findings=[finding],
        duration_seconds=0.01,
    )

    sarif = generate_sarif_dict(summary)
    results = sarif["runs"][0]["results"]
    assert len(results) == 1

    res = results[0]
    assert res["ruleId"] == "RULE-AWS-AKIA"
    assert res["level"] == "error"
    assert "src/aws_client.py" in res["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert res["locations"][0]["physicalLocation"]["region"]["startLine"] == 10

    # Ensure raw secret is not leaked in message
    assert "AKIAIOSFODNN7" not in res["message"]["text"]
    assert "[REDACTED]" in res["message"]["text"]


def test_generate_sarif_with_ast_rule():
    """SARIF report correctly includes dynamically added AST rule definitions."""
    finding = Finding(
        rule_id="RULE-AST-HARDCODED-SECRET",
        rule_name="Hardcoded Secret Assignment",
        file_path="main.py",
        line_number=5,
        column_number=1,
        matched_text="secret1234567890",
        redacted_text="[REDACTED]...7890",
        entropy=4.2,
        severity="HIGH",
        cwe_id="CWE-798",
        category="Static Code Analysis",
        context_line="secret = '[REDACTED]...7890'",
    )
    summary = ScanSummary(
        files_scanned=1,
        bytes_scanned=100,
        findings=[finding],
        duration_seconds=0.01,
    )
    sarif = generate_sarif_dict(summary)
    rules = sarif["runs"][0]["tool"]["driver"]["rules"]
    assert any(r["id"] == "RULE-AST-HARDCODED-SECRET" for r in rules)


def test_export_sarif_file_writing(tmp_path: Path):
    """export_sarif serializes and writes JSON file to disk."""
    out_file = tmp_path / "output" / "scan-report.sarif"
    summary = ScanSummary(
        files_scanned=2,
        bytes_scanned=200,
        findings=[],
        duration_seconds=0.02,
    )

    json_str = export_sarif(summary, output_path=out_file)
    assert out_file.exists()

    parsed = json.loads(out_file.read_text(encoding="utf-8"))
    assert parsed["version"] == "2.1.0"
    assert parsed == json.loads(json_str)
