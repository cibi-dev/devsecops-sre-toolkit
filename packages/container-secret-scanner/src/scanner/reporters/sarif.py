"""SARIF v2.1.0 report generator compatible with GitHub Advanced Security and Code Scanning."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Union

from scanner.engine import Finding, ScanSummary
from scanner.rules import DEFAULT_RULES, SecretRule


SARIF_SCHEMA_URI = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
TOOL_NAME = "container-secret-scanner"
TOOL_VERSION = "0.1.0"
TOOL_INFO_URI = "https://github.com/cibi-dev/container-secret-scanner"


def _map_severity_to_sarif_level(severity: str) -> str:
    """Map tool severity string to SARIF level string."""
    sev = severity.upper()
    if sev in ("CRITICAL", "HIGH"):
        return "error"
    if sev == "MEDIUM":
        return "warning"
    return "note"


def _map_severity_to_score(severity: str) -> str:
    """Map tool severity string to numeric security-severity string for GitHub Code Scanning."""
    sev = severity.upper()
    if sev == "CRITICAL":
        return "9.0"
    if sev == "HIGH":
        return "7.5"
    if sev == "MEDIUM":
        return "5.0"
    return "2.0"


def generate_sarif_dict(summary: ScanSummary, rules: Union[List[SecretRule], None] = None) -> Dict[str, Any]:
    """Generate a valid OASIS SARIF v2.1.0 report dictionary.

    Args:
        summary: ScanSummary object containing discovered findings.
        rules: Optional list of rules used in scanning (defaults to DEFAULT_RULES).

    Returns:
        Dictionary adhering to SARIF v2.1.0 JSON schema.
    """
    rule_catalog = list(rules or DEFAULT_RULES)

    # Build SARIF driver rules list
    sarif_rules: List[Dict[str, Any]] = []
    rule_id_to_index: Dict[str, int] = {}

    for idx, rule in enumerate(rule_catalog):
        rule_id_to_index[rule.rule_id] = idx
        cwe_num = rule.cwe_id.replace("CWE-", "").strip() if rule.cwe_id.startswith("CWE-") else "798"
        sarif_rules.append(
            {
                "id": rule.rule_id,
                "name": rule.name.replace(" ", ""),
                "shortDescription": {"text": rule.name},
                "fullDescription": {"text": rule.description},
                "defaultConfiguration": {
                    "level": _map_severity_to_sarif_level(rule.severity)
                },
                "helpUri": f"https://cwe.mitre.org/data/definitions/{cwe_num}.html",
                "properties": {
                    "tags": ["security", "secret-detection", rule.cwe_id.lower()],
                    "precision": "high",
                    "security-severity": _map_severity_to_score(rule.severity),
                },
            }
        )

    # If there are AST findings with rule_id not in catalog, add it
    ast_rule_id = "RULE-AST-HARDCODED-SECRET"
    if ast_rule_id not in rule_id_to_index:
        idx = len(sarif_rules)
        rule_id_to_index[ast_rule_id] = idx
        sarif_rules.append(
            {
                "id": ast_rule_id,
                "name": "HardcodedSecretAssignment",
                "shortDescription": {"text": "Hardcoded Credential Assignment"},
                "fullDescription": {
                    "text": "Detects sensitive variable or parameter assignments in Python AST (CWE-798)."
                },
                "defaultConfiguration": {"level": "error"},
                "helpUri": "https://cwe.mitre.org/data/definitions/798.html",
                "properties": {
                    "tags": ["security", "secret-detection", "cwe-798"],
                    "precision": "high",
                    "security-severity": "8.0",
                },
            }
        )

    # Build SARIF results
    results: List[Dict[str, Any]] = []
    for finding in summary.findings:
        level = _map_severity_to_sarif_level(finding.severity)
        rule_idx = rule_id_to_index.get(finding.rule_id, 0)

        # Normalize relative artifact URI for SARIF
        artifact_uri = finding.file_path.replace("\\", "/")

        result_item: Dict[str, Any] = {
            "ruleId": finding.rule_id,
            "ruleIndex": rule_idx,
            "level": level,
            "message": {
                "text": f"Potential {finding.rule_name} detected ({finding.redacted_text}) [CWE: {finding.cwe_id}]"
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": artifact_uri,
                        },
                        "region": {
                            "startLine": max(1, finding.line_number),
                            "startColumn": max(1, finding.column_number),
                            "snippet": {
                                "text": finding.context_line
                            },
                        },
                    }
                }
            ],
            "properties": {
                "cwe": finding.cwe_id,
                "entropy": finding.entropy,
                "redacted_token": finding.redacted_text,
                "severity": finding.severity,
            },
        }
        results.append(result_item)

    sarif_doc: Dict[str, Any] = {
        "$schema": SARIF_SCHEMA_URI,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": TOOL_NAME,
                        "version": TOOL_VERSION,
                        "informationUri": TOOL_INFO_URI,
                        "rules": sarif_rules,
                    }
                },
                "results": results,
                "invocations": [
                    {
                        "executionSuccessful": len(summary.errors) == 0,
                    }
                ],
            }
        ],
    }

    return sarif_doc


def export_sarif(
    summary: ScanSummary,
    output_path: Union[str, Path, None] = None,
    rules: Union[List[SecretRule], None] = None,
    indent: int = 2,
) -> str:
    """Generate and optionally save SARIF JSON formatted report.

    Args:
        summary: Scan summary results.
        output_path: Optional file path to write the JSON to.
        rules: Optional rules list.
        indent: JSON indentation.

    Returns:
        Serialized JSON string.
    """
    sarif_data = generate_sarif_dict(summary, rules=rules)
    json_str = json.dumps(sarif_data, indent=indent)

    if output_path:
        out_p = Path(output_path)
        out_p.parent.mkdir(parents=True, exist_ok=True)
        out_p.write_text(json_str, encoding="utf-8")

    return json_str
