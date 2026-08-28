"""Unit tests for the visual reporter (Text, Markdown, JSON, Diff)."""

from __future__ import annotations

import json
from pathlib import Path
import pytest

from drift.comparator import DriftItem, DriftResult, DriftSeverity, DriftType
from drift.reporter import DriftReporter


@pytest.fixture
def sample_clean_result() -> DriftResult:
    item = DriftItem(
        category="services",
        name="nginx",
        drift_type=DriftType.MATCH,
        severity=DriftSeverity.INFO,
        desired={"name": "nginx", "state": "running"},
        actual={"name": "nginx", "state": "running"},
        message="Service 'nginx' matches desired state",
    )
    return DriftResult(manifest_name="clean-host", items=[item])


@pytest.fixture
def sample_drift_result() -> DriftResult:
    item1 = DriftItem(
        category="files",
        name="/etc/shadow",
        drift_type=DriftType.MODIFIED,
        severity=DriftSeverity.CRITICAL,
        desired={"mode": "0600", "owner": "root"},
        actual={"mode": "0777", "owner": "root"},
        differences={"mode": ("0600", "0777")},
        unified_diff="--- desired//etc/shadow\n+++ live//etc/shadow\n-mode: 0600\n+mode: 0777",
        message="File '/etc/shadow' permissions drifted",
    )
    item2 = DriftItem(
        category="ports",
        name="tcp/23 (0.0.0.0)",
        drift_type=DriftType.UNEXPECTED,
        severity=DriftSeverity.HIGH,
        desired={"state": "closed"},
        actual={"state": "listening"},
        message="Port tcp/23 is open but expected closed",
    )
    return DriftResult(manifest_name="drifted-host", items=[item1, item2])


class TestDriftReporter:
    def test_text_report_clean(self, sample_clean_result: DriftResult):
        output = DriftReporter.to_text(sample_clean_result)
        assert "NO DRIFT DETECTED" in output
        assert "Checked: 1" in output
        assert "Matches: 1" in output
        assert "All inspected infrastructure components match" in output

    def test_text_report_drifted(self, sample_drift_result: DriftResult):
        output = DriftReporter.to_text(sample_drift_result)
        assert "DRIFT DETECTED" in output
        assert "CATEGORY: FILES" in output
        assert "[CRITICAL]" in output
        assert "/etc/shadow" in output
        assert "-mode: 0600" in output

    def test_markdown_report_clean(self, sample_clean_result: DriftResult):
        md = DriftReporter.to_markdown(sample_clean_result)
        assert "Drift-CLEAN-success" in md
        assert "> [!NOTE]" in md
        assert "100% In-Sync" in md

    def test_markdown_report_drifted(self, sample_drift_result: DriftResult):
        md = DriftReporter.to_markdown(sample_drift_result)
        assert "Drift-DETECTED-critical" in md
        assert "> [!WARNING]" in md
        assert "🚨 CRITICAL" in md
        assert "<details><summary>" in md
        assert "```diff" in md

    def test_json_report(self, sample_drift_result: DriftResult):
        json_str = DriftReporter.to_json(sample_drift_result)
        data = json.loads(json_str)
        assert data["manifest_name"] == "drifted-host"
        assert data["drift_detected"] is True
        assert data["summary"]["drifts"] == 2
        assert data["summary"]["severity_counts"]["critical"] == 1
        assert len(data["items"]) == 2

    def test_unified_diff_output(self, sample_drift_result: DriftResult):
        diff = DriftReporter.to_unified_diff(sample_drift_result)
        assert "--- desired//etc/shadow" in diff
        assert "+mode: 0777" in diff

    def test_secret_sanitization_in_reporter(self):
        mock_sk = "sk-" + "abcdef123456789012345678"
        mock_gh = "ghp_" + "1234567890abcdefghijklmnopqrstuvwxyz"
        item = DriftItem(
            category="files",
            name="/etc/app.env",
            drift_type=DriftType.MODIFIED,
            severity=DriftSeverity.MEDIUM,
            desired={"content": "password: SuperSecretPassword123!"},
            actual={"content": "password: LivePassword999!"},
            unified_diff=f"custom_key: {mock_sk}\naccess_token: {mock_gh}",
            message=f"Token {mock_gh} changed",
        )
        res = DriftResult(manifest_name="secret-test", items=[item])

        text_out = DriftReporter.to_text(res)
        assert mock_sk not in text_out
        assert mock_gh not in text_out
        assert "[REDACTED" in text_out

        md_out = DriftReporter.to_markdown(res)
        assert mock_sk not in md_out
        assert mock_gh not in md_out

        json_out = DriftReporter.to_json(res)
        assert mock_sk not in json_out
