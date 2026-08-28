"""Unit tests for the CLI subcommands and return codes."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch
import pytest

from drift.cli import main
from drift.comparator import DriftItem, DriftResult, DriftSeverity, DriftType


@pytest.fixture
def valid_manifest_file(tmp_path: Path) -> Path:
    f = tmp_path / "valid.yaml"
    content = """
    name: bastion-host
    version: '1.0'
    users:
      - name: root
        state: present
    services:
      - name: systemd-journald
        state: running
    sysctl:
      - key: net.ipv4.ip_forward
        value: 1
    ports:
      - port: 22
        protocol: tcp
        state: listening
    files:
      - path: /etc/hosts
        mode: '0644'
        state: present
    packages:
      - name: coreutils
        state: present
    """
    f.write_text(content, encoding="utf-8")
    return f


@pytest.fixture
def invalid_manifest_file(tmp_path: Path) -> Path:
    f = tmp_path / "invalid.yaml"
    f.write_text("invalid: [yaml: syntax: error", encoding="utf-8")
    return f


class TestCLI:
    def test_cli_validate_success(self, valid_manifest_file: Path, capsys: pytest.CaptureFixture[str]):
        ret = main(["validate", str(valid_manifest_file)])
        assert ret == 0
        captured = capsys.readouterr()
        assert "Manifest 'bastion-host' is valid" in captured.out

    def test_cli_validate_failure(self, invalid_manifest_file: Path, capsys: pytest.CaptureFixture[str]):
        ret = main(["validate", str(invalid_manifest_file)])
        assert ret == 2
        captured = capsys.readouterr()
        assert "validation failed" in captured.err

    def test_cli_audit_text_format(
        self, valid_manifest_file: Path, capsys: pytest.CaptureFixture[str]
    ):
        ret = main(["audit", str(valid_manifest_file), "--format", "text"])
        assert ret == 0
        captured = capsys.readouterr()
        assert "INFRASTRUCTURE DRIFT REPORT" in captured.out

    def test_cli_audit_json_format(
        self, valid_manifest_file: Path, capsys: pytest.CaptureFixture[str]
    ):
        ret = main(["audit", str(valid_manifest_file), "--format", "json"])
        assert ret == 0
        captured = capsys.readouterr()
        parsed = json.loads(captured.out)
        assert "manifest_name" in parsed
        assert "summary" in parsed

    def test_cli_audit_markdown_format(
        self, valid_manifest_file: Path, capsys: pytest.CaptureFixture[str]
    ):
        ret = main(["audit", str(valid_manifest_file), "--format", "markdown"])
        assert ret == 0
        captured = capsys.readouterr()
        assert "# 🛡️ Infrastructure Drift Audit Report" in captured.out

    def test_cli_audit_output_to_file(self, valid_manifest_file: Path, tmp_path: Path):
        out_file = tmp_path / "report.json"
        ret = main(["audit", str(valid_manifest_file), "--format", "json", "-o", str(out_file)])
        assert ret == 0
        assert out_file.exists()
        parsed = json.loads(out_file.read_text(encoding="utf-8"))
        assert parsed["manifest_name"] == "bastion-host"

    def test_cli_audit_exit_code_on_drift(self, valid_manifest_file: Path):
        mock_drift_item = DriftItem(
            category="files",
            name="/etc/hosts",
            drift_type=DriftType.MODIFIED,
            severity=DriftSeverity.HIGH,
            desired={"mode": "0644"},
            actual={"mode": "0777"},
            message="Mode mismatch",
        )
        mock_result = DriftResult("bastion-host", [mock_drift_item])

        with patch("drift.cli.DriftComparator.compare", return_value=mock_result):
            # Without --exit-code -> returns 0
            assert main(["audit", str(valid_manifest_file)]) == 0
            # With --exit-code -> returns 1
            assert main(["audit", str(valid_manifest_file), "--exit-code"]) == 1

    def test_cli_diff_subcommand(self, valid_manifest_file: Path, capsys: pytest.CaptureFixture[str]):
        mock_drift_item = DriftItem(
            category="sysctl",
            name="net.ipv4.ip_forward",
            drift_type=DriftType.MODIFIED,
            severity=DriftSeverity.MEDIUM,
            desired={"value": "1"},
            actual={"value": "0"},
            unified_diff="--- desired/net.ipv4.ip_forward\n+++ live/net.ipv4.ip_forward\n-value: 1\n+value: 0",
        )
        mock_result = DriftResult("bastion-host", [mock_drift_item])

        with patch("drift.cli.DriftComparator.compare", return_value=mock_result):
            ret = main(["diff", str(valid_manifest_file)])
            assert ret == 1
            captured = capsys.readouterr()
            assert "--- desired/net.ipv4.ip_forward" in captured.out

    def test_cli_report_subcommand(self, valid_manifest_file: Path, tmp_path: Path):
        out_md = tmp_path / "pr_report.md"
        ret = main(["report", str(valid_manifest_file), "-o", str(out_md)])
        assert ret == 0
        assert out_md.exists()
        assert "# 🛡️ Infrastructure Drift Audit Report" in out_md.read_text(encoding="utf-8")

    def test_cli_missing_file_error(self, capsys: pytest.CaptureFixture[str]):
        ret = main(["audit", "nonexistent_file_path.yaml"])
        assert ret == 2
        captured = capsys.readouterr()
        assert "Error reading manifest" in captured.err
