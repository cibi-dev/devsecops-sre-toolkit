"""Unit tests for the CLI subcommands and options."""

import json
import os
import pytest
from unittest.mock import patch

from cis.cli import main
from cis.rules.base import safe_write_file


@pytest.fixture
def cli_sandbox(tmp_path):
    root = tmp_path / "cli_root"
    root.mkdir()
    (root / "etc").mkdir()
    (root / "etc" / "ssh").mkdir()
    (root / "etc" / "sysctl.d").mkdir()
    return str(root)


def test_cli_rules_subcommand(capsys):
    ret = main(["rules"])
    assert ret == 0
    captured = capsys.readouterr()
    assert "Registered CIS Benchmark Level 1 Rules" in captured.out
    assert "CIS-SSH-001" in captured.out

    # JSON mode
    ret_json = main(["rules", "--json"])
    assert ret_json == 0
    captured_json = capsys.readouterr()
    data = json.loads(captured_json.out)
    assert isinstance(data, list)
    assert any(r["rule_id"] == "CIS-SSH-001" for r in data)


def test_cli_audit_subcommand(cli_sandbox, tmp_path, capsys):
    out_file = str(tmp_path / "report.json")

    # Audit with json output file
    ret = main(["audit", "--root-prefix", cli_sandbox, "--format", "json", "--output", out_file])
    assert ret == 0
    assert os.path.exists(out_file)

    with open(out_file, "r") as f:
        data = json.load(f)
    assert "score" in data
    assert "results" in data

    # Audit markdown output
    ret_md = main(["audit", "--root-prefix", cli_sandbox, "--format", "markdown"])
    assert ret_md == 0
    captured_md = capsys.readouterr()
    assert "# 🛡️ CIS Benchmark Level 1 Audit Report" in captured_md.out

    # Fail under threshold
    ret_fail = main(["audit", "--root-prefix", cli_sandbox, "--fail-under", "99.0"])
    assert ret_fail == 1


def test_cli_remediate_and_rollback_subcommand(cli_sandbox, capsys):
    # Remediation in dry run
    ret_dry = main([
        "remediate",
        "--root-prefix", cli_sandbox,
        "--dry-run",
        "--no-root-check",
    ])
    assert ret_dry == 0
    cap_dry = capsys.readouterr()
    assert "[DRY-RUN SIMULATION]" in cap_dry.out

    # Active remediation
    ret_act = main([
        "remediate",
        "--root-prefix", cli_sandbox,
        "--no-root-check",
    ])
    assert ret_act == 0

    # List rollback sessions
    ret_list = main(["rollback", "--root-prefix", cli_sandbox, "--list", "--no-root-check"])
    assert ret_list == 0
    cap_list = capsys.readouterr()
    assert "Available Backup Sessions" in cap_list.out

    # Perform rollback
    ret_rb = main(["rollback", "--root-prefix", cli_sandbox, "--no-root-check"])
    assert ret_rb == 0


def test_cli_report_subcommand(tmp_path, capsys):
    report_json_path = str(tmp_path / "scan_input.json")
    # Generate report file first
    main(["audit", "--format", "json", "--output", report_json_path])

    # Convert report via report command
    ret = main(["report", "--input", report_json_path, "--format", "markdown"])
    assert ret == 0
    cap = capsys.readouterr()
    assert "# 🛡️ CIS Benchmark Level 1 Audit Report" in cap.out


def test_cli_help_and_no_args(capsys):
    ret = main([])
    assert ret == 0
    captured = capsys.readouterr()
    assert "usage: cis-hardener" in captured.out


def test_cli_rules_with_section_filter(capsys):
    ret = main(["rules", "--section", "SSH"])
    assert ret == 0
    cap = capsys.readouterr()
    assert "CIS-SSH-001" in cap.out

    ret_json = main(["rules", "--section", "Sysctl", "--json"])
    assert ret_json == 0
    cap_json = capsys.readouterr()
    data = json.loads(cap_json.out)
    assert all("Sysctl" in r["section"] or "Network" in r["section"] for r in data)


def test_cli_remediate_with_rule_and_section_filters(cli_sandbox):
    ret = main([
        "remediate",
        "--root-prefix", cli_sandbox,
        "--rule", "CIS-SSH-001",
        "--format", "json",
        "--no-root-check",
    ])
    assert ret == 0

    ret_sec = main([
        "remediate",
        "--root-prefix", cli_sandbox,
        "--section", "SSH",
        "--no-root-check",
    ])
    assert ret_sec == 0


def test_cli_remediate_permission_error_exit_code():
    with patch("cis.cli.CISRemediator", side_effect=PermissionError("Need root")):
        ret = main(["remediate", "--root-prefix", ""])
        assert ret == 1


def test_cli_rollback_failures(tmp_path):
    # Non-existent session
    empty_backup_dir = str(tmp_path / "empty_backups")
    os.makedirs(empty_backup_dir)
    ret = main(["rollback", "--backup-dir", empty_backup_dir, "--session-id", "non_existent", "--no-root-check"])
    assert ret == 1

    # Empty list
    ret_list = main(["rollback", "--backup-dir", empty_backup_dir, "--list", "--no-root-check"])
    assert ret_list == 0


def test_cli_report_invalid_file():
    ret = main(["report", "--input", "/non/existent/path/report.json"])
    assert ret == 1
