"""Tests for the CLI module."""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock, patch
import psutil
import pytest

from chaos.cli import main
from chaos.network import NetworkFaultResult


def test_cli_help(capsys: Any) -> None:
    """Test CLI without subcommands displays help."""
    ret = main([])
    assert ret == 0


def test_cli_status(capsys: Any) -> None:
    """Test status subcommand."""
    ret = main(["status"])
    assert ret == 0
    captured = capsys.readouterr()
    assert "CHAOS FAULT INJECTOR STATUS" in captured.out


def test_cli_dry_run_simulation(tmp_path: Any) -> None:
    """Test comprehensive dry-run subcommand."""
    out_file = str(tmp_path / "sim_report.md")
    ret = main(["dry-run", "--type", "network", "--output", out_file])
    assert ret == 0

    json_file = str(tmp_path / "sim_report.json")
    ret_json = main(["dry-run", "--type", "cpu", "--output", json_file])
    assert ret_json == 0


def test_cli_inject_net_dry_run(tmp_path: Any) -> None:
    """Test inject-net subcommand in dry-run mode."""
    rep_file = str(tmp_path / "net_rep.md")
    ret = main([
        "inject-net",
        "--interface", "eth0",
        "--latency-ms", "50",
        "--duration", "0.2",
        "--dry-run",
        "--report-out", rep_file,
    ])
    assert ret == 0


def test_cli_inject_net_failure_handling() -> None:
    """Test inject-net handling failure from inject_network_fault."""
    mock_res = NetworkFaultResult(
        interface="eth0",
        success=False,
        dry_run=False,
        command_executed=["tc", "add"],
        rollback_command=["tc", "del"],
        timestamp="2026-08-27T00:00:00Z",
        duration_seconds=5.0,
        error="Permission denied",
    )
    with patch("chaos.cli.inject_network_fault", return_value=mock_res):
        ret = main(["inject-net", "--interface", "eth0", "--latency-ms", "50", "--dry-run"])
        assert ret == 1


def test_cli_inject_net_protected_interface() -> None:
    """Test inject-net with protected interface is rejected."""
    ret = main(["inject-net", "--interface", "lo", "--dry-run"])
    assert ret == 1


def test_cli_stress_cpu_dry_run(tmp_path: Any) -> None:
    """Test stress-cpu subcommand in dry-run mode."""
    rep_file = str(tmp_path / "cpu_rep.md")
    ret = main([
        "stress-cpu",
        "--cores", "1",
        "--load-pct", "50",
        "--duration", "0.2",
        "--dry-run",
        "--report-out", rep_file,
    ])
    assert ret == 0


def test_cli_kill_proc_dry_run() -> None:
    """Test kill-proc subcommand in dry-run mode."""
    mock_proc = MagicMock(spec=psutil.Process)
    mock_proc.pid = 9999
    mock_proc.name.return_value = "app-worker"

    with patch("psutil.Process", return_value=mock_proc):
        ret = main([
            "kill-proc",
            "--pid", "9999",
            "--signal", "SIGTERM",
            "--whitelist", "app*,worker*",
            "--dry-run",
        ])
        assert ret == 0


def test_cli_kill_proc_no_targets() -> None:
    """Test kill-proc when no targets match."""
    with patch("psutil.process_iter", return_value=[]):
        ret = main(["kill-proc", "--name", "nonexistent-app", "--dry-run"])
        assert ret == 1


def test_cli_rollback_dry_run() -> None:
    """Test rollback subcommand in dry-run mode."""
    ret = main(["rollback", "--interface", "eth0", "--dry-run"])
    assert ret == 0


def test_cli_rollback_failure() -> None:
    """Test rollback subcommand when rollback fails."""
    with patch("chaos.cli.revert_network_fault", return_value=False):
        ret = main(["rollback", "--interface", "eth0", "--dry-run"])
        assert ret == 1


def test_cli_report(tmp_path: Any) -> None:
    """Test report generation subcommand."""
    json_out = str(tmp_path / "rep.json")
    ret = main(["report", "--format", "json", "--output", json_out])
    assert ret == 0

    md_out = str(tmp_path / "rep.md")
    ret_md = main(["report", "--format", "markdown", "--output", md_out])
    assert ret_md == 0


def test_cli_debug_flag_raises() -> None:
    """Test that --debug propagates exceptions."""
    with pytest.raises(Exception):
        main(["inject-net", "--interface", "lo", "--debug"])


def test_cli_unexpected_error_handling() -> None:
    """Test top-level catch of unexpected errors."""
    with patch("chaos.cli.cmd_status", side_effect=RuntimeError("Unexpected crash")):
        ret = main(["status"])
        assert ret == 1
