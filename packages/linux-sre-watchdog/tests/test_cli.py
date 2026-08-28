"""Unit tests for CLI commands and argument parsing."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from watchdog.cli import format_snapshot_table, load_config_file, main
from watchdog.collectors.procfs import (
    CPUStats,
    LoadAvgStats,
    MemoryStats,
    SystemSnapshot,
    ZombieInfo,
)
from watchdog.engine import AnomalyEvent, Severity, WatchdogConfig


@pytest.fixture
def mock_procfs_cli(tmp_path: Path) -> Path:
    """Fixture providing minimal procfs directory for CLI testing."""
    proc = tmp_path / "proc"
    proc.mkdir()

    (proc / "stat").write_text("cpu  1000 100 200 5000 50 0 0 0 0 0\n", encoding="utf-8")
    (proc / "meminfo").write_text(
        "MemTotal: 1000000 kB\nMemFree: 500000 kB\nMemAvailable: 600000 kB\nSwapTotal: 0 kB\nSwapFree: 0 kB\n",
        encoding="utf-8",
    )
    (proc / "loadavg").write_text("0.50 0.50 0.50 1/100 1000\n", encoding="utf-8")
    return proc


def test_cli_check_healthy(mock_procfs_cli: Path, capsys: pytest.CaptureFixture[str]):
    code = main(["--proc-root", str(mock_procfs_cli), "check"])
    assert code == 0
    captured = capsys.readouterr()
    assert "LINUX SRE WATCHDOG STATUS" in captured.out
    assert "HEALTHY" in captured.out


def test_cli_check_json(mock_procfs_cli: Path, capsys: pytest.CaptureFixture[str]):
    code = main(["--proc-root", str(mock_procfs_cli), "--json", "check"])
    assert code == 0
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert data["healthy"] is True
    assert "snapshot" in data


def test_cli_check_with_anomalies(mock_procfs_cli: Path, capsys: pytest.CaptureFixture[str]):
    # Overwrite meminfo with high memory usage (95%)
    (mock_procfs_cli / "meminfo").write_text(
        "MemTotal: 1000000 kB\nMemFree: 10000 kB\nMemAvailable: 20000 kB\nSwapTotal: 0 kB\nSwapFree: 0 kB\n",
        encoding="utf-8",
    )
    code = main(["--proc-root", str(mock_procfs_cli), "check"])
    assert code == 1
    captured = capsys.readouterr()
    assert "Active Anomalies" in captured.out
    assert "CRITICAL" in captured.out


def test_cli_dry_run(mock_procfs_cli: Path, capsys: pytest.CaptureFixture[str]):
    (mock_procfs_cli / "meminfo").write_text(
        "MemTotal: 1000000 kB\nMemFree: 10000 kB\nMemAvailable: 20000 kB\nSwapTotal: 0 kB\nSwapFree: 0 kB\n",
        encoding="utf-8",
    )
    code = main(["--proc-root", str(mock_procfs_cli), "dry-run"])
    assert code == 0
    captured = capsys.readouterr()
    assert "[DRY-RUN]" in captured.out
    assert "clear_pagecache" in captured.out


def test_cli_dry_run_healthy(mock_procfs_cli: Path, capsys: pytest.CaptureFixture[str]):
    code = main(["--proc-root", str(mock_procfs_cli), "dry-run"])
    assert code == 0
    captured = capsys.readouterr()
    assert "No remediation actions needed" in captured.out


def test_cli_status(mock_procfs_cli: Path, capsys: pytest.CaptureFixture[str]):
    code = main(["--proc-root", str(mock_procfs_cli), "status"])
    assert code == 0
    captured = capsys.readouterr()
    assert "CIRCUIT BREAKER ANTI-FLAPPING STATUS" in captured.out
    assert "CLOSED" in captured.out


def test_cli_run_daemon_iterations(mock_procfs_cli: Path, tmp_path: Path):
    log_file = tmp_path / "daemon_audit.jsonl"
    code = main([
        "--proc-root", str(mock_procfs_cli),
        "--log-file", str(log_file),
        "run-daemon",
        "--interval", "0.01",
        "--iterations", "2",
    ])
    assert code == 0
    assert log_file.is_file()
    lines = log_file.read_text(encoding="utf-8").strip().split("\n")
    assert len(lines) >= 2


def test_format_snapshot_table_with_zombies():
    snap = SystemSnapshot(
        timestamp=1600000000.0,
        cpu=CPUStats(usage_percent=50.0),
        memory=MemoryStats(
            total_bytes=8 * 1024**3,
            used_bytes=4 * 1024**3,
            available_bytes=4 * 1024**3,
            usage_percent=50.0,
        ),
        loadavg=LoadAvgStats(load1=1.0, load5=1.0, load15=1.0),
        zombies=[ZombieInfo(pid=999, ppid=1, comm="zombie_app")],
        total_processes=50,
        core_count=2,
    )
    anomalies = [
        AnomalyEvent(
            metric="zombies",
            current_value=1.0,
            threshold_value=1.0,
            severity=Severity.WARNING,
            recommended_runbook="reap_zombies",
            message="1 zombie detected",
        )
    ]
    table = format_snapshot_table(snap, anomalies)
    assert "Detected Zombies:" in table
    assert "PID 999" in table
    assert "[WARNING]" in table


def test_load_config_file_valid(tmp_path: Path):
    cfg_file = tmp_path / "config.json"
    cfg_file.write_text(
        json.dumps({
            "cpu_warning_percent": 65.0,
            "cpu_critical_percent": 85.0,
            "memory_warning_percent": 75.0,
            "memory_critical_percent": 88.0,
            "swap_warning_percent": 40.0,
            "swap_critical_percent": 70.0,
            "load_per_core_warning": 1.5,
            "load_per_core_critical": 3.0,
            "zombie_warning_count": 2,
            "zombie_critical_count": 4,
            "monitored_services": ["nginx.service"],
        }),
        encoding="utf-8",
    )

    cfg = load_config_file(str(cfg_file))
    assert cfg.cpu_warning_percent == 65.0
    assert cfg.monitored_services == ["nginx.service"]


def test_load_config_file_invalid_json(tmp_path: Path):
    bad_cfg = tmp_path / "bad.json"
    bad_cfg.write_text("{not valid json", encoding="utf-8")

    with pytest.raises(SystemExit) as exc_info:
        load_config_file(str(bad_cfg))
    assert exc_info.value.code == 2


def test_load_config_file_oversized_rejected(tmp_path: Path):
    oversized = tmp_path / "big_config.json"
    oversized.write_text("x" * (1024 * 1024 + 10), encoding="utf-8")

    with pytest.raises(SystemExit) as exc_info:
        load_config_file(str(oversized))
    assert exc_info.value.code == 2


def test_load_config_file_nonexistent_rejected(tmp_path: Path):
    with pytest.raises(SystemExit) as exc_info:
        load_config_file(str(tmp_path / "missing.json"))
    assert exc_info.value.code == 2
