"""Comprehensive unit tests for ProcfsCollector."""

from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import patch

import pytest

from watchdog.collectors.procfs import (
    CPUStats,
    LoadAvgStats,
    MemoryStats,
    ProcfsCollector,
    SystemSnapshot,
    ZombieInfo,
)


@pytest.fixture
def mock_procfs(tmp_path: Path) -> Path:
    """Create a synthetic procfs directory layout with valid mocked files."""
    proc = tmp_path / "proc"
    proc.mkdir()

    # /proc/stat
    (proc / "stat").write_text(
        "cpu  10132153 290696 4084025 89234912 284092 1234 4567 0 0 0\n"
        "cpu0 5000000 100000 2000000 44000000 140000 600 2200 0 0 0\n"
        "cpu1 5132153 190696 2084025 45234912 144092 634 2367 0 0 0\n"
        "intr 123456789\n"
        "ctxt 987654321\n"
        "btime 1600000000\n"
        "processes 54321\n"
        "procs_running 2\n"
        "procs_blocked 0\n",
        encoding="utf-8",
    )

    # /proc/meminfo
    (proc / "meminfo").write_text(
        "MemTotal:       16384000 kB\n"
        "MemFree:         4096000 kB\n"
        "MemAvailable:    8192000 kB\n"
        "Buffers:          512000 kB\n"
        "Cached:          4096000 kB\n"
        "SwapTotal:       2048000 kB\n"
        "SwapFree:        1024000 kB\n"
        "Dirty:               120 kB\n"
        "Shmem:             64000 kB\n",
        encoding="utf-8",
    )

    # /proc/loadavg
    (proc / "loadavg").write_text(
        "1.25 2.50 3.75 3/450 12345\n",
        encoding="utf-8",
    )

    # Normal process: PID 100 (systemd)
    p100 = proc / "100"
    p100.mkdir()
    (p100 / "stat").write_text(
        "100 (systemd) S 0 100 100 0 -1 4194560 1000 0 0 0 50 100 0 0 20 0 1 0 10 10000000 2000 18446744073709551615\n",
        encoding="utf-8",
    )

    # Zombie process: PID 200 (worker-zombie)
    p200 = proc / "200"
    p200.mkdir()
    (p200 / "stat").write_text(
        "200 (worker-zombie) Z 100 200 200 0 -1 4194560 0 0 0 0 0 0 0 0 20 0 1 0 20 0 0 0\n",
        encoding="utf-8",
    )

    # Process with complex name: PID 300 (cat (foo bar))
    p300 = proc / "300"
    p300.mkdir()
    (p300 / "stat").write_text(
        "300 (cat (foo bar)) Z 100 300 300 0 -1 4194560 0 0 0 0 0 0 0 0 20 0 1 0 30 0 0 0\n",
        encoding="utf-8",
    )

    return proc


def test_procfs_cpu_raw_parsing(mock_procfs: Path):
    collector = ProcfsCollector(proc_root=mock_procfs)
    cpu = collector.read_cpu_raw()

    assert cpu.user == 10132153
    assert cpu.nice == 290696
    assert cpu.system == 4084025
    assert cpu.idle == 89234912
    assert cpu.iowait == 284092
    assert cpu.idle_all == 89234912 + 284092
    assert cpu.total > 0


def test_procfs_cpu_usage_calculation(mock_procfs: Path):
    collector = ProcfsCollector(proc_root=mock_procfs)
    s1 = collector.collect_cpu(sample_interval=0.0)
    assert s1.usage_percent == 0.0

    # Simulate updated /proc/stat with more busy ticks
    (mock_procfs / "stat").write_text(
        "cpu  10132253 290696 4084125 89234912 284092 1234 4567 0 0 0\n"
        "cpu0 5000050 100000 2000050 44000000 140000 600 2200 0 0 0\n"
        "cpu1 5132203 190696 2084075 45234912 144092 634 2367 0 0 0\n",
        encoding="utf-8",
    )

    s2 = collector.collect_cpu(sample_interval=0.0)
    # Total delta = 200 ticks, idle delta = 0 ticks => usage = 100.0%
    assert s2.usage_percent == 100.0


def test_procfs_cpu_sample_with_interval(mock_procfs: Path):
    collector = ProcfsCollector(proc_root=mock_procfs)
    s = collector.collect_cpu(sample_interval=0.01)
    assert isinstance(s, CPUStats)


def test_procfs_detect_core_count(mock_procfs: Path):
    collector = ProcfsCollector(proc_root=mock_procfs)
    assert collector._core_count == 2


def test_procfs_memory_parsing(mock_procfs: Path):
    collector = ProcfsCollector(proc_root=mock_procfs)
    mem = collector.collect_memory()

    assert mem.total_bytes == 16384000 * 1024
    assert mem.available_bytes == 8192000 * 1024
    assert mem.used_bytes == (16384000 - 8192000) * 1024
    assert mem.usage_percent == 50.0
    assert mem.swap_total_bytes == 2048000 * 1024
    assert mem.swap_free_bytes == 1024000 * 1024
    assert mem.swap_used_bytes == 1024000 * 1024
    assert mem.swap_usage_percent == 50.0


def test_procfs_memory_fallback_when_available_missing(tmp_path: Path):
    proc = tmp_path / "proc"
    proc.mkdir()
    (proc / "meminfo").write_text(
        "MemTotal:       1000000 kB\n"
        "MemFree:         200000 kB\n"
        "Buffers:         100000 kB\n"
        "Cached:          300000 kB\n"
        "SwapTotal:            0 kB\n"
        "SwapFree:             0 kB\n",
        encoding="utf-8",
    )
    collector = ProcfsCollector(proc_root=proc)
    mem = collector.collect_memory()

    # available = 200000 + 100000 + 300000 = 600000 kB
    # used = 1000000 - 600000 = 400000 kB (40%)
    assert mem.available_bytes == 600000 * 1024
    assert mem.used_bytes == 400000 * 1024
    assert mem.usage_percent == 40.0
    assert mem.swap_usage_percent == 0.0


def test_procfs_loadavg_parsing(mock_procfs: Path):
    collector = ProcfsCollector(proc_root=mock_procfs)
    load = collector.collect_loadavg()

    assert load.load1 == 1.25
    assert load.load5 == 2.50
    assert load.load15 == 3.75
    assert load.running_threads == 3
    assert load.total_threads == 450
    assert load.last_pid == 12345


def test_procfs_loadavg_malformed(tmp_path: Path):
    proc = tmp_path / "proc"
    proc.mkdir()
    (proc / "loadavg").write_text("invalid_loadavg", encoding="utf-8")
    collector = ProcfsCollector(proc_root=proc)
    load = collector.collect_loadavg()
    assert load.load1 == 0.0


def test_procfs_zombies_and_process_parsing(mock_procfs: Path):
    collector = ProcfsCollector(proc_root=mock_procfs)
    total_procs, zombies = collector.collect_processes_and_zombies()

    assert total_procs == 3
    assert len(zombies) == 2

    zombie_pids = {z.pid for z in zombies}
    assert zombie_pids == {200, 300}

    # Verify complex process comm name parsing
    z300 = next(z for z in zombies if z.pid == 300)
    assert z300.comm == "cat (foo bar)"
    assert z300.ppid == 100


def test_procfs_take_snapshot(mock_procfs: Path):
    collector = ProcfsCollector(proc_root=mock_procfs)
    snapshot = collector.take_snapshot(sample_interval=0.0)

    assert isinstance(snapshot, SystemSnapshot)
    assert snapshot.core_count == 2
    assert snapshot.total_processes == 3
    assert len(snapshot.zombies) == 2
    assert snapshot.memory.total_bytes > 0
    assert snapshot.loadavg.load1 == 1.25


def test_procfs_root_user_warning_cwe250(mock_procfs: Path, capsys: pytest.CaptureFixture[str]):
    with patch("os.geteuid", return_value=0):
        collector = ProcfsCollector(proc_root=mock_procfs)
        collector.take_snapshot(sample_interval=0.0)
        captured = capsys.readouterr()
        assert "SECURITY WARNING" in captured.err


def test_procfs_empty_or_missing_directory(tmp_path: Path):
    empty_proc = tmp_path / "nonexistent"
    collector = ProcfsCollector(proc_root=empty_proc)

    assert collector.read_cpu_raw().total == 0
    assert collector.collect_memory().total_bytes == 0
    assert collector.collect_loadavg().load1 == 0.0
    assert collector.collect_processes_and_zombies() == (0, [])
