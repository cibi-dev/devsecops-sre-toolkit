"""Unit and integration tests for MetricsCollector."""

from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from exporter.metrics_collector import MetricFamily, MetricsCollector, MetricType


@pytest.fixture
def mock_proc_env(tmp_path: Path) -> Path:
    """Creates a realistic mock /proc directory structure."""
    proc = tmp_path / "proc"
    proc.mkdir(parents=True)

    # /proc/stat
    stat_content = (
        "cpu  10132 120 5432 201230 450 12 34 0 0 0\n"
        "cpu0 5000 60 2700 100600 220 6 17 0 0 0\n"
        "cpu1 5132 60 2732 100630 230 6 17 0 0 0\n"
        "intr 123456\n"
        "ctxt 7891011\n"
    )
    (proc / "stat").write_text(stat_content, encoding="utf-8")

    # /proc/meminfo
    meminfo_content = (
        "MemTotal:       16384000 kB\n"
        "MemFree:         4096000 kB\n"
        "MemAvailable:    8192000 kB\n"
        "Buffers:          512000 kB\n"
        "Cached:          4096000 kB\n"
        "SwapTotal:       2048000 kB\n"
        "SwapFree:        1024000 kB\n"
    )
    (proc / "meminfo").write_text(meminfo_content, encoding="utf-8")

    # /proc/diskstats
    diskstats_content = (
        "   8       0 sda 1000 50 20000 500 2000 100 40000 1000 0 450 1500 0 0 0\n"
        "   8       1 sda1 100 0 2000 50 200 0 4000 100 0 50 150 0 0 0\n"
        " 259       0 nvme0n1 5000 0 100000 2500 10000 0 200000 5000 1 1200 7500 0 0 0\n"
        "   7       0 loop0 10 0 20 5 0 0 0 0 0 0 0 0 0 0\n"
    )
    (proc / "diskstats").write_text(diskstats_content, encoding="utf-8")

    # /proc/net/dev
    netdev_content = (
        "Inter-|   Receive                                                |  Transmit\n"
        " face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n"
        "    lo: 1048576    1024    0    0    0     0          0         0  1048576    1024    0    0    0     0       0          0\n"
        "  eth0: 52428800  50000    5    2    0     0          0         0 104857600  80000   10    1    0     0       0          0\n"
    )
    (proc / "net").mkdir(parents=True)
    (proc / "net" / "dev").write_text(netdev_content, encoding="utf-8")

    # /proc/sys/fs/file-nr
    (proc / "sys" / "fs").mkdir(parents=True)
    (proc / "sys" / "fs" / "file-nr").write_text("1280 0 1048576\n", encoding="utf-8")

    # /proc/loadavg
    (proc / "loadavg").write_text("0.75 1.20 1.05 2/450 12345\n", encoding="utf-8")

    # /proc/uptime
    (proc / "uptime").write_text("360000.50 1440000.20\n", encoding="utf-8")

    # /proc/self/fd
    (proc / "self" / "fd").mkdir(parents=True)
    (proc / "self" / "fd" / "0").touch()
    (proc / "self" / "fd" / "1").touch()
    (proc / "self" / "fd" / "2").touch()

    return proc


def test_collect_cpu_metrics(mock_proc_env: Path):
    collector = MetricsCollector(proc_root=mock_proc_env)
    families = collector.collect_cpu_metrics()

    assert len(families) == 2
    sec_fam = next(f for f in families if f.name == "node_cpu_seconds_total")
    pct_fam = next(f for f in families if f.name == "node_cpu_usage_percent")

    assert sec_fam.metric_type == MetricType.COUNTER
    assert pct_fam.metric_type == MetricType.GAUGE

    # Verify per-mode samples exist
    modes_seen = {s.labels.get("mode") for s in sec_fam.samples if s.labels.get("cpu") == "0"}
    assert "user" in modes_seen
    assert "idle" in modes_seen
    assert "system" in modes_seen

    # Check CPU total sample
    total_pct = next(s for s in pct_fam.samples if s.labels.get("cpu") == "total")
    assert 0.0 <= total_pct.value <= 100.0


def test_collect_cpu_delta_calculation(mock_proc_env: Path):
    collector = MetricsCollector(proc_root=mock_proc_env)
    # First scrape establishes baseline
    collector.collect_cpu_metrics()

    # Update stat with new ticks
    new_stat = (
        "cpu  10232 120 5432 201230 450 12 34 0 0 0\n"
        "cpu0 5050 60 2700 100600 220 6 17 0 0 0\n"
        "cpu1 5182 60 2732 100630 230 6 17 0 0 0\n"
    )
    (mock_proc_env / "stat").write_text(new_stat, encoding="utf-8")

    families = collector.collect_cpu_metrics()
    pct_fam = next(f for f in families if f.name == "node_cpu_usage_percent")
    total_pct = next(s for s in pct_fam.samples if s.labels.get("cpu") == "total")
    assert total_pct.value == 100.0  # All new ticks were active


def test_collect_memory_metrics(mock_proc_env: Path):
    collector = MetricsCollector(proc_root=mock_proc_env)
    families = collector.collect_memory_metrics()

    assert len(families) == 2
    mem_fam = next(f for f in families if f.name == "node_memory_bytes")
    pct_fam = next(f for f in families if f.name == "node_memory_used_percent")

    sample_dict = {s.name: s.value for s in mem_fam.samples}
    assert sample_dict["node_memory_MemTotal_bytes"] == 16384000 * 1024.0
    assert sample_dict["node_memory_MemFree_bytes"] == 4096000 * 1024.0
    assert sample_dict["node_memory_MemAvailable_bytes"] == 8192000 * 1024.0
    assert sample_dict["node_memory_used_bytes"] == (16384000 - 8192000) * 1024.0

    pct_sample = pct_fam.samples[0]
    assert pct_sample.value == 50.0  # 8192MB / 16384MB = 50%


def test_collect_disk_metrics(mock_proc_env: Path):
    collector = MetricsCollector(proc_root=mock_proc_env)
    families = collector.collect_disk_metrics()

    names = {f.name for f in families}
    assert "node_disk_reads_completed_total" in names
    assert "node_disk_read_bytes_total" in names
    assert "node_disk_writes_completed_total" in names
    assert "node_disk_written_bytes_total" in names
    assert "node_disk_io_now" in names
    assert "node_filesystem_size_bytes" in names

    read_bytes_fam = next(f for f in families if f.name == "node_disk_read_bytes_total")
    sda_read = next(s for s in read_bytes_fam.samples if s.labels.get("device") == "sda")
    assert sda_read.value == 20000 * 512.0  # 20000 sectors * 512 bytes


def test_collect_network_metrics(mock_proc_env: Path):
    collector = MetricsCollector(proc_root=mock_proc_env)
    families = collector.collect_network_metrics()

    rx_fam = next(f for f in families if f.name == "node_network_receive_bytes_total")
    tx_fam = next(f for f in families if f.name == "node_network_transmit_bytes_total")

    eth0_rx = next(s for s in rx_fam.samples if s.labels.get("device") == "eth0")
    assert eth0_rx.value == 52428800.0

    eth0_tx = next(s for s in tx_fam.samples if s.labels.get("device") == "eth0")
    assert eth0_tx.value == 104857600.0


def test_collect_fd_metrics(mock_proc_env: Path):
    collector = MetricsCollector(proc_root=mock_proc_env)
    families = collector.collect_fd_metrics()

    alloc_fam = next(f for f in families if f.name == "node_filefd_allocated")
    max_fam = next(f for f in families if f.name == "node_filefd_maximum")
    open_fd_fam = next(f for f in families if f.name == "process_open_fds")

    assert alloc_fam.samples[0].value == 1280.0
    assert max_fam.samples[0].value == 1048576.0
    assert open_fd_fam.samples[0].value == 3.0  # 0, 1, 2


def test_collect_load_and_uptime(mock_proc_env: Path):
    collector = MetricsCollector(proc_root=mock_proc_env)
    families = collector.collect_load_and_uptime()

    load_fam = next(f for f in families if f.name == "node_load")
    uptime_fam = next(f for f in families if f.name == "node_uptime_seconds")

    load_samples = {s.name: s.value for s in load_fam.samples}
    assert load_samples["node_load1"] == 0.75
    assert load_samples["node_load5"] == 1.20
    assert load_samples["node_load15"] == 1.05

    assert uptime_fam.samples[0].value == 360000.50


def test_collect_all_and_dict(mock_proc_env: Path):
    collector = MetricsCollector(proc_root=mock_proc_env)
    families = collector.collect_all()

    # Must contain exporter internal metrics
    names = {f.name for f in families}
    assert "exporter_scrape_duration_seconds" in names
    assert "exporter_scrape_samples_collected" in names
    assert "exporter_scrape_errors_total" in names

    # Test dictionary export
    metrics_dict = collector.collect_as_dict()
    assert "node_memory_used_percent" in metrics_dict
    assert "node_load1" in metrics_dict
    assert metrics_dict["node_load1"] == 0.75


def test_missing_files_error_resilience(tmp_path: Path):
    empty_proc = tmp_path / "empty_proc"
    empty_proc.mkdir()
    collector = MetricsCollector(proc_root=empty_proc)

    # None of these should raise exceptions
    cpu = collector.collect_cpu_metrics()
    mem = collector.collect_memory_metrics()
    disk = collector.collect_disk_metrics()
    net = collector.collect_network_metrics()
    fd = collector.collect_fd_metrics()
    load = collector.collect_load_and_uptime()
    all_fams = collector.collect_all()

    assert isinstance(all_fams, list)
    assert len(all_fams) > 0  # exporter internal metrics always collected


def test_real_linux_host_collection():
    # If running on Linux with /proc, verify real collection works
    if os.path.exists("/proc/stat"):
        collector = MetricsCollector()
        families = collector.collect_all()
        assert len(families) > 5
        metrics_dict = collector.collect_as_dict()
        assert len(metrics_dict) > 10
