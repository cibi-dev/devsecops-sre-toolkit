"""Unit tests for AnomalyEngine threshold evaluator."""

from __future__ import annotations

import pytest

from watchdog.collectors.procfs import (
    CPUStats,
    LoadAvgStats,
    MemoryStats,
    SystemSnapshot,
    ZombieInfo,
)
from watchdog.collectors.systemd import ServiceStatus
from watchdog.engine import AnomalyEngine, Severity, WatchdogConfig


@pytest.fixture
def base_snapshot() -> SystemSnapshot:
    """Healthy baseline system snapshot."""
    return SystemSnapshot(
        timestamp=1600000000.0,
        cpu=CPUStats(usage_percent=15.0),
        memory=MemoryStats(
            total_bytes=16 * 1024**3,
            available_bytes=12 * 1024**3,
            used_bytes=4 * 1024**3,
            usage_percent=25.0,
            swap_total_bytes=4 * 1024**3,
            swap_free_bytes=4 * 1024**3,
            swap_used_bytes=0,
            swap_usage_percent=0.0,
        ),
        loadavg=LoadAvgStats(load1=0.5, load5=0.5, load15=0.5),
        zombies=[],
        total_processes=100,
        core_count=4,
    )


def test_engine_healthy_snapshot_produces_no_anomalies(base_snapshot: SystemSnapshot):
    engine = AnomalyEngine()
    anomalies = engine.evaluate_snapshot(base_snapshot)
    assert len(anomalies) == 0


def test_engine_cpu_warning_and_critical(base_snapshot: SystemSnapshot):
    engine = AnomalyEngine(WatchdogConfig(cpu_warning_percent=70.0, cpu_critical_percent=90.0))

    # Test warning
    warn_snap = base_snapshot.model_copy(
        update={"cpu": base_snapshot.cpu.model_copy(update={"usage_percent": 75.0})}
    )
    anomalies = engine.evaluate_snapshot(warn_snap)
    assert len(anomalies) == 1
    assert anomalies[0].metric == "cpu"
    assert anomalies[0].severity == Severity.WARNING

    # Test critical
    crit_snap = base_snapshot.model_copy(
        update={"cpu": base_snapshot.cpu.model_copy(update={"usage_percent": 95.0})}
    )
    anomalies = engine.evaluate_snapshot(crit_snap)
    assert len(anomalies) == 1
    assert anomalies[0].metric == "cpu"
    assert anomalies[0].severity == Severity.CRITICAL
    assert anomalies[0].recommended_runbook == "throttle_high_cpu_tasks"


def test_engine_memory_warning_and_critical(base_snapshot: SystemSnapshot):
    engine = AnomalyEngine(WatchdogConfig(memory_warning_percent=80.0, memory_critical_percent=92.0))

    # Warning
    snap_warn = base_snapshot.model_copy(
        update={"memory": base_snapshot.memory.model_copy(update={"usage_percent": 85.0})}
    )
    anomalies = engine.evaluate_snapshot(snap_warn)
    assert len(anomalies) == 1
    assert anomalies[0].metric == "memory"
    assert anomalies[0].severity == Severity.WARNING

    # Critical
    snap_crit = base_snapshot.model_copy(
        update={"memory": base_snapshot.memory.model_copy(update={"usage_percent": 95.0})}
    )
    anomalies = engine.evaluate_snapshot(snap_crit)
    assert len(anomalies) == 1
    assert anomalies[0].metric == "memory"
    assert anomalies[0].severity == Severity.CRITICAL
    assert anomalies[0].recommended_runbook == "clear_pagecache"


def test_engine_swap_warning_and_critical(base_snapshot: SystemSnapshot):
    engine = AnomalyEngine(WatchdogConfig(swap_warning_percent=50.0, swap_critical_percent=80.0))

    # Swap warning
    snap_warn = base_snapshot.model_copy(
        update={"memory": base_snapshot.memory.model_copy(update={"swap_usage_percent": 60.0})}
    )
    anomalies = engine.evaluate_snapshot(snap_warn)
    assert len(anomalies) == 1
    assert anomalies[0].metric == "swap"
    assert anomalies[0].severity == Severity.WARNING

    # Swap critical
    snap_crit = base_snapshot.model_copy(
        update={"memory": base_snapshot.memory.model_copy(update={"swap_usage_percent": 85.0})}
    )
    anomalies = engine.evaluate_snapshot(snap_crit)
    assert len(anomalies) == 1
    assert anomalies[0].metric == "swap"
    assert anomalies[0].severity == Severity.CRITICAL
    assert anomalies[0].recommended_runbook == "clear_pagecache"


def test_engine_load_per_core_evaluation(base_snapshot: SystemSnapshot):
    engine = AnomalyEngine(WatchdogConfig(load_per_core_warning=2.0, load_per_core_critical=4.0))

    # 4 cores, load1 = 10.0 => load_per_core = 2.5 (Warning)
    snap_warn = base_snapshot.model_copy(
        update={"loadavg": base_snapshot.loadavg.model_copy(update={"load1": 10.0})}
    )
    anomalies = engine.evaluate_snapshot(snap_warn)
    assert len(anomalies) == 1
    assert anomalies[0].metric == "loadavg"
    assert anomalies[0].severity == Severity.WARNING

    # 4 cores, load1 = 20.0 => load_per_core = 5.0 (Critical)
    snap_crit = base_snapshot.model_copy(
        update={"loadavg": base_snapshot.loadavg.model_copy(update={"load1": 20.0})}
    )
    anomalies = engine.evaluate_snapshot(snap_crit)
    assert len(anomalies) == 1
    assert anomalies[0].metric == "loadavg"
    assert anomalies[0].severity == Severity.CRITICAL
    assert anomalies[0].recommended_runbook == "reap_zombies"


def test_engine_zombie_process_detection(base_snapshot: SystemSnapshot):
    engine = AnomalyEngine(WatchdogConfig(zombie_warning_count=1, zombie_critical_count=3))

    zombies = [
        ZombieInfo(pid=101, ppid=1, comm="z1"),
        ZombieInfo(pid=102, ppid=1, comm="z2"),
        ZombieInfo(pid=103, ppid=1, comm="z3"),
    ]

    snap = base_snapshot.model_copy(update={"zombies": zombies})
    anomalies = engine.evaluate_snapshot(snap)

    assert len(anomalies) == 1
    assert anomalies[0].metric == "zombies"
    assert anomalies[0].severity == Severity.CRITICAL
    assert anomalies[0].recommended_runbook == "reap_zombies"
    assert anomalies[0].current_value == 3.0


def test_engine_failed_service_anomaly(base_snapshot: SystemSnapshot):
    engine = AnomalyEngine()
    services = {
        "nginx.service": ServiceStatus(name="nginx.service", active_state="active", is_active=True),
        "api.service": ServiceStatus(name="api.service", active_state="failed", sub_state="failed", is_failed=True),
    }

    anomalies = engine.evaluate_snapshot(base_snapshot, service_statuses=services)

    assert len(anomalies) == 1
    assert anomalies[0].metric == "service"
    assert anomalies[0].severity == Severity.CRITICAL
    assert anomalies[0].recommended_runbook == "restart_service:api.service"
