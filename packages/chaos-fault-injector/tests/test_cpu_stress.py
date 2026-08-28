"""Tests for CPU stress injection module."""

from __future__ import annotations

import os
import threading
import time
from typing import Any
import pytest
from pydantic import ValidationError

from chaos.cpu_stress import (
    CpuStressConfig,
    CpuStressInjector,
    CpuStressResult,
    _cpu_worker,
    stress_cpu,
)
from chaos.safety_guard import SafetyGuard


def test_cpu_stress_config_validation() -> None:
    """Test valid CPU stress configuration and bounding."""
    max_cores = os.cpu_count() or 1
    config = CpuStressConfig(cores=2, load_percentage=75.0, duration_seconds=5.0, dry_run=True)
    assert config.cores == min(2, max_cores)
    assert config.load_percentage == 75.0
    assert config.duration_seconds == 5.0
    assert config.dry_run is True


def test_cpu_stress_config_clamps_cores() -> None:
    """Ensure requested cores > system cores is capped automatically."""
    max_cores = os.cpu_count() or 1
    config = CpuStressConfig(cores=max_cores + 100)
    assert config.cores == max_cores


def test_cpu_stress_config_invalid_boundaries() -> None:
    """Ensure invalid load or duration values raise validation error."""
    with pytest.raises(ValidationError):
        CpuStressConfig(load_percentage=0.0)  # Must be >= 1.0

    with pytest.raises(ValidationError):
        CpuStressConfig(load_percentage=105.0)  # Must be <= 100.0

    with pytest.raises(ValidationError):
        CpuStressConfig(duration_seconds=35.0)  # Exceeds max 30s

    with pytest.raises(ValidationError):
        CpuStressConfig(cores=0)  # Must be >= 1


def test_cpu_worker_lifecycle() -> None:
    """Test that cpu worker exits cleanly when stop event is set."""
    stop_event = threading.Event()
    worker_thread = threading.Thread(
        target=_cpu_worker,
        args=(stop_event, 50.0, 0.02),
        daemon=True,
    )
    worker_thread.start()
    assert worker_thread.is_alive()
    time.sleep(0.05)
    stop_event.set()
    worker_thread.join(timeout=1.0)
    assert not worker_thread.is_alive()


def test_cpu_stress_injector_dry_run() -> None:
    """Test CpuStressInjector in dry run mode."""
    config = CpuStressConfig(cores=1, load_percentage=50.0, duration_seconds=1.0, dry_run=True)
    injector = CpuStressInjector(config)
    assert not injector.is_running
    injector.start()
    assert injector.is_running
    # Second start is idempotent
    injector.start()
    injector.stop()
    assert not injector.is_running
    # Second stop is idempotent
    injector.stop()


def test_cpu_stress_injector_real_threads() -> None:
    """Test CpuStressInjector starts and stops worker threads."""
    config = CpuStressConfig(cores=2, load_percentage=50.0, duration_seconds=1.0, dry_run=False)
    injector = CpuStressInjector(config)
    injector.start()
    assert injector.is_running
    assert len(injector._threads) == 2
    time.sleep(0.05)
    injector.stop()
    assert not injector.is_running
    assert len(injector._threads) == 0


def test_stress_cpu_dry_run() -> None:
    """Test functional stress_cpu in dry-run mode."""
    config = CpuStressConfig(cores=1, load_percentage=60.0, duration_seconds=0.2, dry_run=True)
    res = stress_cpu(config)
    assert isinstance(res, CpuStressResult)
    assert res.success is True
    assert res.dry_run is True
    assert res.cores_stressed == 1
    assert res.target_load_percentage == 60.0


def test_stress_cpu_real_execution() -> None:
    """Test functional stress_cpu short execution."""
    config = CpuStressConfig(cores=1, load_percentage=40.0, duration_seconds=0.2, dry_run=False)
    res = stress_cpu(config)
    assert isinstance(res, CpuStressResult)
    assert res.success is True
    assert res.dry_run is False
    assert res.actual_duration_seconds >= 0.15


def test_stress_cpu_with_safety_guard(tmp_path: Any) -> None:
    """Test that stress_cpu pre-registers stop rollback with safety guard."""
    lock_file = str(tmp_path / "test_cpu.lock")
    config = CpuStressConfig(cores=1, load_percentage=30.0, duration_seconds=0.2, dry_run=True)

    with SafetyGuard(lock_file_path=lock_file, auto_lock=True) as guard:
        res = stress_cpu(config, safety_guard=guard)
        assert res.success is True
        assert guard.rollback_count == 1
        executed = guard.rollback_all()
        assert len(executed) == 1
        assert "Stop CPU stress injector" in executed[0]
