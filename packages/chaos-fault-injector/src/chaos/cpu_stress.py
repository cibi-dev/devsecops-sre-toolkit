"""CPU stress injector module with duty-cycle throttling and hard timeouts (CWE-400).

Supports:
- Per-core or all-core load distribution
- Duty-cycle throttling (e.g. 50% load = 50ms spin / 50ms sleep)
- Hard maximum duration cutoff (<=30s)
- Clean stop via threading.Event
- Pre-registration with SafetyGuard atomic rollback
"""

from __future__ import annotations

import datetime
import math
import os
import threading
import time
from typing import Any, Dict, List, Optional
import psutil
from pydantic import BaseModel, ConfigDict, Field, field_validator

from chaos.safety_guard import MAX_EXPERIMENT_DURATION, SafetyGuard


class CpuStressConfig(BaseModel):
    """Configuration schema for CPU stress fault injection."""

    model_config = ConfigDict(extra="forbid")

    cores: Optional[int] = Field(
        default=None,
        ge=1,
        description="Number of CPU cores/threads to stress (defaults to all cores)",
    )
    load_percentage: float = Field(
        default=80.0,
        ge=1.0,
        le=100.0,
        description="Target CPU load percentage (1-100)",
    )
    duration_seconds: float = Field(
        default=10.0,
        gt=0.0,
        le=MAX_EXPERIMENT_DURATION,
        description="Duration of stress test in seconds",
    )
    dry_run: bool = Field(default=False, description="Simulate CPU stress without consuming CPU cycles")

    @field_validator("cores")
    @classmethod
    def validate_cores(cls, v: Optional[int]) -> Optional[int]:
        max_cores = os.cpu_count() or 1
        if v is not None and v > max_cores:
            return max_cores
        return v


class CpuStressResult(BaseModel):
    """Execution result of CPU stress injection."""

    model_config = ConfigDict(extra="forbid")

    cores_stressed: int
    target_load_percentage: float
    duration_seconds: float
    actual_duration_seconds: float
    dry_run: bool
    timestamp_start: str
    timestamp_end: str
    avg_cpu_percent_observed: float
    success: bool
    error: Optional[str] = None
    parameters: Dict[str, Any] = Field(default_factory=dict)


def _cpu_worker(stop_event: threading.Event, load_pct: float, slice_duration: float = 0.05) -> None:
    """Worker function executing a duty cycle: spin for busy_time, sleep for rest_time."""
    busy_time = slice_duration * (load_pct / 100.0)
    rest_time = slice_duration * (1.0 - (load_pct / 100.0))

    while not stop_event.is_set():
        # Spin loop
        spin_start = time.monotonic()
        while (time.monotonic() - spin_start) < busy_time:
            # Perform mathematical computation to consume CPU cycles
            _ = math.sqrt(12345.6789) * math.sin(0.42)
            if stop_event.is_set():
                return

        # Rest period
        if rest_time > 0:
            time.sleep(rest_time)


class CpuStressInjector:
    """Manages CPU stress worker threads and controlled execution."""

    def __init__(self, config: CpuStressConfig, safety_guard: Optional[SafetyGuard] = None) -> None:
        self.config = config
        self.safety_guard = safety_guard
        self._stop_event = threading.Event()
        self._threads: List[threading.Thread] = []
        self._running = False
        self._lock = threading.Lock()

    def start(self) -> None:
        """Spawn stress worker threads according to core count."""
        with self._lock:
            if self._running:
                return

            if self.config.dry_run:
                self._running = True
                return

            num_cores = self.config.cores or (os.cpu_count() or 1)
            self._stop_event.clear()
            self._threads = []

            for i in range(num_cores):
                thread = threading.Thread(
                    target=_cpu_worker,
                    args=(self._stop_event, self.config.load_percentage),
                    name=f"chaos-cpu-worker-{i}",
                    daemon=True,
                )
                self._threads.append(thread)
                thread.start()

            self._running = True

    def stop(self) -> None:
        """Signal all stress workers to stop and wait for completion."""
        with self._lock:
            if not self._running:
                return

            self._stop_event.set()
            for thread in self._threads:
                thread.join(timeout=1.0)
            self._threads.clear()
            self._running = False

    @property
    def is_running(self) -> bool:
        return self._running


def stress_cpu(
    config: CpuStressConfig,
    safety_guard: Optional[SafetyGuard] = None,
) -> CpuStressResult:
    """Execute controlled CPU stress for the specified duration.

    Args:
        config: CpuStressConfig instance.
        safety_guard: Optional SafetyGuard instance for atomic rollback & dead-man switch.

    Returns:
        CpuStressResult with metrics.
    """
    cores_to_use = config.cores or (os.cpu_count() or 1)
    injector = CpuStressInjector(config, safety_guard)

    start_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
    start_time = time.monotonic()

    # Pre-register stop in SafetyGuard
    if safety_guard is not None:
        safety_guard.register_rollback(
            callback=injector.stop,
            description=f"Stop CPU stress injector ({cores_to_use} cores)",
        )

    # Initial CPU baseline reading
    psutil.cpu_percent(interval=None)

    cpu_samples: List[float] = []

    try:
        injector.start()

        # Wait loop sampling CPU periodically
        elapsed = 0.0
        sample_interval = 0.5
        while elapsed < config.duration_seconds:
            sleep_chunk = min(sample_interval, config.duration_seconds - elapsed)
            time.sleep(sleep_chunk)
            elapsed = time.monotonic() - start_time
            if not config.dry_run:
                cpu_samples.append(psutil.cpu_percent(interval=None))
    finally:
        injector.stop()

    actual_duration = time.monotonic() - start_time
    end_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()

    avg_cpu = sum(cpu_samples) / len(cpu_samples) if cpu_samples else (config.load_percentage if not config.dry_run else 0.0)

    return CpuStressResult(
        cores_stressed=cores_to_use,
        target_load_percentage=config.load_percentage,
        duration_seconds=config.duration_seconds,
        actual_duration_seconds=actual_duration,
        dry_run=config.dry_run,
        timestamp_start=start_iso,
        timestamp_end=end_iso,
        avg_cpu_percent_observed=round(avg_cpu, 2),
        success=True,
        parameters=config.model_dump(exclude={"dry_run"}),
    )
