"""Saturation threshold evaluator and anomaly detection engine for Linux SRE Watchdog.

Deterministic threshold evaluations and runbook mapping (CWE-502 compliant schemas).
"""

from __future__ import annotations

import time
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field

from watchdog.collectors.procfs import SystemSnapshot
from watchdog.collectors.systemd import ServiceStatus


class Severity(str, Enum):
    """Anomaly severity level."""

    OK = "OK"
    WARNING = "WARNING"
    CRITICAL = "CRITICAL"


class WatchdogConfig(BaseModel):
    """Watchdog saturation thresholds and monitoring policy."""

    model_config = ConfigDict(extra="forbid")

    cpu_warning_percent: float = Field(default=80.0, ge=0.0, le=100.0)
    cpu_critical_percent: float = Field(default=90.0, ge=0.0, le=100.0)

    memory_warning_percent: float = Field(default=80.0, ge=0.0, le=100.0)
    memory_critical_percent: float = Field(default=90.0, ge=0.0, le=100.0)

    swap_warning_percent: float = Field(default=50.0, ge=0.0, le=100.0)
    swap_critical_percent: float = Field(default=80.0, ge=0.0, le=100.0)

    load_per_core_warning: float = Field(default=2.0, ge=0.0)
    load_per_core_critical: float = Field(default=4.0, ge=0.0)

    zombie_warning_count: int = Field(default=1, ge=0)
    zombie_critical_count: int = Field(default=5, ge=0)

    monitored_services: list[str] = Field(default_factory=list)


class AnomalyEvent(BaseModel):
    """Structured representation of a detected system anomaly."""

    model_config = ConfigDict(extra="forbid")

    metric: str = Field(description="Name of the affected metric (e.g. cpu, memory, zombies)")
    current_value: float = Field(description="Measured value")
    threshold_value: float = Field(description="Configured threshold value")
    severity: Severity = Field(description="Anomaly severity")
    recommended_runbook: Optional[str] = Field(default=None, description="Recommended remediation action identifier")
    timestamp: float = Field(default_factory=time.time, description="Timestamp of detection")
    message: str = Field(description="Human-readable description of anomaly")
    details: dict[str, Any] = Field(default_factory=dict, description="Additional context and metrics")


class AnomalyEngine:
    """Evaluates system snapshots against saturation thresholds."""

    def __init__(self, config: Optional[WatchdogConfig] = None) -> None:
        self.config = config or WatchdogConfig()

    def evaluate_snapshot(
        self,
        snapshot: SystemSnapshot,
        service_statuses: Optional[dict[str, ServiceStatus]] = None,
    ) -> list[AnomalyEvent]:
        """Evaluate full snapshot and return list of active anomalies."""
        anomalies: list[AnomalyEvent] = []

        # 1. CPU Saturation Evaluation
        cpu_usage = snapshot.cpu.usage_percent
        if cpu_usage >= self.config.cpu_critical_percent:
            anomalies.append(
                AnomalyEvent(
                    metric="cpu",
                    current_value=cpu_usage,
                    threshold_value=self.config.cpu_critical_percent,
                    severity=Severity.CRITICAL,
                    recommended_runbook="throttle_high_cpu_tasks",
                    message=f"CRITICAL: CPU usage {cpu_usage:.1f}% exceeds critical threshold {self.config.cpu_critical_percent:.1f}%",
                    details={"idle_all": snapshot.cpu.idle_all, "total_ticks": snapshot.cpu.total},
                )
            )
        elif cpu_usage >= self.config.cpu_warning_percent:
            anomalies.append(
                AnomalyEvent(
                    metric="cpu",
                    current_value=cpu_usage,
                    threshold_value=self.config.cpu_warning_percent,
                    severity=Severity.WARNING,
                    recommended_runbook=None,
                    message=f"WARNING: CPU usage {cpu_usage:.1f}% exceeds warning threshold {self.config.cpu_warning_percent:.1f}%",
                    details={"idle_all": snapshot.cpu.idle_all, "total_ticks": snapshot.cpu.total},
                )
            )

        # 2. Memory Exhaustion Evaluation
        mem_usage = snapshot.memory.usage_percent
        if mem_usage >= self.config.memory_critical_percent:
            anomalies.append(
                AnomalyEvent(
                    metric="memory",
                    current_value=mem_usage,
                    threshold_value=self.config.memory_critical_percent,
                    severity=Severity.CRITICAL,
                    recommended_runbook="clear_pagecache",
                    message=f"CRITICAL: RAM usage {mem_usage:.1f}% exceeds critical threshold {self.config.memory_critical_percent:.1f}%",
                    details={
                        "used_bytes": snapshot.memory.used_bytes,
                        "total_bytes": snapshot.memory.total_bytes,
                        "available_bytes": snapshot.memory.available_bytes,
                    },
                )
            )
        elif mem_usage >= self.config.memory_warning_percent:
            anomalies.append(
                AnomalyEvent(
                    metric="memory",
                    current_value=mem_usage,
                    threshold_value=self.config.memory_warning_percent,
                    severity=Severity.WARNING,
                    recommended_runbook=None,
                    message=f"WARNING: RAM usage {mem_usage:.1f}% exceeds warning threshold {self.config.memory_warning_percent:.1f}%",
                    details={"available_bytes": snapshot.memory.available_bytes},
                )
            )

        # 3. Swap Saturation Evaluation
        swap_usage = snapshot.memory.swap_usage_percent
        if snapshot.memory.swap_total_bytes > 0:
            if swap_usage >= self.config.swap_critical_percent:
                anomalies.append(
                    AnomalyEvent(
                        metric="swap",
                        current_value=swap_usage,
                        threshold_value=self.config.swap_critical_percent,
                        severity=Severity.CRITICAL,
                        recommended_runbook="clear_pagecache",
                        message=f"CRITICAL: Swap usage {swap_usage:.1f}% exceeds critical threshold {self.config.swap_critical_percent:.1f}%",
                        details={"swap_used_bytes": snapshot.memory.swap_used_bytes},
                    )
                )
            elif swap_usage >= self.config.swap_warning_percent:
                anomalies.append(
                    AnomalyEvent(
                        metric="swap",
                        current_value=swap_usage,
                        threshold_value=self.config.swap_warning_percent,
                        severity=Severity.WARNING,
                        recommended_runbook=None,
                        message=f"WARNING: Swap usage {swap_usage:.1f}% exceeds warning threshold {self.config.swap_warning_percent:.1f}%",
                        details={"swap_used_bytes": snapshot.memory.swap_used_bytes},
                    )
                )

        # 4. Normalized Load Average (Load / Logical Cores)
        cores = max(1, snapshot.core_count)
        load_per_core = round(snapshot.loadavg.load1 / cores, 2)
        if load_per_core >= self.config.load_per_core_critical:
            anomalies.append(
                AnomalyEvent(
                    metric="loadavg",
                    current_value=load_per_core,
                    threshold_value=self.config.load_per_core_critical,
                    severity=Severity.CRITICAL,
                    recommended_runbook="reap_zombies",
                    message=f"CRITICAL: 1-min load per core {load_per_core} exceeds critical threshold {self.config.load_per_core_critical}",
                    details={"load1": snapshot.loadavg.load1, "cores": cores},
                )
            )
        elif load_per_core >= self.config.load_per_core_warning:
            anomalies.append(
                AnomalyEvent(
                    metric="loadavg",
                    current_value=load_per_core,
                    threshold_value=self.config.load_per_core_warning,
                    severity=Severity.WARNING,
                    recommended_runbook=None,
                    message=f"WARNING: 1-min load per core {load_per_core} exceeds warning threshold {self.config.load_per_core_warning}",
                    details={"load1": snapshot.loadavg.load1, "cores": cores},
                )
            )

        # 5. Zombie Process Buildup
        zombie_count = len(snapshot.zombies)
        if zombie_count >= self.config.zombie_critical_count:
            zombie_pids = [z.pid for z in snapshot.zombies]
            anomalies.append(
                AnomalyEvent(
                    metric="zombies",
                    current_value=float(zombie_count),
                    threshold_value=float(self.config.zombie_critical_count),
                    severity=Severity.CRITICAL,
                    recommended_runbook="reap_zombies",
                    message=f"CRITICAL: {zombie_count} defunct zombie processes detected (threshold: {self.config.zombie_critical_count})",
                    details={"zombie_pids": zombie_pids, "zombies": [z.model_dump() for z in snapshot.zombies]},
                )
            )
        elif zombie_count >= self.config.zombie_warning_count:
            anomalies.append(
                AnomalyEvent(
                    metric="zombies",
                    current_value=float(zombie_count),
                    threshold_value=float(self.config.zombie_warning_count),
                    severity=Severity.WARNING,
                    recommended_runbook="reap_zombies",
                    message=f"WARNING: {zombie_count} defunct zombie processes detected (threshold: {self.config.zombie_warning_count})",
                    details={"zombie_pids": [z.pid for z in snapshot.zombies]},
                )
            )

        # 6. Monitored Services Failures
        if service_statuses:
            for s_name, s_status in service_statuses.items():
                if s_status.is_failed:
                    anomalies.append(
                        AnomalyEvent(
                            metric="service",
                            current_value=1.0,
                            threshold_value=0.0,
                            severity=Severity.CRITICAL,
                            recommended_runbook=f"restart_service:{s_status.name}",
                            message=f"CRITICAL: Service '{s_status.name}' is in failed state (SubState={s_status.sub_state})",
                            details={"service_status": s_status.model_dump()},
                        )
                    )

        return anomalies
