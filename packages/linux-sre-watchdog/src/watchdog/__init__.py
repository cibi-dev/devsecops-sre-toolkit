"""Linux SRE Watchdog package.

Lightweight SRE daemon reading procfs directly with anti-flapping circuit breaker
and safe runbook auto-remediation.
"""

from watchdog.circuit_breaker import CircuitBreaker, CircuitBreakerState
from watchdog.collectors.procfs import (
    CPUStats,
    LoadAvgStats,
    MemoryStats,
    ProcfsCollector,
    SystemSnapshot,
    ZombieInfo,
)
from watchdog.collectors.systemd import ServiceStatus, SystemdCollector
from watchdog.engine import AnomalyEngine, AnomalyEvent, Severity, WatchdogConfig
from watchdog.logger import StructuredAuditLogger
from watchdog.remediation import PrivilegeError, RemediationManager, RunbookResult

__version__ = "0.1.0"

__all__ = [
    "__version__",
    "ProcfsCollector",
    "CPUStats",
    "MemoryStats",
    "LoadAvgStats",
    "ZombieInfo",
    "SystemSnapshot",
    "SystemdCollector",
    "ServiceStatus",
    "AnomalyEngine",
    "AnomalyEvent",
    "Severity",
    "WatchdogConfig",
    "CircuitBreaker",
    "CircuitBreakerState",
    "RemediationManager",
    "RunbookResult",
    "PrivilegeError",
    "StructuredAuditLogger",
]
