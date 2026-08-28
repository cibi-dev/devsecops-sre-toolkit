"""Enterprise Linux Chaos Engineering Engine.

Provides controlled fault injection (network netem, CPU stress, process termination)
with guaranteed safety guardrails, dead-man switches, atomic rollbacks, and
resilience reporting.
"""

from chaos.cpu_stress import CpuStressConfig, CpuStressInjector, CpuStressResult, stress_cpu
from chaos.network import (
    NetworkFaultConfig,
    NetworkFaultResult,
    build_tc_command,
    build_tc_rollback_command,
    inject_network_fault,
    revert_network_fault,
)
from chaos.process_killer import (
    ProcessKillResult,
    ProcessTargetConfig,
    find_target_processes,
    kill_target_process,
    terminate_processes,
)
from chaos.reporter import (
    ExperimentPhase,
    PhaseMetrics,
    ResilienceReport,
    ResilienceTracker,
    calculate_percentiles,
    calculate_resilience_score,
    export_json,
    export_markdown,
    generate_markdown_report,
)
from chaos.safety_guard import (
    ChaosSecurityError,
    DeadManSwitchTriggered,
    LockAcquisitionError,
    PrivilegeError,
    ProtectedTargetError,
    RollbackAction,
    SafetyGuard,
    check_root_privileges,
    validate_target_interface,
    validate_target_pid,
    validate_target_process_name,
)

__version__ = "0.1.0"

__all__ = [
    "CpuStressConfig",
    "CpuStressInjector",
    "CpuStressResult",
    "stress_cpu",
    "NetworkFaultConfig",
    "NetworkFaultResult",
    "build_tc_command",
    "build_tc_rollback_command",
    "inject_network_fault",
    "revert_network_fault",
    "ProcessKillResult",
    "ProcessTargetConfig",
    "find_target_processes",
    "kill_target_process",
    "terminate_processes",
    "ExperimentPhase",
    "PhaseMetrics",
    "ResilienceReport",
    "ResilienceTracker",
    "calculate_percentiles",
    "calculate_resilience_score",
    "export_json",
    "export_markdown",
    "generate_markdown_report",
    "ChaosSecurityError",
    "DeadManSwitchTriggered",
    "LockAcquisitionError",
    "PrivilegeError",
    "ProtectedTargetError",
    "RollbackAction",
    "SafetyGuard",
    "check_root_privileges",
    "validate_target_interface",
    "validate_target_pid",
    "validate_target_process_name",
]
