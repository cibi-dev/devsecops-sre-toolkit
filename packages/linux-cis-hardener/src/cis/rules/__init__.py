"""Registry and loader for all CIS Benchmark Level 1 security rules."""

from __future__ import annotations

from typing import Type

from cis.rules.base import (
    AuditResult,
    CISRule,
    CISSection,
    RemediationResult,
    RollbackResult,
    RuleStatus,
    Severity,
    SEVERITY_WEIGHTS,
    resolve_target_path,
    safe_read_file,
    safe_write_file,
)
from cis.rules.firewall import (
    FirewallDefaultDrop,
    FirewallInstalled,
    FirewallLoopback,
)
from cis.rules.permissions import (
    PermDefaultUmask,
    PermGShadow,
    PermGroup,
    PermPasswd,
    PermSSHConfig,
    PermShadow,
)
from cis.rules.ssh import (
    SSHClientAliveInterval,
    SSHLoginGraceTime,
    SSHMaxAuthTries,
    SSHPasswordAuthentication,
    SSHPermitRootLogin,
    SSHX11Forwarding,
)
from cis.rules.sysctl import (
    SysctlASLR,
    SysctlAcceptRedirects,
    SysctlAcceptSourceRoute,
    SysctlIPForward,
    SysctlLogMartians,
    SysctlSendRedirects,
    SysctlSyncookies,
)

ALL_RULE_CLASSES: list[Type[CISRule]] = [
    # SSH Rules (CIS 5.2)
    SSHPermitRootLogin,
    SSHPasswordAuthentication,
    SSHMaxAuthTries,
    SSHX11Forwarding,
    SSHClientAliveInterval,
    SSHLoginGraceTime,
    # Sysctl Rules (CIS 3.2 / 1.5)
    SysctlIPForward,
    SysctlSendRedirects,
    SysctlAcceptRedirects,
    SysctlSyncookies,
    SysctlASLR,
    SysctlAcceptSourceRoute,
    SysctlLogMartians,
    # File Permissions & Umask Rules (CIS 6.1 / 5.4)
    PermPasswd,
    PermShadow,
    PermGShadow,
    PermGroup,
    PermSSHConfig,
    PermDefaultUmask,
    # Firewall Rules (CIS 3.5)
    FirewallInstalled,
    FirewallDefaultDrop,
    FirewallLoopback,
]


def get_all_rules() -> list[CISRule]:
    """Instantiate and return fresh instances of all registered CIS Benchmark Level 1 rules."""
    return [cls() for cls in ALL_RULE_CLASSES]


def get_rule_by_id(rule_id: str) -> CISRule | None:
    """Retrieve a rule instance by its unique identifier (e.g. CIS-SSH-001)."""
    for cls in ALL_RULE_CLASSES:
        instance = cls()
        if instance.rule_id.lower() == rule_id.lower():
            return instance
    return None


__all__ = [
    "AuditResult",
    "CISRule",
    "CISSection",
    "RemediationResult",
    "RollbackResult",
    "RuleStatus",
    "Severity",
    "SEVERITY_WEIGHTS",
    "resolve_target_path",
    "safe_read_file",
    "safe_write_file",
    "ALL_RULE_CLASSES",
    "get_all_rules",
    "get_rule_by_id",
    # Rule classes
    "SSHPermitRootLogin",
    "SSHPasswordAuthentication",
    "SSHMaxAuthTries",
    "SSHX11Forwarding",
    "SSHClientAliveInterval",
    "SSHLoginGraceTime",
    "SysctlIPForward",
    "SysctlSendRedirects",
    "SysctlAcceptRedirects",
    "SysctlSyncookies",
    "SysctlASLR",
    "SysctlAcceptSourceRoute",
    "SysctlLogMartians",
    "PermPasswd",
    "PermShadow",
    "PermGShadow",
    "PermGroup",
    "PermSSHConfig",
    "PermDefaultUmask",
    "FirewallInstalled",
    "FirewallDefaultDrop",
    "FirewallLoopback",
]
