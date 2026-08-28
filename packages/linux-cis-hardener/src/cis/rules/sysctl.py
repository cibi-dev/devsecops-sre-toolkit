"""CIS Benchmark Level 1 rules for Linux Kernel and Network Sysctl parameters."""

from __future__ import annotations

import os
import re
import subprocess  # nosec B404
from typing import Any, Optional

from cis.rules.base import (
    AuditResult,
    CISRule,
    CISSection,
    RemediationResult,
    RollbackResult,
    RuleStatus,
    Severity,
    resolve_target_path,
    safe_read_file,
    safe_write_file,
)

SYSCTL_CIS_CONF = "/etc/sysctl.d/99-cis.conf"
SYSCTL_FALLBACK_CONF = "/etc/sysctl.conf"


def parse_sysctl_file(content: str) -> dict[str, str]:
    """Parse key=value pairs from a sysctl configuration file."""
    directives: dict[str, str] = {}
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith(";"):
            continue
        if "=" in line:
            k, v = line.split("=", 1)
            directives[k.strip().lower()] = v.strip()
    return directives


def update_sysctl_directive(content: str, key: str, value: str) -> tuple[str, bool]:
    """Update or append a sysctl directive in configuration string."""
    pattern_active = re.compile(rf"^(\s*){re.escape(key)}\s*=.*$", re.IGNORECASE | re.MULTILINE)
    pattern_commented = re.compile(rf"^(\s*)[#;]\s*{re.escape(key)}\s*=.*$", re.IGNORECASE | re.MULTILINE)

    match = pattern_active.search(content)
    if match:
        current_line = match.group(0)
        current_val = current_line.split("=", 1)[1].strip()
        if current_val == str(value):
            return content, False
        new_content = pattern_active.sub(f"{key} = {value}", content, count=1)
        return new_content, True

    if pattern_commented.search(content):
        new_content = pattern_commented.sub(f"{key} = {value}", content, count=1)
        return new_content, True

    delimiter = "\n" if not content.endswith("\n") and content else ""
    new_content = f"{content}{delimiter}{key} = {value}\n"
    return new_content, True


def read_proc_sys(param: str) -> Optional[str]:
    """Read kernel parameter directly from /proc/sys/ safely."""
    rel_path = param.replace(".", "/")
    proc_path = os.path.join("/proc/sys", rel_path)
    if os.path.exists(proc_path):
        try:
            with open(proc_path, "r", encoding="utf-8") as f:
                return f.read().strip()
        except (OSError, PermissionError):
            return None
    return None


class BaseSysctlRule(CISRule):
    """Base class for sysctl kernel parameter CIS rules."""

    section = CISSection.NETWORK_SYSCTL.value
    parameters: dict[str, str]  # dict mapping parameter name -> expected value
    target_file = SYSCTL_CIS_CONF

    def _get_target_file_path(self, root_prefix: str) -> str:
        return resolve_target_path(root_prefix, self.target_file)

    def audit(self, root_prefix: str = "") -> AuditResult:
        file_path = self._get_target_file_path(root_prefix)
        conf_content = safe_read_file(file_path)
        if conf_content is None and not root_prefix:
            fallback_path = resolve_target_path(root_prefix, SYSCTL_FALLBACK_CONF)
            conf_content = safe_read_file(fallback_path)

        file_directives = parse_sysctl_file(conf_content) if conf_content else {}

        all_compliant = True
        current_states: list[str] = []
        expected_states: list[str] = []

        for param, expected_val in self.parameters.items():
            expected_states.append(f"{param}={expected_val}")
            param_lower = param.lower()

            # If live host without prefix, try /proc/sys first
            live_val = None
            if not root_prefix:
                live_val = read_proc_sys(param)

            file_val = file_directives.get(param_lower)
            effective_val = live_val if live_val is not None else file_val

            current_states.append(f"{param}={effective_val if effective_val is not None else 'UNSET'}")

            if effective_val is None or str(effective_val).strip() != str(expected_val).strip():
                all_compliant = False

        status = RuleStatus.PASSED if all_compliant else RuleStatus.FAILED
        current_str = ", ".join(current_states)
        expected_str = ", ".join(expected_states)

        return AuditResult(
            rule_id=self.rule_id,
            name=self.title,
            section=self.section,
            status=status,
            severity=self.severity,
            details=f"Sysctl parameters: {current_str} (expected {expected_str})",
            current_value=current_str,
            expected_value=expected_str,
            remediation_available=self.remediation_supported,
        )

    def remediate(
        self,
        root_prefix: str = "",
        dry_run: bool = False,
        backup_manager: Any = None,
    ) -> RemediationResult:
        file_path = self._get_target_file_path(root_prefix)
        conf_content = safe_read_file(file_path) or "# CIS Hardened Sysctl Parameters\n"

        file_directives = parse_sysctl_file(conf_content)
        needs_change = False

        for param, expected_val in self.parameters.items():
            current_val = file_directives.get(param.lower())
            if current_val != str(expected_val):
                needs_change = True
                break

        if not needs_change:
            return RemediationResult(
                rule_id=self.rule_id,
                name=self.title,
                changed=False,
                backup_path=None,
                details=f"Sysctl parameters for {self.rule_id} already configured correctly",
            )

        if dry_run:
            return RemediationResult(
                rule_id=self.rule_id,
                name=self.title,
                changed=True,
                details=f"[DRY-RUN] Would update {list(self.parameters.keys())} in {file_path}",
            )

        backup_entry = None
        if backup_manager is not None:
            backup_entry = backup_manager.backup_file(file_path)

        updated_content = conf_content
        for param, expected_val in self.parameters.items():
            updated_content, _ = update_sysctl_directive(updated_content, param, str(expected_val))

        success = safe_write_file(file_path, updated_content, mode=0o644)
        if not success:
            return RemediationResult(
                rule_id=self.rule_id,
                name=self.title,
                changed=False,
                details="Failed to write sysctl config",
                error_message=f"Write error on {file_path}",
            )

        # If running live as root, apply with sysctl -w
        if not root_prefix and os.geteuid() == 0:
            for param, expected_val in self.parameters.items():
                try:
                    subprocess.run(  # nosec B603,B607
                        ["sysctl", "-w", f"{param}={expected_val}"],
                        shell=False,
                        check=False,
                        timeout=5,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                    )
                except (OSError, subprocess.SubprocessError):
                    pass

        return RemediationResult(
            rule_id=self.rule_id,
            name=self.title,
            changed=True,
            backup_path=backup_entry.backup_path if backup_entry else None,
            details=f"Applied sysctl settings {list(self.parameters.keys())} in {file_path}",
        )

    def rollback(self, backup_manager: Any, root_prefix: str = "") -> RollbackResult:
        file_path = self._get_target_file_path(root_prefix)
        if backup_manager is None:
            return RollbackResult(
                rule_id=self.rule_id,
                name=self.title,
                restored=False,
                details="No backup manager provided for rollback",
                error_message="Missing backup manager",
            )
        success = backup_manager.restore_file(file_path)
        return RollbackResult(
            rule_id=self.rule_id,
            name=self.title,
            restored=success,
            details=f"Restored sysctl configuration from {file_path}" if success else f"Failed to restore {file_path}",
        )


class SysctlIPForward(BaseSysctlRule):
    """CIS 3.1.1: Ensure IP forwarding is disabled."""

    rule_id = "CIS-SYSCTL-001"
    title = "Disable IP Forwarding"
    description = "Disables kernel packet forwarding between network interfaces."
    severity = Severity.HIGH
    parameters = {"net.ipv4.ip_forward": "0"}


class SysctlSendRedirects(BaseSysctlRule):
    """CIS 3.1.2: Ensure packet redirect sending is disabled."""

    rule_id = "CIS-SYSCTL-002"
    title = "Disable Packet Redirect Sending"
    description = "Disables ICMP redirect sending to prevent routing table tampering."
    severity = Severity.MEDIUM
    parameters = {
        "net.ipv4.conf.all.send_redirects": "0",
        "net.ipv4.conf.default.send_redirects": "0",
    }


class SysctlAcceptRedirects(BaseSysctlRule):
    """CIS 3.2.2: Ensure ICMP redirects are not accepted."""

    rule_id = "CIS-SYSCTL-003"
    title = "Disable ICMP Redirect Acceptance"
    description = "Prevents malicious hosts from altering local routing tables via ICMP."
    severity = Severity.MEDIUM
    parameters = {
        "net.ipv4.conf.all.accept_redirects": "0",
        "net.ipv4.conf.default.accept_redirects": "0",
    }


class SysctlSyncookies(BaseSysctlRule):
    """CIS 3.2.8: Ensure TCP SYN Cookies is enabled."""

    rule_id = "CIS-SYSCTL-004"
    title = "Enable TCP SYN Cookies"
    description = "Protects against TCP SYN flood denial-of-service attacks."
    severity = Severity.HIGH
    parameters = {"net.ipv4.tcp_syncookies": "1"}


class SysctlASLR(BaseSysctlRule):
    """CIS 1.5.3: Ensure Address Space Layout Randomization (ASLR) is enabled."""

    rule_id = "CIS-SYSCTL-005"
    title = "Enable ASLR (Address Space Layout Randomization)"
    description = "Randomizes memory layout of program text, stack and heap to prevent exploit payloads."
    severity = Severity.CRITICAL
    parameters = {"kernel.randomize_va_space": "2"}


class SysctlAcceptSourceRoute(BaseSysctlRule):
    """CIS 3.2.1: Ensure source routed packets are not accepted."""

    rule_id = "CIS-SYSCTL-006"
    title = "Disable Source Routed Packet Acceptance"
    description = "Rejects source routed packets to prevent spoofing and unauthorized network routing."
    severity = Severity.MEDIUM
    parameters = {
        "net.ipv4.conf.all.accept_source_route": "0",
        "net.ipv4.conf.default.accept_source_route": "0",
    }


class SysctlLogMartians(BaseSysctlRule):
    """CIS 3.2.4: Ensure suspicious packets are logged."""

    rule_id = "CIS-SYSCTL-007"
    title = "Enable Martian Packet Logging"
    description = "Logs spoofed or impossible IP addresses to syslog."
    severity = Severity.LOW
    parameters = {
        "net.ipv4.conf.all.log_martians": "1",
        "net.ipv4.conf.default.log_martians": "1",
    }
