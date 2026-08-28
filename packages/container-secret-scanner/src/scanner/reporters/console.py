"""Sanitized terminal console reporter for secret scan findings."""

from __future__ import annotations

import sys
from typing import List

from scanner.engine import Finding, ScanSummary


# ANSI Colors
RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
RED = "\033[31m"
YELLOW = "\033[33m"
BLUE = "\033[34m"
MAGENTA = "\033[35m"
CYAN = "\033[36m"
GREEN = "\033[32m"


def _colorize(text: str, color_code: str, use_color: bool) -> str:
    if not use_color:
        return text
    return f"{color_code}{text}{RESET}"


def _get_severity_badge(severity: str, use_color: bool) -> str:
    sev = severity.upper()
    if sev == "CRITICAL":
        return _colorize("[CRITICAL]", RED + BOLD, use_color)
    if sev == "HIGH":
        return _colorize("[HIGH]", RED, use_color)
    if sev == "MEDIUM":
        return _colorize("[MEDIUM]", YELLOW, use_color)
    return _colorize("[LOW]", BLUE, use_color)


def render_console_report(summary: ScanSummary, use_color: bool = True) -> str:
    """Render a human-readable, sanitized console report.

    Args:
        summary: Scan results summary.
        use_color: Whether ANSI color codes should be enabled.

    Returns:
        Formatted multi-line report string.
    """
    lines: List[str] = []

    # Header
    banner = "╔══════════════════════════════════════════════════════════════════╗\n" \
             "║             CONTAINER SECRET SCANNER — AUDIT REPORT              ║\n" \
             "╚══════════════════════════════════════════════════════════════════╝"
    lines.append(_colorize(banner, CYAN + BOLD, use_color))
    lines.append("")

    # Findings Section
    if summary.findings:
        lines.append(_colorize(f"🚨 FOUND {len(summary.findings)} SUSPICIOUS SECRET(S):", RED + BOLD, use_color))
        lines.append("─" * 68)

        for idx, finding in enumerate(summary.findings, start=1):
            badge = _get_severity_badge(finding.severity, use_color)
            loc = f"{finding.file_path}:{finding.line_number}:{finding.column_number}"
            loc_str = _colorize(loc, BOLD, use_color)

            lines.append(f"{idx:2d}. {badge} {_colorize(finding.rule_name, BOLD, use_color)} ({finding.rule_id})")
            lines.append(f"    📍 Location: {loc_str}")
            lines.append(f"    🔒 Sanitized Token: {_colorize(finding.redacted_text, MAGENTA, use_color)} (Entropy: {finding.entropy:.2f} bits)")
            lines.append(f"    🛡️ Control: {finding.cwe_id} | Category: {finding.category}")

            if finding.context_line:
                lines.append(f"    📄 Context: {_colorize(finding.context_line, DIM, use_color)}")
            lines.append("")
    else:
        lines.append(_colorize("✅ Zero secrets detected. Codebase / archive is clean!", GREEN + BOLD, use_color))
        lines.append("")

    # Errors section if any
    if summary.errors:
        lines.append(_colorize(f"⚠️ Encountered {len(summary.errors)} non-fatal warning(s) during scan:", YELLOW + BOLD, use_color))
        for err in summary.errors[:5]:
            lines.append(f"   • {err}")
        if len(summary.errors) > 5:
            lines.append(f"   • ... and {len(summary.errors) - 5} more")
        lines.append("")

    # Summary Statistics Box
    lines.append("─" * 68)
    lines.append(_colorize("📊 SCAN SUMMARY METRICS:", BOLD, use_color))
    mb_scanned = summary.bytes_scanned / (1024 * 1024)
    lines.append(f"   • Files Processed:     {summary.files_scanned:,}")
    lines.append(f"   • Total Data Scanned:  {mb_scanned:.2f} MB ({summary.bytes_scanned:,} bytes)")
    lines.append(f"   • Elapsed Time:        {summary.duration_seconds:.4f} seconds")

    if summary.findings:
        lines.append(f"   • Breakdown by Severity:")
        lines.append(f"       🔴 Critical: {summary.critical_count}")
        lines.append(f"       🟠 High:     {summary.high_count}")
        lines.append(f"       🟡 Medium:   {summary.medium_count}")
        lines.append(f"       🔵 Low:      {summary.low_count}")
    lines.append("─" * 68)

    return "\n".join(lines)
