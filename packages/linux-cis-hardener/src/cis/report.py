"""Audit report generator supporting Markdown, JSON, and terminal console formats."""

from __future__ import annotations

import json
from typing import Optional

from cis.remediator import RemediationSummary
from cis.scanner import ScanReport


class ReportGenerator:
    """Formatter for audit and remediation reports across multiple presentation formats."""

    @staticmethod
    def to_json(report: ScanReport, indent: int = 2) -> str:
        """Convert ScanReport to sanitized JSON string."""
        return report.model_dump_json(indent=indent)

    @staticmethod
    def to_markdown(report: ScanReport) -> str:
        """Generate structured GitHub-flavored Markdown report."""
        lines: list[str] = [
            "# 🛡️ CIS Benchmark Level 1 Audit Report",
            "",
            f"- **Host / Target:** `{report.host}`",
            f"- **Timestamp:** `{report.timestamp}`",
            f"- **Target Prefix:** `{report.root_prefix or '/'}`",
            f"- **Overall CIS Score:** **`{report.score}%`**",
            "",
            "## 📊 Executive Summary",
            "",
            "| Metric | Count |",
            "|---|:---:|",
            f"| **Total Evaluated Rules** | {report.total_rules} |",
            f"| 🟢 **Passed Rules** | {report.passed_rules} |",
            f"| 🔴 **Failed Rules** | {report.failed_rules} |",
            f"| ⚪ **Skipped Rules** | {report.skipped_rules} |",
            f"| ⚠️ **Error Rules** | {report.error_rules} |",
            "",
            "### Section Scores",
            "",
            "| CIS Benchmark Section | Compliance Score |",
            "|---|:---:|",
        ]

        for sec, score in sorted(report.section_scores.items()):
            emoji = "🟢" if score >= 80.0 else "🟡" if score >= 50.0 else "🔴"
            lines.append(f"| {sec} | {emoji} **{score}%** |")

        lines.extend([
            "",
            "## 📋 Detailed Rule Findings",
            "",
            "| Rule ID | Severity | Status | Name | Current Value | Expected Value |",
            "|---|:---:|:---:|---|---|---|",
        ])

        for r in report.results:
            st_emoji = "✅ PASSED" if r.status == "PASSED" else "❌ FAILED" if r.status == "FAILED" else f"⚠️ {r.status}"
            curr = (r.current_value or "UNSET").replace("|", "\\|")
            exp = (r.expected_value or "N/A").replace("|", "\\|")
            lines.append(f"| `{r.rule_id}` | `{r.severity}` | {st_emoji} | {r.name} | `{curr}` | `{exp}` |")

        return "\n".join(lines) + "\n"

    @staticmethod
    def to_console(report: ScanReport, color: bool = True) -> str:
        """Generate human-readable colored terminal output."""
        green = "\033[92m" if color else ""
        red = "\033[91m" if color else ""
        yellow = "\033[93m" if color else ""
        bold = "\033[1m" if color else ""
        reset = "\033[0m" if color else ""

        score_color = green if report.score >= 80 else yellow if report.score >= 50 else red

        lines: list[str] = [
            f"{bold}======================================================{reset}",
            f"{bold}🛡️  CIS BENCHMARK LEVEL 1 SECURITY AUDIT REPORT{reset}",
            f"{bold}======================================================{reset}",
            f" Target Host:   {report.host}",
            f" Timestamp:     {report.timestamp}",
            f" Target Prefix: {report.root_prefix or '/'}",
            f" CIS Score:     {bold}{score_color}{report.score}%{reset}",
            f" Evaluated:     {report.total_rules} rules (Passed: {green}{report.passed_rules}{reset}, Failed: {red}{report.failed_rules}{reset})",
            "",
            f"{bold}--- Section Compliance Summary ---{reset}",
        ]

        for sec, score in sorted(report.section_scores.items()):
            sec_color = green if score >= 80 else yellow if score >= 50 else red
            lines.append(f" • {sec:<35} : {sec_color}{score:>5.1f}%{reset}")

        lines.extend([
            "",
            f"{bold}--- Detailed Findings ---{reset}",
        ])

        for r in report.results:
            if r.status == "PASSED":
                tag = f"{green}[PASSED]{reset}"
            elif r.status == "FAILED":
                tag = f"{red}[FAILED]{reset}"
            else:
                tag = f"{yellow}[{r.status}]{reset}"

            lines.append(f" {tag} {bold}{r.rule_id}{reset} ({r.severity}) - {r.name}")
            lines.append(f"       Details:  {r.details}")
            if r.status != "PASSED":
                lines.append(f"       Observed: {r.current_value} | Target: {r.expected_value}")

        lines.append(f"{bold}======================================================{reset}")
        return "\n".join(lines) + "\n"

    @staticmethod
    def remediation_to_console(summary: RemediationSummary, color: bool = True) -> str:
        """Format remediation results for console display."""
        green = "\033[92m" if color else ""
        red = "\033[91m" if color else ""
        yellow = "\033[93m" if color else ""
        bold = "\033[1m" if color else ""
        reset = "\033[0m" if color else ""

        mode_str = f"{yellow}[DRY-RUN SIMULATION]{reset}" if summary.dry_run else f"{green}[ACTIVE EXECUTION]{reset}"

        lines: list[str] = [
            f"{bold}======================================================{reset}",
            f"{bold}🔧 CIS BENCHMARK REMEDIATION SUMMARY {mode_str}{reset}",
            f"{bold}======================================================{reset}",
            f" Session ID:        {summary.session_id or 'NONE'}",
            f" Rules Evaluated:   {summary.total_evaluated}",
            f" Remediated:        {green}{summary.remediated_count}{reset}",
            f" Already Compliant: {summary.already_compliant_count}",
            f" Failures/Errors:   {red if summary.failed_count > 0 else green}{summary.failed_count}{reset}",
            "",
            f"{bold}--- Action Details ---{reset}",
        ]

        for r in summary.results:
            if r.changed:
                tag = f"{green}[CHANGED]{reset}"
            elif r.error_message:
                tag = f"{red}[ERROR]{reset}"
            else:
                tag = f"{bold}[OK]{reset}"
            lines.append(f" {tag} {bold}{r.rule_id}{reset} - {r.name}")
            lines.append(f"       Details: {r.details}")
            if r.backup_path:
                lines.append(f"       Backup:  {r.backup_path}")

        lines.append(f"{bold}======================================================{reset}")
        return "\n".join(lines) + "\n"
