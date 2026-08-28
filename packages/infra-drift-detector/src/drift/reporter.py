"""Visual report generators for terminal, JSON, and PR-ready Markdown."""

from __future__ import annotations

import json
from drift.comparator import DriftItem, DriftResult, DriftSeverity, DriftType
from drift.parser import sanitize_secrets


class DriftReporter:
    """Generates structured visual reports from DriftResult."""

    @staticmethod
    def to_json(result: DriftResult, indent: int = 2) -> str:
        """Serialize drift result to sanitized JSON."""
        data = result.to_dict()
        raw_json = json.dumps(data, indent=indent)
        return sanitize_secrets(raw_json)

    @staticmethod
    def to_unified_diff(result: DriftResult) -> str:
        """Return combined unified diffs for all drifted resources."""
        diffs = [
            item.unified_diff
            for item in result.drift_items
            if item.unified_diff
        ]
        combined = "\n\n".join(diffs) if diffs else "# No configuration drift detected."
        return sanitize_secrets(combined)

    @staticmethod
    def to_text(result: DriftResult, use_color: bool = True) -> str:
        """Generate human-readable terminal report."""
        lines: list[str] = []
        
        status_header = "🚨 DRIFT DETECTED" if result.drift_detected else "✅ NO DRIFT DETECTED"
        lines.append("=" * 70)
        lines.append(f"  INFRASTRUCTURE DRIFT REPORT: {result.manifest_name}")
        lines.append(f"  Status: {status_header}")
        lines.append(f"  Timestamp: {result.timestamp}")
        lines.append("=" * 70)

        # Summary box
        lines.append(f"Checked: {result.total_checked} | Matches: {result.match_count} | Drifts: {len(result.drift_items)}")
        lines.append(
            f"Breakdown -> Missing: {result.missing_count} | Unexpected: {result.unexpected_count} | Modified: {result.modified_count}"
        )
        lines.append(
            f"Severities -> Critical: {result.critical_count} | High: {result.high_count} | Medium: {result.medium_count} | Low: {result.low_count}"
        )
        lines.append("-" * 70)

        if not result.drift_detected:
            lines.append("All inspected infrastructure components match the desired state.")
            lines.append("=" * 70)
            return sanitize_secrets("\n".join(lines))

        # Group by category
        categories: dict[str, list[DriftItem]] = {}
        for item in result.drift_items:
            categories.setdefault(item.category, []).append(item)

        for cat, items in categories.items():
            lines.append(f"\n📁 CATEGORY: {cat.upper()} ({len(items)} issues)")
            for item in items:
                sev_tag = f"[{item.severity.value}]"
                type_tag = f"[{item.drift_type.value}]"
                lines.append(f"  {sev_tag:<10} {type_tag:<12} {item.name}")
                lines.append(f"    Reason: {item.message}")
                if item.differences:
                    for field, (desired_val, actual_val) in item.differences.items():
                        lines.append(f"      - {field}: desired='{desired_val}' != live='{actual_val}'")
                if item.unified_diff:
                    lines.append("    Unified Diff:")
                    for dline in item.unified_diff.splitlines():
                        lines.append(f"      {dline}")

        lines.append("\n" + "=" * 70)
        return sanitize_secrets("\n".join(lines))

    @staticmethod
    def to_markdown(result: DriftResult) -> str:
        """Generate GitHub PR-ready Markdown report."""
        lines: list[str] = []

        badge_status = (
            "![Drift](https://img.shields.io/badge/Drift-DETECTED-critical)"
            if result.drift_detected
            else "![Drift](https://img.shields.io/badge/Drift-CLEAN-success)"
        )

        lines.append(f"# 🛡️ Infrastructure Drift Audit Report: `{result.manifest_name}`\n")
        lines.append(f"{badge_status} `Audited at: {result.timestamp}`\n")

        if result.drift_detected:
            lines.append("> [!WARNING]")
            lines.append(
                f"> **Infrastructure Drift Detected!** Found **{len(result.drift_items)}** differences "
                f"across {result.total_checked} checked resources.\n"
            )
        else:
            lines.append("> [!NOTE]")
            lines.append("> **100% In-Sync**: Host infrastructure perfectly matches the desired GitOps specification.\n")

        # Summary Table
        lines.append("### 📊 Summary of Findings\n")
        lines.append("| Metric | Count | Status |")
        lines.append("|---|:---:|:---:|")
        lines.append(f"| Total Resources Checked | `{result.total_checked}` | ℹ️ |")
        lines.append(f"| Matches (In-Sync) | `{result.match_count}` | ✅ |")
        lines.append(f"| Missing Resources | `{result.missing_count}` | ❌ |")
        lines.append(f"| Unexpected Resources | `{result.unexpected_count}` | ⚠️ |")
        lines.append(f"| Modified Configurations | `{result.modified_count}` | 🔄 |")
        lines.append(f"| **Critical Severities** | `{result.critical_count}` | 🚨 |")
        lines.append(f"| **High Severities** | `{result.high_count}` | 🔴 |")
        lines.append(f"| **Medium Severities** | `{result.medium_count}` | 🟡 |")
        lines.append(f"| **Low Severities** | `{result.low_count}` | 🟢 |\n")

        if result.drift_detected:
            lines.append("### 🔍 Detailed Drift Breakdown\n")
            lines.append("| Category | Resource | Type | Severity | Description |")
            lines.append("|---|---|:---:|:---:|---|")
            for item in result.drift_items:
                sev_icon = {
                    DriftSeverity.CRITICAL: "🚨 CRITICAL",
                    DriftSeverity.HIGH: "🔴 HIGH",
                    DriftSeverity.MEDIUM: "🟡 MEDIUM",
                    DriftSeverity.LOW: "🟢 LOW",
                    DriftSeverity.INFO: "ℹ️ INFO",
                }.get(item.severity, item.severity.value)

                lines.append(
                    f"| `{item.category}` | `{item.name}` | **{item.drift_type.value}** | {sev_icon} | {item.message} |"
                )

            # Details with Diffs
            diff_items = [i for i in result.drift_items if i.unified_diff]
            if diff_items:
                lines.append("\n### 📝 Unified Configuration Diffs\n")
                for item in diff_items:
                    lines.append(f"<details><summary><b>{item.category} / {item.name}</b> ({item.drift_type.value})</summary>\n")
                    lines.append("```diff")
                    lines.append(item.unified_diff)
                    lines.append("```\n</details>\n")

        lines.append("---")
        lines.append("*(Report generated automatically by `infra-drift-detector` read-only auditor)*")

        return sanitize_secrets("\n".join(lines))
