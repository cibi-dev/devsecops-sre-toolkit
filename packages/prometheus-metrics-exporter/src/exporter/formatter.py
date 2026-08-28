"""Strict OpenMetrics and standard Prometheus exposition format serializer and parser.

Conforms to OpenMetrics 1.0.0 and Prometheus Text Format 0.0.4 specifications.
"""

from __future__ import annotations

import json
import math
import re
from typing import Any, Dict, List, Optional

from .metrics_collector import MetricFamily, MetricSample, MetricType


class OpenMetricsFormatter:
    """Serializes metric families to OpenMetrics / Prometheus text and JSON formats."""

    @staticmethod
    def _escape_help(text: str) -> str:
        """Escapes backslashes and newlines in help text according to OpenMetrics spec."""
        return text.replace("\\", "\\\\").replace("\n", "\\n")

    @staticmethod
    def _escape_label_value(val: str) -> str:
        """Escapes backslashes, double-quotes, and newlines in label values."""
        return (
            str(val)
            .replace("\\", "\\\\")
            .replace('"', '\\"')
            .replace("\n", "\\n")
        )

    @staticmethod
    def _format_float(val: float) -> str:
        """Formats floating point values handling NaN, +Inf, -Inf, and integers cleanly."""
        if math.isnan(val):
            return "nan"
        if math.isinf(val):
            return "+Inf" if val > 0 else "-Inf"
        # If float represents an exact integer (e.g. 10.0), preserve standard float or integer format
        if val.is_integer():
            return f"{int(val)}"
        return f"{val:.6g}"

    @classmethod
    def format_sample(
        cls,
        sample: MetricSample,
        openmetrics: bool = True,
    ) -> str:
        """Formats a single MetricSample with labels and optional timestamp."""
        labels_str = ""
        if sample.labels:
            sorted_labels = sorted(sample.labels.items())
            pairs = [
                f'{k}="{cls._escape_label_value(v)}"'
                for k, v in sorted_labels
            ]
            labels_str = "{" + ",".join(pairs) + "}"

        val_str = cls._format_float(sample.value)

        if sample.timestamp is not None:
            ts_str = f" {sample.timestamp:.3f}" if openmetrics else f" {int(sample.timestamp * 1000)}"
            return f"{sample.name}{labels_str} {val_str}{ts_str}"
        return f"{sample.name}{labels_str} {val_str}"

    @classmethod
    def format_family(
        cls,
        family: MetricFamily,
        openmetrics: bool = True,
    ) -> str:
        """Formats a MetricFamily with HELP, TYPE, optional UNIT, and all samples."""
        lines: List[str] = []

        # HELP
        if family.help_text:
            escaped_help = cls._escape_help(family.help_text)
            lines.append(f"# HELP {family.name} {escaped_help}")

        # TYPE
        type_str = family.metric_type.value
        lines.append(f"# TYPE {family.name} {type_str}")

        # UNIT (OpenMetrics only)
        if openmetrics and family.unit:
            lines.append(f"# UNIT {family.name} {family.unit}")

        # Samples
        for sample in family.samples:
            lines.append(cls.format_sample(sample, openmetrics=openmetrics))

        return "\n".join(lines)

    @classmethod
    def format_openmetrics(cls, families: List[MetricFamily]) -> str:
        """Renders metric families according to OpenMetrics 1.0.0 specification (terminating in # EOF)."""
        if not families:
            return "# EOF\n"

        chunks = [cls.format_family(fam, openmetrics=True) for fam in families]
        body = "\n".join(chunks)
        return f"{body}\n# EOF\n"

    @classmethod
    def format_prometheus(cls, families: List[MetricFamily]) -> str:
        """Renders metric families according to standard Prometheus text format 0.0.4."""
        if not families:
            return ""

        chunks = [cls.format_family(fam, openmetrics=False) for fam in families]
        return "\n".join(chunks) + "\n"

    @classmethod
    def format_json(cls, families: List[MetricFamily]) -> str:
        """Renders metric families as a structured JSON object."""
        result: List[Dict[str, Any]] = []
        for fam in families:
            fam_dict: Dict[str, Any] = {
                "name": fam.name,
                "help": fam.help_text,
                "type": fam.metric_type.value,
                "unit": fam.unit,
                "samples": [
                    {
                        "name": s.name,
                        "value": s.value,
                        "labels": s.labels,
                        "timestamp": s.timestamp,
                    }
                    for s in fam.samples
                ],
            }
            result.append(fam_dict)
        return json.dumps(result, indent=2)

    @classmethod
    def parse_openmetrics(cls, text: str) -> List[MetricFamily]:
        """Parses OpenMetrics / Prometheus text representation back into MetricFamily objects."""
        families: Dict[str, MetricFamily] = {}
        current_help: Dict[str, str] = {}
        current_type: Dict[str, MetricType] = {}
        current_unit: Dict[str, str] = {}

        label_pattern = re.compile(r'([a-zA-Z_][a-zA-Z0-9_]*)="((?:[^"\\]|\\.)*)"')

        for raw_line in text.splitlines():
            line = raw_line.strip()
            if not line or line == "# EOF":
                continue

            if line.startswith("# HELP "):
                parts = line[7:].split(" ", 1)
                metric_name = parts[0]
                help_text = parts[1] if len(parts) > 1 else ""
                # Unescape \n and \\
                help_text = help_text.replace("\\n", "\n").replace("\\\\", "\\")
                current_help[metric_name] = help_text
                continue

            if line.startswith("# TYPE "):
                parts = line[7:].split(" ", 1)
                metric_name = parts[0]
                type_val = parts[1].lower() if len(parts) > 1 else "untyped"
                try:
                    current_type[metric_name] = MetricType(type_val)
                except ValueError:
                    current_type[metric_name] = MetricType.UNTYPED
                continue

            if line.startswith("# UNIT "):
                parts = line[7:].split(" ", 1)
                metric_name = parts[0]
                unit_val = parts[1] if len(parts) > 1 else ""
                current_unit[metric_name] = unit_val
                continue

            if line.startswith("#"):
                continue

            # Sample line: name{labels} value [timestamp]
            space_idx = line.find(" ")
            if space_idx == -1:
                continue

            name_and_labels = line[:space_idx]
            rest = line[space_idx:].strip().split()
            if not rest:
                continue

            val_str = rest[0]
            try:
                if val_str == "+Inf" or val_str == "Inf":
                    val = float("inf")
                elif val_str == "-Inf":
                    val = float("-inf")
                elif val_str == "nan":
                    val = float("nan")
                else:
                    val = float(val_str)
            except ValueError:
                continue

            ts: Optional[float] = None
            if len(rest) > 1:
                try:
                    ts = float(rest[1])
                except ValueError:
                    pass

            # Extract metric base name and labels
            if "{" in name_and_labels and name_and_labels.endswith("}"):
                sample_name, label_chunk = name_and_labels[:-1].split("{", 1)
                labels: Dict[str, str] = {}
                for match in label_pattern.finditer(label_chunk):
                    k, v = match.group(1), match.group(2)
                    v_unescaped = v.replace('\\"', '"').replace("\\n", "\n").replace("\\\\", "\\")
                    labels[k] = v_unescaped
            else:
                sample_name = name_and_labels
                labels = {}

            # Determine family name (strip _total for counters if family was defined without it)
            family_name = sample_name
            if family_name not in current_type and family_name.endswith("_total"):
                candidate = family_name[:-6]
                if candidate in current_type:
                    family_name = candidate

            if family_name not in families:
                fam_type = current_type.get(family_name, MetricType.UNTYPED)
                fam_help = current_help.get(family_name, "")
                fam_unit = current_unit.get(family_name)
                families[family_name] = MetricFamily(
                    name=family_name,
                    help_text=fam_help,
                    metric_type=fam_type,
                    unit=fam_unit,
                )

            families[family_name].add_sample(
                name=sample_name,
                value=val,
                labels=labels,
                timestamp=ts,
            )

        return list(families.values())
