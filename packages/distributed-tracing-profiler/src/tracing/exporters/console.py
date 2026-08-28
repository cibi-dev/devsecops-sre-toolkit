"""ASCII Terminal Waterfall / Cascade Visualizer for distributed traces.

Renders hierarchical span trees with proportional timeline duration bars.
"""

from __future__ import annotations

import io
import sys
from collections.abc import Sequence
from typing import TYPE_CHECKING, TextIO

from tracing.span import SpanStatus

if TYPE_CHECKING:
    from tracing.span import Span


def _format_duration(ms: float | None) -> str:
    """Format duration into human-readable string."""
    if ms is None:
        return "0.00ms"
    if ms < 0.001:
        return f"{ms * 1_000_000:.1f}ns"
    if ms < 1.0:
        return f"{ms * 1_000:.2f}µs"
    if ms < 1000.0:
        return f"{ms:.2f}ms"
    return f"{ms / 1000.0:.2f}s"


class ASCIIWaterfallExporter:
    """Renders high-clarity ASCII waterfall cascade charts."""

    def __init__(self, bar_width: int = 24) -> None:
        self.bar_width = max(10, bar_width)

    def render_cascade(self, spans: Sequence[Span]) -> str:
        """Generate ASCII waterfall tree visualization from spans."""
        if not spans:
            return "No spans to display."

        # Find trace boundaries
        min_start_ns = min(s.start_time_ns for s in spans)
        max_end_ns = max((s.end_time_ns or s.start_time_ns) for s in spans)
        total_trace_duration_ns = max(1, max_end_ns - min_start_ns)
        total_trace_duration_ms = total_trace_duration_ns / 1_000_000.0

        trace_id = spans[0].trace_id

        # Build parent-to-children tree
        children_map: dict[str | None, list[Span]] = {}
        span_by_id: dict[str, Span] = {s.span_id: s for s in spans}

        for s in spans:
            parent_id = s.parent_span_id
            if parent_id not in span_by_id:
                parent_id = None
            children_map.setdefault(parent_id, []).append(s)

        # Sort children by start_time_ns
        for p_id in children_map:
            children_map[p_id].sort(key=lambda x: x.start_time_ns)

        lines: list[str] = []
        lines.append("=" * 80)
        lines.append(
            f"🔍 TRACE: {trace_id} | Total Duration: {_format_duration(total_trace_duration_ms)} | Spans: {len(spans)}"
        )
        lines.append("-" * 80)

        def _render_bar(start_ns: int, end_ns: int) -> str:
            rel_start = (start_ns - min_start_ns) / total_trace_duration_ns
            rel_end = (end_ns - min_start_ns) / total_trace_duration_ns

            start_col = int(rel_start * self.bar_width)
            end_col = max(start_col + 1, int(rel_end * self.bar_width))
            end_col = min(self.bar_width, end_col)

            chars = []
            for i in range(self.bar_width):
                if i < start_col:
                    chars.append(" ")
                elif i < end_col:
                    chars.append("=")
                else:
                    chars.append(" ")
            return f"[{''.join(chars)}]"

        def _traverse(parent_id: str | None, prefix: str) -> None:
            children = children_map.get(parent_id, [])
            for idx, child in enumerate(children):
                is_last = idx == (len(children) - 1)
                connector = "└─ " if is_last else "├─ "
                child_prefix = prefix + ("   " if is_last else "│  ")

                end_ns = child.end_time_ns or child.start_time_ns
                bar = _render_bar(child.start_time_ns, end_ns)
                dur_str = _format_duration(child.duration_ms)
                status_icon = (
                    "🔴 ERROR"
                    if child.status == SpanStatus.ERROR
                    else ("🟢 OK" if child.status == SpanStatus.OK else "⚪ UNSET")
                )

                lines.append(
                    f"{prefix}{connector}{bar} {child.name} ({dur_str}) [{child.kind.value}] {status_icon}"
                )

                _traverse(child.span_id, child_prefix)

        # Traverse roots (parent_id is None)
        _traverse(None, "")
        lines.append("=" * 80)
        return "\n".join(lines)


class ConsoleSpanExporter:
    """Console exporter that prints waterfall charts to stdout or a stream."""

    def __init__(
        self, stream: TextIO | None = None, bar_width: int = 24
    ) -> None:
        self.stream = stream or sys.stdout
        self.visualizer = ASCIIWaterfallExporter(bar_width=bar_width)

    def export(self, spans: Sequence[Span]) -> None:
        """Export and print spans to the configured stream."""
        output = self.visualizer.render_cascade(spans)
        self.stream.write(output + "\n")
        self.stream.flush()
