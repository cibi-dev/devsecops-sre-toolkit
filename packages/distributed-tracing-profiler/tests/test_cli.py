"""Unit tests for the Command Line Interface (CLI)."""

from __future__ import annotations

import json
from typing import Any

import pytest
from tracing.cli import main


def test_cli_help(capsys: Any) -> None:
    with pytest.raises(SystemExit) as excinfo:
        main(["--help"])
    assert excinfo.value.code == 0
    captured = capsys.readouterr()
    assert "distributed-tracing-profiler" in captured.out


def test_cli_no_args(capsys: Any) -> None:
    code = main([])
    assert code == 0
    captured = capsys.readouterr()
    assert "usage:" in captured.out


def test_cli_inspect_valid(capsys: Any) -> None:
    code = main([
        "inspect",
        "--traceparent",
        "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
        "--tracestate",
        "rojo=1,congo=2",
    ])
    assert code == 0
    captured = capsys.readouterr()
    assert "VALID W3C TraceContext traceparent" in captured.out
    assert "VALID W3C TraceContext tracestate" in captured.out
    assert "4bf92f3577b34da6a3ce929d0e0e4736" in captured.out


def test_cli_inspect_invalid(capsys: Any) -> None:
    code = main(["inspect", "--traceparent", "invalid_header"])
    assert code == 0
    captured = capsys.readouterr()
    assert "INVALID traceparent" in captured.out


def test_cli_inspect_missing_args(capsys: Any) -> None:
    code = main(["inspect"])
    assert code == 1
    captured = capsys.readouterr()
    assert "Error: Please provide at least" in captured.out


def test_cli_trace_simulation(capsys: Any, tmp_path: Any) -> None:
    json_path = str(tmp_path / "out_trace.json")
    code = main(["trace", "--output-json", json_path])
    assert code == 0
    captured = capsys.readouterr()
    assert "TRACE:" in captured.out
    assert "HTTP GET /api/v1/orders/1042" in captured.out
    assert "Exported OpenTelemetry JSON" in captured.out

    with open(json_path, encoding="utf-8") as f:
        data = json.load(f)
        assert "resourceSpans" in data


def test_cli_trace_simulate_error(capsys: Any) -> None:
    code = main(["trace", "--simulate-error"])
    assert code == 0
    captured = capsys.readouterr()
    assert "🔴 ERROR" in captured.out


def test_cli_benchmark(capsys: Any) -> None:
    code = main(["benchmark", "--iterations", "500"])
    assert code == 0
    captured = capsys.readouterr()
    assert "BENCHMARK RESULTS" in captured.out
    assert "Avg Overhead per Span" in captured.out


def test_cli_profile_synthetic(capsys: Any) -> None:
    code = main(["profile", "--samples", "200"])
    assert code == 0
    captured = capsys.readouterr()
    assert "STATISTICAL LATENCY PROFILE" in captured.out
    assert "p50:" in captured.out
    assert "p99:" in captured.out


def test_cli_profile_json_file(capsys: Any, tmp_path: Any) -> None:
    json_path = str(tmp_path / "durations.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump([10.5, 20.2, 15.3, 30.1, 5.0], f)

    code = main(["profile", "--input-json", json_path])
    assert code == 0
    captured = capsys.readouterr()
    assert "Samples: 5" in captured.out
    assert "p50:" in captured.out


def test_cli_profile_json_invalid(capsys: Any, tmp_path: Any) -> None:
    json_path = str(tmp_path / "invalid.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump({"unsupported": "data"}, f)

    code = main(["profile", "--input-json", json_path])
    assert code == 1
