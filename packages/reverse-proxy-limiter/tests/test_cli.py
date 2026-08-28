"""Unit tests for Command Line Interface (CLI)."""

import pytest
from proxy.cli import main


def test_cli_help(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--help"])
    assert exc.value.code == 0
    captured = capsys.readouterr()
    assert "reverse-proxy-limiter" in captured.out


def test_cli_version(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    captured = capsys.readouterr()
    assert "0.1.0" in captured.out


def test_cli_no_args(capsys):
    code = main([])
    assert code == 0
    captured = capsys.readouterr()
    assert "usage:" in captured.out


def test_cli_status(capsys):
    code = main(["status"])
    assert code == 0
    captured = capsys.readouterr()
    assert "reverse-proxy-limiter" in captured.out
    assert "OpenMetrics" in captured.out


def test_cli_test_upstream(capsys):
    # Test with non-existing endpoint, should handle gracefully
    code = main(["test-upstream", "http://127.0.0.1:54321", "--timeout", "0.1"])
    assert code == 1
    captured = capsys.readouterr()
    assert "Probing 1 upstream target(s)" in captured.out


def test_cli_benchmark(capsys):
    code = main(["benchmark", "-n", "20", "-c", "5"])
    assert code == 0
    captured = capsys.readouterr()
    assert "Benchmark Results" in captured.out
    assert "Throughput" in captured.out
