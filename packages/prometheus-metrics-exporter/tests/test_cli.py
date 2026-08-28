"""Unit tests for CLI subcommands and entrypoint."""

from __future__ import annotations

import io
import socket
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from exporter.cli import build_parser, main
from exporter.http_server import MetricsHTTPServer
from exporter.metrics_collector import MetricsCollector


def get_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def test_cli_help_no_subcommand(capsys: pytest.CaptureFixture):
    ret = main([])
    assert ret == 0
    captured = capsys.readouterr()
    assert "usage:" in captured.out or "usage:" in captured.err or "prometheus-exporter" in captured.out


def test_cli_collect_openmetrics(capsys: pytest.CaptureFixture):
    ret = main(["collect", "--format", "openmetrics"])
    assert ret == 0
    captured = capsys.readouterr()
    assert "# TYPE" in captured.out
    assert "# EOF" in captured.out


def test_cli_collect_prometheus(capsys: pytest.CaptureFixture):
    ret = main(["collect", "--format", "prometheus"])
    assert ret == 0
    captured = capsys.readouterr()
    assert "# TYPE" in captured.out
    assert "# EOF" not in captured.out


def test_cli_collect_json(capsys: pytest.CaptureFixture):
    ret = main(["collect", "--format", "json"])
    assert ret == 0
    captured = capsys.readouterr()
    assert "[" in captured.out and "]" in captured.out


def test_cli_eval_alerts(tmp_path: Path, capsys: pytest.CaptureFixture):
    yaml_file = tmp_path / "alerts.yaml"
    yaml_file.write_text("""
    groups:
      - name: test_grp
        rules:
          - alert: TestRule
            expr: "node_load1 >= 0"
            for: "0s"
    """, encoding="utf-8")

    ret = main(["eval-alerts", "--config", str(yaml_file), "--dry-run"])
    assert ret == 0
    captured = capsys.readouterr()
    assert "Evaluated 1 alert rule(s)" in captured.out
    assert "TestRule" in captured.out


def test_cli_eval_alerts_missing_file(capsys: pytest.CaptureFixture):
    ret = main(["eval-alerts", "--config", "/non/existent/path/alerts.yaml"])
    assert ret == 1
    captured = capsys.readouterr()
    assert "Error:" in captured.err


def test_cli_eval_alerts_invalid_syntax(tmp_path: Path, capsys: pytest.CaptureFixture):
    invalid_file = tmp_path / "bad.yaml"
    invalid_file.write_text("invalid: [yaml: broken", encoding="utf-8")

    ret = main(["eval-alerts", "--config", str(invalid_file)])
    assert ret == 1
    captured = capsys.readouterr()
    assert "Error loading alert configuration" in captured.err


def test_cli_status_success(capsys: pytest.CaptureFixture):
    port = get_free_port()
    collector = MetricsCollector()
    server = MetricsHTTPServer(host="127.0.0.1", port=port, collector=collector)
    server.start(background=True)
    time.sleep(0.1)

    try:
        ret = main(["status", "--url", f"http://127.0.0.1:{port}"])
        assert ret == 0
        captured = capsys.readouterr()
        assert "prometheus-metrics-exporter" in captured.out
    finally:
        server.stop()


def test_cli_status_failure(capsys: pytest.CaptureFixture):
    # Port unlikely to be running
    ret = main(["status", "--url", "http://127.0.0.1:59999", "--timeout", "0.5"])
    assert ret == 1
    captured = capsys.readouterr()
    assert "Connection failed" in captured.err


def test_cli_serve_missing_alerts_config(capsys: pytest.CaptureFixture):
    ret = main(["serve", "--alerts-config", "/path/that/does/not/exist.yaml"])
    assert ret == 1
    captured = capsys.readouterr()
    assert "Error: Alert configuration file not found" in captured.err


def test_cli_verbose_flag(capsys: pytest.CaptureFixture):
    ret = main(["-v", "collect", "--format", "json"])
    assert ret == 0


def test_cli_eval_alerts_with_webhook_dispatch(tmp_path: Path, capsys: pytest.CaptureFixture):
    yaml_file = tmp_path / "firing_alerts.yaml"
    yaml_file.write_text("""
    groups:
      - name: critical_grp
        rules:
          - alert: ImmediateCritical
            expr: "node_load1 >= 0"
            for: "0s"
            severity: "critical"
    """, encoding="utf-8")

    with patch("exporter.notifiers.webhook.httpx.Client.post") as mock_post:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_post.return_value = mock_resp

        ret = main([
            "eval-alerts",
            "--config", str(yaml_file),
            "--webhook-url", "https://hooks.example.com/alerts?token=123",
        ])
        assert ret == 0
        captured = capsys.readouterr()
        assert "FIRING" in captured.out
        assert "Webhook dispatched successfully" in captured.out


def test_cli_eval_alerts_webhook_failure(tmp_path: Path, capsys: pytest.CaptureFixture):
    yaml_file = tmp_path / "firing_alerts.yaml"
    yaml_file.write_text("""
    groups:
      - name: critical_grp
        rules:
          - alert: ImmediateCritical
            expr: "node_load1 >= 0"
            for: "0s"
            severity: "critical"
    """, encoding="utf-8")

    with patch("exporter.notifiers.webhook.httpx.Client.post") as mock_post:
        mock_resp = MagicMock()
        mock_resp.status_code = 500
        mock_post.return_value = mock_resp

        ret = main([
            "eval-alerts",
            "--config", str(yaml_file),
            "--webhook-url", "https://hooks.example.com/alerts",
        ])
        assert ret == 1
        captured = capsys.readouterr()
        assert "Webhook dispatch failed" in captured.err


def test_cli_serve_with_config_and_stop(tmp_path: Path, capsys: pytest.CaptureFixture):
    yaml_file = tmp_path / "alerts.yaml"
    yaml_file.write_text("""
    groups:
      - name: grp
        rules:
          - alert: Test
            expr: "node_load1 > 10"
    """, encoding="utf-8")

    port = get_free_port()

    # Mock server.start to raise KeyboardInterrupt
    with patch.object(MetricsHTTPServer, "start", side_effect=KeyboardInterrupt):
        ret = main([
            "serve",
            "--host", "127.0.0.1",
            "-p", str(port),
            "--alerts-config", str(yaml_file),
            "--webhook-url", "https://hooks.example.com/alerts?key=abc",
        ])
        assert ret == 0
        captured = capsys.readouterr()
        assert "Shutting down server" in captured.out
