"""Unit and integration tests for MetricsHTTPServer."""

from __future__ import annotations

import json
import socket
import time
from typing import Generator
from unittest.mock import MagicMock

import httpx
import pytest

from exporter.alert_evaluator import AlertEvaluator, AlertRuleModel
from exporter.http_server import MetricsHTTPServer, create_server_app
from exporter.metrics_collector import MetricFamily, MetricsCollector, MetricType
from exporter.notifiers.webhook import WebhookNotifier


def get_free_port() -> int:
    """Finds an available local TCP port."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
def mock_collector() -> MetricsCollector:
    collector = MagicMock(spec=MetricsCollector)
    fam = MetricFamily(
        name="test_gauge",
        help_text="Test gauge metric",
        metric_type=MetricType.GAUGE,
    )
    fam.add_sample("test_gauge", 42.0, {"env": "test"})
    collector.collect_all.return_value = [fam]
    return collector


@pytest.fixture
def mock_evaluator() -> AlertEvaluator:
    evaluator = AlertEvaluator()
    rule = AlertRuleModel(
        alert="HighLoad",
        expr="test_gauge > 40",
        for_duration="0s",
        severity="critical",
        labels={"team": "sre"},
    )
    evaluator.add_rule(rule)
    return evaluator


@pytest.fixture
def running_server(
    mock_collector: MetricsCollector,
    mock_evaluator: AlertEvaluator,
) -> Generator[str, None, None]:
    port = get_free_port()
    server = MetricsHTTPServer(
        host="127.0.0.1",
        port=port,
        collector=mock_collector,
        evaluator=mock_evaluator,
        openmetrics=True,
    )
    server.start(background=True)
    time.sleep(0.1)
    base_url = f"http://127.0.0.1:{port}"
    yield base_url
    server.stop()


def test_get_metrics_openmetrics(running_server: str):
    with httpx.Client() as client:
        resp = client.get(f"{running_server}/metrics")
        assert resp.status_code == 200
        assert "application/openmetrics-text" in resp.headers.get("Content-Type", "")
        assert "test_gauge" in resp.text
        assert resp.text.endswith("# EOF\n")


def test_get_metrics_prometheus_negotiation(running_server: str):
    headers = {"Accept": "text/plain; version=0.0.4; q=0.5"}
    with httpx.Client() as client:
        resp = client.get(f"{running_server}/metrics", headers=headers)
        assert resp.status_code == 200
        assert "text/plain" in resp.headers.get("Content-Type", "")
        assert "# EOF" not in resp.text


def test_get_health_and_livez(running_server: str):
    with httpx.Client() as client:
        for path in ("/health", "/livez", "/healthz"):
            resp = client.get(f"{running_server}{path}")
            assert resp.status_code == 200
            data = resp.json()
            assert data["status"] == "healthy"
            assert "uptime_seconds" in data


def test_get_readyz(running_server: str):
    with httpx.Client() as client:
        resp = client.get(f"{running_server}/readyz")
        assert resp.status_code == 200
        assert resp.json() == {"status": "ready"}


def test_get_status_and_alerts(running_server: str):
    with httpx.Client() as client:
        for path in ("/status", "/alerts"):
            resp = client.get(f"{running_server}{path}")
            assert resp.status_code == 200
            data = resp.json()
            assert data["server"] == "prometheus-metrics-exporter"
            assert "alerts" in data
            assert len(data["alerts"]) == 1
            assert data["alerts"][0]["alert"] == "HighLoad"


def test_get_index_html(running_server: str):
    with httpx.Client() as client:
        resp = client.get(f"{running_server}/")
        assert resp.status_code == 200
        assert "text/html" in resp.headers.get("Content-Type", "")
        assert "Prometheus Metrics Exporter" in resp.text


def test_post_eval_alerts(running_server: str):
    with httpx.Client() as client:
        resp = client.post(f"{running_server}/alerts/eval", json={})
        assert resp.status_code == 200
        data = resp.json()
        assert data["evaluated_rules"] == 1
        assert data["firing_rules"] == 1
        assert data["alerts"][0]["state"] == "firing"


def test_not_found_endpoints(running_server: str):
    with httpx.Client() as client:
        resp = client.get(f"{running_server}/non_existent")
        assert resp.status_code == 404
        assert resp.json()["error"] == "Not Found"

        resp_post = client.post(f"{running_server}/unknown_post", json={})
        assert resp_post.status_code == 404


def test_unsupported_http_methods(running_server: str):
    with httpx.Client() as client:
        resp_put = client.put(f"{running_server}/metrics")
        assert resp_put.status_code == 405

        resp_del = client.delete(f"{running_server}/metrics")
        assert resp_del.status_code == 405


def test_post_eval_alerts_no_evaluator():
    port = get_free_port()
    server = MetricsHTTPServer(host="127.0.0.1", port=port, evaluator=None)
    server.start(background=True)
    time.sleep(0.1)

    try:
        with httpx.Client() as client:
            resp = client.post(f"http://127.0.0.1:{port}/alerts/eval", json={})
            assert resp.status_code == 400
            assert "No alert evaluator configured" in resp.json()["error"]
    finally:
        server.stop()


def test_server_background_eval_loop_with_notifier():
    port = get_free_port()
    collector = MagicMock(spec=MetricsCollector)
    fam = MetricFamily(name="crit_metric", help_text="Crit", metric_type=MetricType.GAUGE)
    fam.add_sample("crit_metric", 100.0)
    collector.collect_all.return_value = [fam]

    evaluator = AlertEvaluator()
    evaluator.add_rule(AlertRuleModel(alert="InstantCrit", expr="crit_metric > 50", for_duration="0s"))

    mock_notifier = MagicMock(spec=WebhookNotifier)

    server = MetricsHTTPServer(
        host="127.0.0.1",
        port=port,
        collector=collector,
        evaluator=evaluator,
        notifier=mock_notifier,
        eval_interval_seconds=0.1,
    )
    server.start(background=True)
    time.sleep(0.3)
    server.stop()

    assert mock_notifier.dispatch.called


def test_context_manager_and_factory():
    port = get_free_port()
    server = create_server_app(host="127.0.0.1", port=port)
    with server as srv:
        addr = srv.server_address
        assert addr[0] == "127.0.0.1"
        assert addr[1] == port
        with httpx.Client() as client:
            resp = client.get(f"http://127.0.0.1:{port}/health")
            assert resp.status_code == 200
