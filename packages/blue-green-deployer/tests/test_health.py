"""Unit tests for active HTTP health check probe with retries and validations."""

from unittest.mock import MagicMock, patch
import httpx
import pytest

from deployer.config import DeployerConfig, EnvironmentSlot, HealthCheckConfig, TargetEnvironmentConfig
from deployer.health import HealthChecker, HealthCheckResult, HealthProbeResult


def test_probe_once_success():
    """Verify successful probe with 200 OK."""
    checker = HealthChecker(HealthCheckConfig(expected_status=200, timeout_seconds=1.0))

    mock_resp = httpx.Response(status_code=200, text='{"status": "ok"}', request=httpx.Request("GET", "http://127.0.0.1:8081/health"))
    with patch.object(httpx.Client, "get", return_value=mock_resp):
        res = checker.probe_once("http://127.0.0.1:8081/health")
        assert res.success is True
        assert res.status_code == 200
        assert res.error_message is None
        assert "ok" in res.body_preview


def test_probe_once_status_mismatch():
    """Verify failure when status code does not match expected_status."""
    checker = HealthChecker(HealthCheckConfig(expected_status=200))

    mock_resp = httpx.Response(status_code=503, text="Service Unavailable", request=httpx.Request("GET", "http://127.0.0.1:8081/health"))
    with patch.object(httpx.Client, "get", return_value=mock_resp):
        res = checker.probe_once("http://127.0.0.1:8081/health")
        assert res.success is False
        assert res.status_code == 503
        assert "503" in res.error_message


def test_probe_once_body_contains_check():
    """Verify expected body substring validation."""
    checker = HealthChecker(HealthCheckConfig(expected_status=200, expected_body_contains="HEALTHY_V2"))

    # Matching case
    mock_ok = httpx.Response(status_code=200, text='{"state": "HEALTHY_V2"}', request=httpx.Request("GET", "http://127.0.0.1:8081/health"))
    with patch.object(httpx.Client, "get", return_value=mock_ok):
        res = checker.probe_once("http://127.0.0.1:8081/health")
        assert res.success is True

    # Missing substring case
    mock_bad = httpx.Response(status_code=200, text='{"state": "STARTING"}', request=httpx.Request("GET", "http://127.0.0.1:8081/health"))
    with patch.object(httpx.Client, "get", return_value=mock_bad):
        res = checker.probe_once("http://127.0.0.1:8081/health")
        assert res.success is False
        assert "HEALTHY_V2" in res.error_message


def test_probe_once_timeout_exception():
    """Verify handling of HTTP timeout exception."""
    checker = HealthChecker(HealthCheckConfig(timeout_seconds=0.1))

    with patch.object(httpx.Client, "get", side_effect=httpx.TimeoutException("Read timed out")):
        res = checker.probe_once("http://127.0.0.1:8081/health")
        assert res.success is False
        assert res.status_code is None
        assert "timeout" in res.error_message.lower()


def test_probe_once_network_error():
    """Verify handling of network connection refused error."""
    checker = HealthChecker()

    with patch.object(httpx.Client, "get", side_effect=httpx.ConnectError("Connection refused")):
        res = checker.probe_once("http://127.0.0.1:8081/health")
        assert res.success is False
        assert "ConnectError" in res.error_message or "Connection refused" in res.error_message


def test_probe_once_generic_exception():
    """Verify handling of unexpected generic exceptions during probe."""
    checker = HealthChecker()
    with patch.object(httpx.Client, "get", side_effect=RuntimeError("Socket failure")):
        res = checker.probe_once("http://127.0.0.1:8081/health")
        assert res.success is False
        assert "Unexpected health probe error" in res.error_message


def test_check_target_consecutive_successes():
    """Verify requiring multiple consecutive successes."""
    checker = HealthChecker(HealthCheckConfig(
        max_retries=5,
        retry_interval_seconds=0.01,
        consecutive_successes_required=2
    ))
    target = TargetEnvironmentConfig(name=EnvironmentSlot.GREEN, host="127.0.0.1", port=8082)

    responses = [
        httpx.Response(500, text="err", request=httpx.Request("GET", target.url)),
        httpx.Response(200, text="ok", request=httpx.Request("GET", target.url)),
        httpx.Response(200, text="ok", request=httpx.Request("GET", target.url)),
    ]

    with patch.object(httpx.Client, "get", side_effect=responses):
        res = checker.check_target(target)
        assert res.healthy is True
        assert res.consecutive_successes == 2
        assert res.total_attempts == 3
        assert len(res.history) == 3


def test_check_target_retries_exhausted():
    """Verify failure result when all retries fail."""
    checker = HealthChecker(HealthCheckConfig(
        max_retries=3,
        retry_interval_seconds=0.01,
        consecutive_successes_required=2
    ))
    target = TargetEnvironmentConfig(name=EnvironmentSlot.BLUE, host="127.0.0.1", port=8081)

    with patch.object(httpx.Client, "get", side_effect=httpx.ConnectError("Connection refused")):
        res = checker.check_target(target)
        assert res.healthy is False
        assert res.consecutive_successes == 0
        assert res.total_attempts == 3
        assert "failed" in res.message.lower()


def test_check_slot_helper():
    """Verify check_slot method resolves configuration correctly."""
    cfg = DeployerConfig()
    checker = HealthChecker(cfg.health)

    mock_resp = httpx.Response(status_code=200, text="ok", request=httpx.Request("GET", cfg.blue.url))
    with patch.object(httpx.Client, "get", return_value=mock_resp):
        res = checker.check_slot(EnvironmentSlot.BLUE, cfg)
        assert res.healthy is True
        assert res.slot == EnvironmentSlot.BLUE
        dict_output = res.to_dict()
        assert dict_output["slot"] == "blue"
        assert dict_output["healthy"] is True
