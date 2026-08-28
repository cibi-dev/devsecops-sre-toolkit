"""Tests for CLI interface."""

import json
import tempfile
from unittest.mock import AsyncMock, patch
import pytest
from prober.cli import create_parser, main, run_probe, run_server_daemon, run_status, run_watch_certs
from prober.probes.dns import DNSProbeResult
from prober.probes.http import HTTPProbeResult
from prober.probes.ssl_cert import SSLCertProbeResult
from prober.probes.tcp import TCPProbeResult


def test_cli_parser():
    """Verify CLI parser options."""
    parser = create_parser()
    args = parser.parse_args(["probe", "https://example.com", "--type", "http"])
    assert args.subcommand == "probe"
    assert args.target == "https://example.com"
    assert args.type == "http"

    args_watch = parser.parse_args(["watch-certs", "example.com", "google.com"])
    assert args_watch.subcommand == "watch-certs"
    assert args_watch.hosts == ["example.com", "google.com"]

    args_server = parser.parse_args(["run-server", "--port", "9999"])
    assert args_server.subcommand == "run-server"
    assert args_server.port == 9999

    args_status = parser.parse_args(["status", "https://example.com"])
    assert args_status.subcommand == "status"


@pytest.mark.asyncio
async def test_cli_run_probe_http(capsys):
    """Test CLI probe subcommand for HTTP."""
    parser = create_parser()
    args = parser.parse_args(["probe", "https://api.test", "--type", "http", "--json"])

    with patch(
        "prober.probes.http.HTTPProbe.probe",
        AsyncMock(
            return_value=HTTPProbeResult(
                url="https://api.test",
                target_host="api.test",
                status_code=200,
                status="SUCCESS",
            )
        ),
    ):
        code = await run_probe(args)
        assert code == 0
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data["status"] == "SUCCESS"
        assert data["status_code"] == 200


@pytest.mark.asyncio
async def test_cli_run_probe_tcp(capsys):
    """Test CLI probe subcommand for TCP."""
    parser = create_parser()
    args = parser.parse_args(["probe", "127.0.0.1", "--type", "tcp", "-p", "8080"])

    with patch(
        "prober.probes.tcp.TCPProbe.probe",
        AsyncMock(
            return_value=TCPProbeResult(
                host="127.0.0.1",
                port=8080,
                connected=True,
                status="SUCCESS",
            )
        ),
    ):
        code = await run_probe(args)
        assert code == 0
        captured = capsys.readouterr()
        assert "TCPProbeResult" in captured.out


@pytest.mark.asyncio
async def test_cli_run_probe_ssl(capsys):
    """Test CLI probe subcommand for SSL."""
    parser = create_parser()
    args = parser.parse_args(["probe", "example.com", "--type", "ssl"])

    with patch(
        "prober.probes.ssl_cert.SSLCertProbe.probe",
        AsyncMock(
            return_value=SSLCertProbeResult(
                host="example.com",
                port=443,
                valid=True,
                status="SUCCESS",
            )
        ),
    ):
        code = await run_probe(args)
        assert code == 0
        captured = capsys.readouterr()
        assert "SSLCertProbeResult" in captured.out


@pytest.mark.asyncio
async def test_cli_run_probe_dns(capsys):
    """Test CLI probe subcommand for DNS."""
    parser = create_parser()
    args = parser.parse_args(["probe", "example.com", "--type", "dns", "-r", "A"])

    with patch(
        "prober.probes.dns.DNSProbe.probe",
        AsyncMock(
            return_value=DNSProbeResult(
                target="example.com",
                record_type="A",
                resolved_records=["93.184.216.34"],
                status="SUCCESS",
            )
        ),
    ):
        code = await run_probe(args)
        assert code == 0
        captured = capsys.readouterr()
        assert "DNSProbeResult" in captured.out


@pytest.mark.asyncio
async def test_cli_run_watch_certs_table_and_json(capsys):
    """Test CLI watch-certs subcommand."""
    parser = create_parser()
    args_json = parser.parse_args(["watch-certs", "example.com", "--json"])

    with patch(
        "prober.probes.ssl_cert.SSLCertProbe.probe",
        AsyncMock(
            return_value=SSLCertProbeResult(
                host="example.com",
                port=443,
                valid=True,
                days_until_expiration=60.0,
                alert_level="OK",
                status="SUCCESS",
            )
        ),
    ):
        code_json = await run_watch_certs(args_json)
        assert code_json == 0
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert len(data) == 1
        assert data[0]["alert_level"] == "OK"

    args_table = parser.parse_args(["watch-certs", "critical.com"])
    with patch(
        "prober.probes.ssl_cert.SSLCertProbe.probe",
        AsyncMock(
            return_value=SSLCertProbeResult(
                host="critical.com",
                port=443,
                valid=True,
                days_until_expiration=5.0,
                alert_level="EMERGENCY_7D",
                status="SUCCESS",
            )
        ),
    ):
        code_table = await run_watch_certs(args_table)
        assert code_table == 1
        captured = capsys.readouterr()
        assert "EMERGENCY_7D" in captured.out


@pytest.mark.asyncio
async def test_cli_run_status(capsys):
    """Test CLI status subcommand."""
    parser = create_parser()
    args = parser.parse_args(["status", "https://site1.local", "https://site2.local"])

    with patch(
        "prober.scheduler.ProbeScheduler.run_batch",
        AsyncMock(
            return_value=[
                HTTPProbeResult(url="https://site1.local", target_host="site1.local", status_code=200, status="SUCCESS"),
                HTTPProbeResult(url="https://site2.local", target_host="site2.local", status_code=500, status="HTTP_ERROR"),
            ]
        ),
    ):
        code = await run_status(args)
        assert code == 1
        captured = capsys.readouterr()
        assert "TARGET" in captured.out
        assert "site1.local" in captured.out

    args_json = parser.parse_args(["status", "https://site1.local", "--json"])
    with patch(
        "prober.scheduler.ProbeScheduler.run_batch",
        AsyncMock(
            return_value=[
                HTTPProbeResult(url="https://site1.local", target_host="site1.local", status_code=200, status="SUCCESS"),
            ]
        ),
    ):
        code_j = await run_status(args_json)
        assert code_j == 0
        captured_j = capsys.readouterr()
        data_j = json.loads(captured_j.out)
        assert len(data_j) == 1


@pytest.mark.asyncio
async def test_cli_run_server_daemon():
    """Test run_server_daemon with temporary config file and targets."""
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as tf:
        json.dump([{"name": "test_t", "probe_type": "http", "target": "https://api.test"}], tf)
        cfg_path = tf.name

    parser = create_parser()
    args = parser.parse_args(["run-server", "--port", "0", "--config", cfg_path, "--targets", "https://site.test"])

    with patch("prober.exporter.MetricsServer.start", AsyncMock()) as mock_srv_start:
        with patch("prober.exporter.MetricsServer.stop", AsyncMock()) as mock_srv_stop:
            with patch("prober.scheduler.ProbeScheduler.run_loop", AsyncMock()) as mock_loop:
                code = await run_server_daemon(args)
                assert code == 0
                mock_srv_start.assert_called_once()
                mock_loop.assert_called_once()
                mock_srv_stop.assert_called_once()


@pytest.mark.asyncio
async def test_cli_run_server_invalid_config():
    """Test run_server_daemon with invalid config file."""
    parser = create_parser()
    args = parser.parse_args(["run-server", "--config", "/non/existent/config.json"])

    with patch("prober.exporter.MetricsServer.start", AsyncMock()):
        with patch("prober.exporter.MetricsServer.stop", AsyncMock()):
            code = await run_server_daemon(args)
            assert code == 1


@pytest.mark.asyncio
async def test_cli_run_probe_unknown_type(capsys):
    """Test CLI probe subcommand with unsupported probe type."""
    parser = create_parser()
    args = parser.parse_args(["probe", "https://api.test", "--type", "http"])
    args.type = "unsupported_type"

    code = await run_probe(args)
    assert code == 1
    captured = capsys.readouterr()
    assert "Unknown probe type" in captured.err


@pytest.mark.asyncio
async def test_cli_run_server_no_targets(capsys):
    """Test run_server_daemon without targets prints warning."""
    parser = create_parser()
    args = parser.parse_args(["run-server"])

    with patch("prober.exporter.MetricsServer.start", AsyncMock()):
        with patch("prober.exporter.MetricsServer.stop", AsyncMock()):
            with patch("prober.scheduler.ProbeScheduler.run_loop", AsyncMock()):
                code = await run_server_daemon(args)
                assert code == 0
                captured = capsys.readouterr()
                assert "Warning: No targets specified" in captured.err


def test_cli_main_subcommands(monkeypatch):
    """Test CLI main function routing to all subcommands."""
    # 1. watch-certs
    with patch("prober.cli.run_watch_certs", AsyncMock(return_value=0)):
        with pytest.raises(SystemExit) as exc:
            main(["watch-certs", "example.com"])
        assert exc.value.code == 0

    # 2. run-server
    with patch("prober.cli.run_server_daemon", AsyncMock(return_value=0)):
        with pytest.raises(SystemExit) as exc:
            main(["run-server", "--port", "9115"])
        assert exc.value.code == 0

    # 3. status
    with patch("prober.cli.run_status", AsyncMock(return_value=0)):
        with pytest.raises(SystemExit) as exc:
            main(["status", "https://example.com"])
        assert exc.value.code == 0

    # 4. KeyboardInterrupt
    with patch("prober.cli.run_probe", AsyncMock(side_effect=KeyboardInterrupt())):
        with pytest.raises(SystemExit) as exc:
            main(["probe", "https://example.com"])
        assert exc.value.code == 130
