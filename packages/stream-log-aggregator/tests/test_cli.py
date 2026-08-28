"""Tests for stream-log-aggregator CLI commands and entry points."""

import asyncio
import io
import sys
import unittest.mock
import pytest
from aggregator.cli import (
    build_parser,
    main,
    run_benchmark,
    run_start,
    run_status,
    run_test_input,
)


class TestCLI:
    """Test suite for CLI interfaces."""

    def test_cli_parser_help_and_version(self):
        """Verify CLI parser builds and validates arguments."""
        parser = build_parser()
        assert parser.prog == "stream-log-aggregator"

        # start subcommand
        args_start = parser.parse_args([
            "start",
            "--tcp-port", "5140",
            "--udp-port", "5140",
            "--unix-socket", "var_run_syslog.sock",
            "--tail-file", "var_log_test.log",
            "--output-file", "var_log_out.log",
            "--output-webhook", "http://localhost:8080",
            "--workers", "8",
        ])
        assert args_start.command == "start"
        assert args_start.tcp_port == 5140
        assert args_start.udp_port == 5140
        assert args_start.unix_socket == "var_run_syslog.sock"
        assert args_start.tail_file == "var_log_test.log"
        assert args_start.output_file == "var_log_out.log"
        assert args_start.output_webhook == "http://localhost:8080"
        assert args_start.workers == 8

        # test-input subcommand
        args_test = parser.parse_args(["test-input", "--protocol", "direct"])
        assert args_test.command == "test-input"
        assert args_test.protocol == "direct"

        # benchmark subcommand
        args_bench = parser.parse_args(["benchmark", "--events", "1000"])
        assert args_bench.command == "benchmark"
        assert args_bench.events == 1000

        # status subcommand
        args_status = parser.parse_args(["status"])
        assert args_status.command == "status"

    def test_run_status(self, capsys):
        """Verify status command output."""
        code = run_status()
        assert code == 0
        captured = capsys.readouterr()
        assert "stream-log-aggregator version" in captured.out
        assert "Status: Daemon ready." in captured.out

    @pytest.mark.asyncio
    async def test_run_test_input_direct(self, capsys):
        """Verify test-input with direct protocol prints sanitized event."""
        parser = build_parser()
        args = parser.parse_args(["test-input", "--protocol", "direct"])
        code = await run_test_input(args)
        assert code == 0
        captured = capsys.readouterr()
        assert "[+] Processed & Sanitized Event:" in captured.out
        assert "[REDACTED]" in captured.out

    @pytest.mark.asyncio
    async def test_run_test_input_tcp(self, capsys):
        """Verify test-input with tcp protocol."""
        # Mock open_connection
        async def mock_open_connection(host, port):
            mock_writer = unittest.mock.AsyncMock()
            mock_reader = unittest.mock.AsyncMock()
            return mock_reader, mock_writer

        with unittest.mock.patch("asyncio.open_connection", side_effect=mock_open_connection):
            parser = build_parser()
            args = parser.parse_args(["test-input", "--protocol", "tcp", "--port", "5140"])
            code = await run_test_input(args)
            assert code == 0
            captured = capsys.readouterr()
            assert "Sent via TCP" in captured.out

    @pytest.mark.asyncio
    async def test_run_test_input_udp(self, capsys):
        """Verify test-input with udp protocol."""
        mock_transport = unittest.mock.MagicMock()

        async def mock_create_endpoint(protocol_factory, remote_addr):
            protocol = protocol_factory()
            protocol.connection_made(mock_transport)
            protocol.connection_lost(None)
            return mock_transport, protocol

        loop = asyncio.get_running_loop()
        with unittest.mock.patch.object(loop, "create_datagram_endpoint", side_effect=mock_create_endpoint):
            parser = build_parser()
            args = parser.parse_args(["test-input", "--protocol", "udp", "--port", "5140"])
            code = await run_test_input(args)
            assert code == 0
            captured = capsys.readouterr()
            assert "Sent via UDP" in captured.out

    @pytest.mark.asyncio
    async def test_run_benchmark_cli(self, capsys):
        """Verify benchmark CLI executes with synthetic events."""
        parser = build_parser()
        args = parser.parse_args(["benchmark", "--events", "500", "--workers", "2", "--batch-size", "100"])
        code = await run_benchmark(args)
        assert code == 0
        captured = capsys.readouterr()
        assert "[+] Benchmark completed:" in captured.out
        assert "Throughput" in captured.out

    @pytest.mark.asyncio
    async def test_run_start_brief_execution(self, capsys, tmp_path):
        """Verify start command initializes pipeline and shuts down."""
        out_file = str(tmp_path / "cli_out.log")
        parser = build_parser()
        args = parser.parse_args([
            "start",
            "--tcp-port", "0",
            "--udp-port", "0",
            "--output-file", out_file,
            "--workers", "1",
        ])

        with unittest.mock.patch("asyncio.Event.wait", new_callable=unittest.mock.AsyncMock):
            code = await run_start(args)
            assert code == 0

        captured = capsys.readouterr()
        assert "Starting stream-log-aggregator" in captured.out

    def test_main_subcommand_dispatch(self):
        """Verify main() dispatches to subcommands."""
        with unittest.mock.patch("aggregator.cli.run_status", return_value=0) as m_status:
            code = main(["status"])
            assert code == 0
            m_status.assert_called_once()

    def test_main_no_args(self, capsys):
        """Verify main() prints help when invoked without arguments."""
        code = main([])
        assert code == 0
        captured = capsys.readouterr()
        assert "usage: stream-log-aggregator" in captured.out
