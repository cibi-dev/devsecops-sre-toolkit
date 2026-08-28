"""Unit tests for CLI interface commands and output formats."""

import json
from pathlib import Path
from unittest.mock import MagicMock, patch
import httpx
import pytest

from deployer.cli import main
from deployer.config import DeployerConfig, DeploymentStatus, EnvironmentSlot, TargetEnvironmentConfig
from deployer.engine import DeploymentResult
from deployer.rollback import RollbackResult


@pytest.fixture
def cli_config_file(tmp_path: Path) -> Path:
    """Create a temporary JSON config file for CLI testing."""
    conf = {
        "blue": {"name": "blue", "host": "127.0.0.1", "port": 8081, "config_path": str(tmp_path / "blue.conf")},
        "green": {"name": "green", "host": "127.0.0.1", "port": 8082, "config_path": str(tmp_path / "green.conf")},
        "router": {"symlink_path": str(tmp_path / "active.conf"), "enable_proxy_reload": False},
        "allow_unprivileged": True,
    }
    (tmp_path / "blue.conf").write_text("blue", encoding="utf-8")
    (tmp_path / "green.conf").write_text("green", encoding="utf-8")
    cfg_file = tmp_path / "deployer.json"
    cfg_file.write_text(json.dumps(conf), encoding="utf-8")
    return cfg_file


def test_cli_no_args_shows_help(capsys):
    """Verify that invoking CLI without arguments prints help and exits with 0."""
    code = main([])
    captured = capsys.readouterr()
    assert code == 0
    assert "usage:" in captured.out.lower() or "subcommands" in captured.out.lower()


def test_cli_deploy_command_success(cli_config_file: Path, capsys):
    """Verify CLI deploy subcommand with JSON and text output."""
    mock_resp = httpx.Response(200, text="OK", request=httpx.Request("GET", "http://127.0.0.1:8082/health"))
    with patch.object(httpx.Client, "get", return_value=mock_resp):
        # JSON output
        code = main(["--config", str(cli_config_file), "deploy", "--target", "green", "--json"])
        captured = capsys.readouterr()
        assert code == 0
        data = json.loads(captured.out)
        assert data["success"] is True
        assert data["target_slot"] == "green"

        # Text output
        code_txt = main(["--config", str(cli_config_file), "deploy", "--target", "blue"])
        captured_txt = capsys.readouterr()
        assert code_txt == 0
        assert "Deployment Result: SUCCESS" in captured_txt.out


def test_cli_deploy_command_default_slot(cli_config_file: Path, capsys):
    """Verify CLI deploy subcommand without --target flag."""
    mock_resp = httpx.Response(200, text="OK", request=httpx.Request("GET", "http://127.0.0.1:8082/health"))
    with patch.object(httpx.Client, "get", return_value=mock_resp):
        code = main(["--config", str(cli_config_file), "deploy"])
        assert code == 0


def test_cli_switch_command(cli_config_file: Path, capsys):
    """Verify CLI switch subcommand with text and json formatting."""
    # Text output
    code = main(["--config", str(cli_config_file), "switch", "--target", "blue", "--force"])
    captured = capsys.readouterr()
    assert code == 0
    assert "Switch to BLUE" in captured.out

    # JSON output
    code_json = main(["--config", str(cli_config_file), "switch", "--target", "green", "--force", "--json"])
    captured_json = capsys.readouterr()
    assert code_json == 0
    data = json.loads(captured_json.out)
    assert data["success"] is True
    assert data["target_slot"] == "green"


def test_cli_rollback_command(cli_config_file: Path, capsys):
    """Verify CLI rollback subcommand with text and json formatting."""
    mock_resp = httpx.Response(200, text="OK", request=httpx.Request("GET", "http://127.0.0.1:8081/health"))
    with patch.object(httpx.Client, "get", return_value=mock_resp):
        # JSON output
        code = main(["--config", str(cli_config_file), "rollback", "--reason", "Test CLI Rollback", "--json"])
        captured = capsys.readouterr()
        assert code == 0
        data = json.loads(captured.out)
        assert data["success"] is True
        assert data["trigger_reason"] == "Test CLI Rollback"

        # Text output
        code_txt = main(["--config", str(cli_config_file), "rollback"])
        captured_txt = capsys.readouterr()
        assert code_txt == 0
        assert "Rollback: COMPLETED" in captured_txt.out


def test_cli_status_command(cli_config_file: Path, capsys):
    """Verify CLI status subcommand."""
    mock_resp = httpx.Response(200, text="OK", request=httpx.Request("GET", "http://127.0.0.1:8081/health"))
    with patch.object(httpx.Client, "get", return_value=mock_resp):
        code = main(["--config", str(cli_config_file), "status"])
        captured = capsys.readouterr()
        assert code == 0
        assert "BLUE/GREEN DEPLOYER STATUS" in captured.out

        code_json = main(["--config", str(cli_config_file), "status", "--json"])
        captured_json = capsys.readouterr()
        assert code_json == 0
        data = json.loads(captured_json.out)
        assert "active_slot" in data


def test_cli_health_command_slots(cli_config_file: Path, capsys):
    """Verify CLI health subcommand for individual and combined slots."""
    mock_resp = httpx.Response(200, text="OK", request=httpx.Request("GET", "http://127.0.0.1:8081/health"))
    with patch.object(httpx.Client, "get", return_value=mock_resp):
        # Blue slot json
        code = main(["--config", str(cli_config_file), "health", "--slot", "blue", "--json"])
        captured = capsys.readouterr()
        assert code == 0
        data = json.loads(captured.out)
        assert "blue" in data

        # Green slot text
        code_green = main(["--config", str(cli_config_file), "health", "--slot", "green"])
        captured_green = capsys.readouterr()
        assert code_green == 0
        assert "GREEN:" in captured_green.out

        # Active slot
        code_active = main(["--config", str(cli_config_file), "health", "--slot", "active"])
        assert code_active == 0


def test_cli_error_handling(capsys):
    """Verify CLI error handling when invalid config file is specified."""
    # Text error format
    code = main(["--config", "/invalid/non_existent_file.json", "status"])
    captured = capsys.readouterr()
    assert code == 2
    assert "Error:" in captured.err

    # JSON error format
    code_json = main(["--config", "/invalid/non_existent_file.json", "status", "--json"])
    captured_json = capsys.readouterr()
    assert code_json == 2
    assert "error" in captured_json.err
