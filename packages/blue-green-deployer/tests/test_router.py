"""Unit tests for TrafficRouter atomic symlink switching and safe reload."""

import os
import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch
import pytest

from deployer.config import DeployerConfig, EnvironmentSlot, RouterConfig, TargetEnvironmentConfig
from deployer.router import PrivilegeError, ProxyReloadError, SwitchResult, TrafficRouter


def test_atomic_symlink_switching(tmp_path: Path):
    """Verify atomic symlink creation and replacement without downtime."""
    symlink_file = tmp_path / "active_upstream.conf"
    backup_dir = tmp_path / "backups"
    blue_conf = tmp_path / "upstream_blue.conf"
    green_conf = tmp_path / "upstream_green.conf"

    blue_conf.write_text("server 127.0.0.1:8081;\n", encoding="utf-8")
    green_conf.write_text("server 127.0.0.1:8082;\n", encoding="utf-8")

    router_cfg = RouterConfig(
        symlink_path=symlink_file,
        backup_dir=backup_dir,
        enable_proxy_reload=False,
    )
    router = TrafficRouter(config=router_cfg, allow_unprivileged=True)

    # 1. Switch to BLUE
    res_blue = router.switch_to_target(
        target_slot=EnvironmentSlot.BLUE,
        target_config_path=blue_conf,
    )
    assert res_blue.success is True
    assert symlink_file.is_symlink()
    assert os.readlink(str(symlink_file)) == str(blue_conf.resolve())

    # 2. Switch to GREEN atomically
    res_green = router.switch_to_target(
        target_slot=EnvironmentSlot.GREEN,
        target_config_path=green_conf,
        from_slot=EnvironmentSlot.BLUE,
    )
    assert res_green.success is True
    assert symlink_file.is_symlink()
    assert os.readlink(str(symlink_file)) == str(green_conf.resolve())
    assert res_green.backup_path is not None
    assert res_green.backup_path.exists()


def test_get_active_slot(tmp_path: Path):
    """Verify determining active slot from symlink resolution."""
    symlink_file = tmp_path / "active_upstream.conf"
    blue_conf = tmp_path / "upstream_blue.conf"
    green_conf = tmp_path / "upstream_green.conf"
    blue_conf.write_text("blue", encoding="utf-8")
    green_conf.write_text("green", encoding="utf-8")

    deployer_cfg = DeployerConfig(
        blue=TargetEnvironmentConfig(name=EnvironmentSlot.BLUE, host="127.0.0.1", port=8081, config_path=blue_conf),
        green=TargetEnvironmentConfig(name=EnvironmentSlot.GREEN, host="127.0.0.1", port=8082, config_path=green_conf),
        router=RouterConfig(symlink_path=symlink_file, enable_proxy_reload=False),
        allow_unprivileged=True,
    )
    router = TrafficRouter(config=deployer_cfg.router, allow_unprivileged=True)

    assert router.get_active_slot(deployer_cfg) is None

    # Switch to green
    router.switch_to_target(EnvironmentSlot.GREEN, green_conf)
    assert router.get_active_slot(deployer_cfg) == EnvironmentSlot.GREEN

    # Switch to blue
    router.switch_to_target(EnvironmentSlot.BLUE, blue_conf)
    assert router.get_active_slot(deployer_cfg) == EnvironmentSlot.BLUE


def test_get_active_slot_unknown_target(tmp_path: Path):
    """Verify unknown slot returns None when symlink points to unfamiliar file."""
    symlink_file = tmp_path / "active_upstream.conf"
    other_conf = tmp_path / "other.conf"
    other_conf.write_text("custom", encoding="utf-8")

    deployer_cfg = DeployerConfig(
        router=RouterConfig(symlink_path=symlink_file, enable_proxy_reload=False),
        allow_unprivileged=True,
    )
    router = TrafficRouter(config=deployer_cfg.router, allow_unprivileged=True)
    os.symlink(str(other_conf.resolve()), str(symlink_file))

    assert router.get_active_slot(deployer_cfg) is None


def test_proxy_test_and_reload_execution(tmp_path: Path):
    """Verify subprocess invocation of test and reload commands."""
    symlink_file = tmp_path / "active.conf"
    target_conf = tmp_path / "target.conf"
    target_conf.write_text("server 127.0.0.1:8081;\n", encoding="utf-8")

    router_cfg = RouterConfig(
        symlink_path=symlink_file,
        enable_proxy_reload=True,
        test_command=["echo", "test_ok"],
        reload_command=["echo", "reload_ok"],
    )
    router = TrafficRouter(config=router_cfg, allow_unprivileged=True)

    with patch("subprocess.run") as mock_sub:
        mock_sub.return_value = subprocess.CompletedProcess(args=["echo"], returncode=0, stdout="ok", stderr="")
        res = router.switch_to_target(EnvironmentSlot.BLUE, target_conf, validate_proxy=True)
        assert res.success is True
        assert res.proxy_reloaded is True
        assert mock_sub.call_count == 2


def test_proxy_test_timeout_expired(tmp_path: Path):
    """Verify ProxyReloadError when test command times out."""
    router = TrafficRouter(RouterConfig(test_command=["sleep", "20"]))
    with patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd=["sleep"], timeout=10.0)):
        with pytest.raises(ProxyReloadError, match="timed out"):
            router.test_proxy_configuration()


def test_proxy_reload_timeout_expired(tmp_path: Path):
    """Verify ProxyReloadError when reload command times out."""
    router = TrafficRouter(RouterConfig(reload_command=["sleep", "20"]))
    with patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd=["sleep"], timeout=10.0)):
        with pytest.raises(ProxyReloadError, match="timed out"):
            router.reload_proxy()


def test_proxy_reload_binary_not_found():
    """Verify ProxyReloadError when proxy binary is not found and not unprivileged."""
    router = TrafficRouter(RouterConfig(reload_command=["/invalid/proxy_bin"]), allow_unprivileged=False)
    with patch("subprocess.run", side_effect=FileNotFoundError("No such file")):
        with pytest.raises(ProxyReloadError, match="not found"):
            router.reload_proxy()


def test_privilege_check_rejection(tmp_path: Path):
    """Verify PrivilegeError when require_root=True and not root (CWE-250)."""
    router_cfg = RouterConfig(
        symlink_path=tmp_path / "active.conf",
        require_root=True,
    )
    router = TrafficRouter(config=router_cfg, allow_unprivileged=False)

    with patch("os.geteuid", return_value=1000):
        with pytest.raises(PrivilegeError, match="Root privileges"):
            router.switch_to_target(EnvironmentSlot.BLUE, tmp_path / "blue.conf")


def test_privilege_check_allowed_when_root(tmp_path: Path):
    """Verify execution allowed when os.geteuid() == 0 (root)."""
    blue_conf = tmp_path / "blue.conf"
    blue_conf.write_text("upstream blue;", encoding="utf-8")
    router_cfg = RouterConfig(
        symlink_path=tmp_path / "active.conf",
        require_root=True,
        enable_proxy_reload=False,
    )
    router = TrafficRouter(config=router_cfg, allow_unprivileged=False)

    with patch("os.geteuid", return_value=0):
        res = router.switch_to_target(EnvironmentSlot.BLUE, blue_conf, validate_proxy=False)
        assert res.success is True


def test_switch_creates_missing_config_file(tmp_path: Path):
    """Verify switch_to_target creates snippet file if it does not yet exist."""
    missing_target = tmp_path / "snippets" / "auto_created.conf"
    router = TrafficRouter(RouterConfig(symlink_path=tmp_path / "active.conf", enable_proxy_reload=False), allow_unprivileged=True)
    res = router.switch_to_target(EnvironmentSlot.BLUE, missing_target)
    assert res.success is True
    assert missing_target.exists()


def test_switch_result_to_dict(tmp_path: Path):
    """Verify SwitchResult dictionary serialization."""
    res = SwitchResult(
        success=True,
        from_slot=EnvironmentSlot.BLUE,
        to_slot=EnvironmentSlot.GREEN,
        target_config_path=tmp_path / "green.conf",
        symlink_path=tmp_path / "active.conf",
        switch_duration_ms=4.52,
        proxy_reloaded=True,
    )
    d = res.to_dict()
    assert d["success"] is True
    assert d["from_slot"] == "blue"
    assert d["to_slot"] == "green"
    assert d["switch_duration_ms"] == 4.52
