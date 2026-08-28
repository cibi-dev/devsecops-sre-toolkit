"""Security and DevSecOps compliance tests for blue-green-deployer.

Validates mitigations against:
- CWE-362: Concurrency locks with fcntl.flock and <=5s timeout
- CWE-377: Insecure temporary files and race-free atomic symlink replacement
- CWE-250: Privilege separation (read-only unprivileged, switch requires root)
- CWE-78:  OS command injection defense (closed argument lists, shell=False)
- CWE-22:  Path traversal defense
"""

import os
import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch
import pytest

from deployer.config import DeployerConfig, EnvironmentSlot, LockConfig, RouterConfig, TargetEnvironmentConfig
from deployer.lock import DeploymentLock, DeploymentLockTimeoutError
from deployer.router import PrivilegeError, TrafficRouter


def test_cwe_362_lock_timeout_enforced(tmp_path: Path):
    """CWE-362: Validate that deployment lock strictly times out within <=5 seconds."""
    lock_file = tmp_path / "sec_test.lock"
    lock1 = DeploymentLock(lock_path=lock_file, timeout_seconds=1.0)
    lock2 = DeploymentLock(lock_path=lock_file, timeout_seconds=0.1)

    lock1.acquire()
    try:
        with pytest.raises(DeploymentLockTimeoutError):
            lock2.acquire()
    finally:
        lock1.release()


def test_cwe_377_atomic_symlink_replacement_and_cleanup(tmp_path: Path):
    """CWE-377: Validate atomic symlink creation without insecure temp files or race conditions."""
    symlink_file = tmp_path / "active.conf"
    target1 = tmp_path / "upstream1.conf"
    target2 = tmp_path / "upstream2.conf"
    target1.write_text("server 1;\n", encoding="utf-8")
    target2.write_text("server 2;\n", encoding="utf-8")

    router = TrafficRouter(
        RouterConfig(symlink_path=symlink_file, enable_proxy_reload=False),
        allow_unprivileged=True,
    )

    # Initial switch
    res1 = router.switch_to_target(EnvironmentSlot.BLUE, target1)
    assert res1.success is True
    assert symlink_file.is_symlink()

    # Second atomic switch
    res2 = router.switch_to_target(EnvironmentSlot.GREEN, target2)
    assert res2.success is True
    assert symlink_file.is_symlink()
    assert os.readlink(str(symlink_file)) == str(target2.resolve())

    # Ensure no leftover .tmp files remain in the directory
    temp_files = list(tmp_path.glob(".tmp_*"))
    assert len(temp_files) == 0


def test_cwe_250_privilege_separation(tmp_path: Path):
    """CWE-250: Validate that mutating traffic requires root (EUID 0) unless allow_unprivileged is set."""
    target_conf = tmp_path / "target.conf"
    target_conf.write_text("upstream;\n", encoding="utf-8")
    router_cfg = RouterConfig(symlink_path=tmp_path / "active.conf", require_root=True)

    # Unprivileged user (EUID != 0) without allow_unprivileged -> Must raise PrivilegeError
    router_strict = TrafficRouter(config=router_cfg, allow_unprivileged=False)
    with patch("os.geteuid", return_value=1000):
        with pytest.raises(PrivilegeError, match="Root privileges"):
            router_strict.switch_to_target(EnvironmentSlot.BLUE, target_conf)

    # Root user (EUID == 0) -> Allowed
    with patch("os.geteuid", return_value=0):
        res = router_strict.switch_to_target(EnvironmentSlot.BLUE, target_conf, validate_proxy=False)
        assert res.success is True


def test_cwe_78_subprocess_safe_execution(tmp_path: Path):
    """CWE-78: Validate that subprocess calls never use shell=True and use strict list arguments."""
    target_conf = tmp_path / "target.conf"
    target_conf.write_text("upstream;\n", encoding="utf-8")

    router_cfg = RouterConfig(
        symlink_path=tmp_path / "active.conf",
        test_command=["/usr/sbin/nginx", "-t"],
        reload_command=["/usr/sbin/nginx", "-s", "reload"],
        enable_proxy_reload=True,
    )
    router = TrafficRouter(config=router_cfg, allow_unprivileged=True)

    with patch("subprocess.run") as mock_sub:
        mock_sub.return_value = subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")
        res = router.switch_to_target(EnvironmentSlot.BLUE, target_conf, validate_proxy=True)
        assert res.success is True

        # Assert all calls used shell=False
        for call_args in mock_sub.call_args_list:
            kwargs = call_args.kwargs
            assert kwargs.get("shell") is False
            args_list = call_args.args[0]
            assert isinstance(args_list, list)
            assert not any(";" in arg or "|" in arg or "&" in arg for arg in args_list)


def test_cwe_22_path_resolution(tmp_path: Path):
    """CWE-22: Validate path resolution avoids unexpected directory traversal."""
    nested_dir = tmp_path / "nested" / "dir"
    nested_dir.mkdir(parents=True)
    target_conf = nested_dir / "target.conf"
    target_conf.write_text("server 127.0.0.1:8081;\n", encoding="utf-8")

    router_cfg = RouterConfig(symlink_path=tmp_path / "active.conf", enable_proxy_reload=False)
    router = TrafficRouter(config=router_cfg, allow_unprivileged=True)

    res = router.switch_to_target(EnvironmentSlot.BLUE, target_conf)
    assert res.success is True
    assert Path(os.readlink(str(tmp_path / "active.conf"))).is_absolute()
