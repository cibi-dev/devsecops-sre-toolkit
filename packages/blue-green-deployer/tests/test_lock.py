"""Unit tests for concurrency locking via fcntl.flock (CWE-362)."""

import errno
import os
import tempfile
from pathlib import Path
from unittest.mock import patch
import pytest

from deployer.config import LockConfig
from deployer.lock import DeploymentLock, DeploymentLockError, DeploymentLockTimeoutError


def test_lock_acquire_and_release(tmp_path: Path):
    """Verify clean acquisition and release of deployment lock."""
    lock_file = tmp_path / "deploy.lock"
    lock = DeploymentLock(lock_path=lock_file, timeout_seconds=1.0)

    assert not lock.is_locked
    lock.acquire()
    assert lock.is_locked
    assert lock_file.exists()

    # Re-acquiring already held lock in same instance is a no-op
    lock.acquire()
    assert lock.is_locked

    lock.release()
    assert not lock.is_locked


def test_lock_context_manager(tmp_path: Path):
    """Verify context manager enters and exits cleanly."""
    lock_file = tmp_path / "ctx.lock"
    with DeploymentLock(lock_path=lock_file, timeout_seconds=1.0) as lock:
        assert lock.is_locked
        assert lock_file.exists()
    assert not lock.is_locked


def test_lock_contention_timeout(tmp_path: Path):
    """Verify that a second lock instance raises TimeoutError within timeout_seconds."""
    lock_file = tmp_path / "contested.lock"
    lock1 = DeploymentLock(lock_path=lock_file, timeout_seconds=1.0)
    lock2 = DeploymentLock(lock_path=lock_file, timeout_seconds=0.2)

    lock1.acquire()
    try:
        with pytest.raises(DeploymentLockTimeoutError, match="Timed out"):
            lock2.acquire()
    finally:
        lock1.release()

    # After lock1 releases, lock2 should acquire successfully
    lock2.acquire()
    assert lock2.is_locked
    lock2.release()


def test_lock_audit_metadata_written(tmp_path: Path):
    """Verify PID is recorded in the lock file."""
    lock_file = tmp_path / "audit.lock"
    with DeploymentLock(lock_path=lock_file, timeout_seconds=1.0):
        content = lock_file.read_text(encoding="utf-8")
        assert f"pid={os.getpid()}" in content


def test_lock_with_config(tmp_path: Path):
    """Verify initialization with LockConfig object."""
    cfg = LockConfig(lock_file_path=tmp_path / "cfg.lock", lock_timeout_seconds=2.0)
    lock = DeploymentLock(config=cfg)
    assert lock.timeout_seconds == 2.0
    with lock:
        assert lock.is_locked


def test_lock_default_initialization():
    """Verify default initialization when no args are provided."""
    lock = DeploymentLock()
    assert lock.lock_path == (Path(tempfile.gettempdir()) / "blue_green_deploy.lock").resolve()
    assert lock.timeout_seconds <= 5.0


def test_lock_open_error():
    """Verify DeploymentLockError when file opening fails."""
    lock = DeploymentLock(lock_path=Path("/non_existent_dir_123/unwritable/lock.file"))
    with pytest.raises(DeploymentLockError, match="Failed to open lock file"):
        lock.acquire()


def test_lock_flock_unexpected_os_error(tmp_path: Path):
    """Verify DeploymentLockError on unexpected OS errors during fcntl.flock."""
    lock = DeploymentLock(lock_path=tmp_path / "err.lock", timeout_seconds=0.5)
    with patch("fcntl.flock", side_effect=OSError(errno.EBADF, "Bad file descriptor")):
        with pytest.raises(DeploymentLockError, match="Unexpected error acquiring lock"):
            lock.acquire()
