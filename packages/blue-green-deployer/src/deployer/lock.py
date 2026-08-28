"""Concurrency locking module using fcntl.flock (CWE-362 mitigation).

Ensures only a single deployment or traffic switch operation can execute
at any given moment across processes or sub-processes.
"""

from __future__ import annotations

import errno
import fcntl
import os
import tempfile
import time
from pathlib import Path
from typing import Optional

from deployer.config import LockConfig


class DeploymentLockError(Exception):
    """Raised when a deployment lock cannot be acquired or manipulated."""
    pass


class DeploymentLockTimeoutError(DeploymentLockError):
    """Raised when acquiring the deployment lock exceeds the configured timeout."""
    pass


class DeploymentLock:
    """Process-safe exclusive flock mutex for deployment operations."""

    def __init__(self, config: Optional[LockConfig] = None, lock_path: Optional[Path] = None, timeout_seconds: float = 5.0) -> None:
        if config is not None:
            self.lock_path = Path(config.lock_file_path).resolve()
            self.timeout_seconds = min(config.lock_timeout_seconds, 5.0)  # CWE-362 strict guardrail <= 5s
        elif lock_path is not None:
            self.lock_path = Path(lock_path).resolve()
            self.timeout_seconds = min(timeout_seconds, 5.0)
        else:
            self.lock_path = (Path(tempfile.gettempdir()) / "blue_green_deploy.lock").resolve()
            self.timeout_seconds = min(timeout_seconds, 5.0)

        self._fd: Optional[int] = None
        self._is_locked: bool = False

    @property
    def is_locked(self) -> bool:
        """Return True if this instance currently holds the lock."""
        return self._is_locked

    def acquire(self) -> None:
        """Acquire exclusive flock with non-blocking attempts until timeout.

        Raises:
            DeploymentLockTimeoutError: If lock cannot be acquired before timeout.
            DeploymentLockError: If an OS error occurs while managing the lock file.
        """
        if self._is_locked:
            return

        try:
            # Ensure parent directory exists
            self.lock_path.parent.mkdir(parents=True, exist_ok=True)
            # Open or create lock file with safe permissions
            self._fd = os.open(str(self.lock_path), os.O_CREAT | os.O_RDWR, 0o600)
        except OSError as exc:
            raise DeploymentLockError(f"Failed to open lock file '{self.lock_path}': {exc}") from exc

        start_time = time.monotonic()
        poll_interval = 0.05

        while True:
            try:
                # Attempt non-blocking exclusive lock
                fcntl.flock(self._fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                self._is_locked = True

                # Write PID and timestamp to lockfile for auditing
                try:
                    os.ftruncate(self._fd, 0)
                    os.lseek(self._fd, 0, os.SEEK_SET)
                    payload = f"pid={os.getpid()}\ntimestamp={time.time()}\n".encode("utf-8")
                    os.write(self._fd, payload)
                    os.fsync(self._fd)
                except OSError:
                    pass  # Non-fatal metadata write failure

                return
            except (OSError, IOError) as exc:
                if exc.errno not in (errno.EACCES, errno.EAGAIN, errno.EWOULDBLOCK):
                    self.release()
                    raise DeploymentLockError(f"Unexpected error acquiring lock: {exc}") from exc

                elapsed = time.monotonic() - start_time
                if elapsed >= self.timeout_seconds:
                    self.release()
                    raise DeploymentLockTimeoutError(
                        f"Timed out after {elapsed:.2f}s waiting for deployment lock at '{self.lock_path}'"
                    )

                time.sleep(poll_interval)

    def release(self) -> None:
        """Release the flock and close the file descriptor."""
        if self._fd is not None:
            try:
                if self._is_locked:
                    fcntl.flock(self._fd, fcntl.LOCK_UN)
            except OSError:
                pass
            finally:
                try:
                    os.close(self._fd)
                except OSError:
                    pass
                self._fd = None
                self._is_locked = False

    def __enter__(self) -> DeploymentLock:
        self.acquire()
        return self

    def __exit__(self, exc_type: object, exc_val: object, exc_tb: object) -> None:
        self.release()
