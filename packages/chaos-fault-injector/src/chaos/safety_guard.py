"""Safety Guard and Dead-Man Switch module for Chaos Fault Injector.

Implements strict DevSecOps guardrails:
- Least privilege / Root validation (CWE-250)
- Protected targets whitelist [PID 1, sshd, loopback, dbus, init, systemd]
- Guaranteed LIFO atomic rollback stack
- Dead-man switch watchdog with hard timeouts (<=30s) (CWE-377 & CWE-362)
- Safe concurrency locking via fcntl.flock (<=5s timeout)
- Guaranteed cleanup in atexit and signal handlers (SIGINT, SIGTERM, SIGHUP)
"""

from __future__ import annotations

import atexit
import fcntl
import os
import signal
import sys
import threading
import time
from dataclasses import dataclass
from typing import Any, Callable, List, Optional, Set

import tempfile

# --- Security Constants ---
PROTECTED_PROCESS_NAMES: Set[str] = {
    "systemd",
    "init",
    "sshd",
    "ssh",
    "dbus-daemon",
    "dbus-broker",
    "login",
    "systemd-journald",
    "systemd-udevd",
    "bash",
    "zsh",
    "python",
    "python3",
    "pytest",
}

PROTECTED_INTERFACES: Set[str] = {
    "lo",
    "loopback",
    "127.0.0.1",
    "::1",
}

PROTECTED_PIDS: Set[int] = {0, 1}

MAX_EXPERIMENT_DURATION: float = 30.0
DEFAULT_LOCK_TIMEOUT: float = 5.0
DEFAULT_LOCK_FILE: str = os.path.join(tempfile.gettempdir(), "chaos_fault_injector.lock")



class ChaosSecurityError(Exception):
    """Base exception for security and guardrail violations."""


class PrivilegeError(ChaosSecurityError):
    """Raised when mutation is attempted without root privileges."""


class ProtectedTargetError(ChaosSecurityError):
    """Raised when an operation targets a protected system resource."""


class LockAcquisitionError(ChaosSecurityError):
    """Raised when the concurrency lock cannot be acquired."""


class DeadManSwitchTriggered(ChaosSecurityError):
    """Raised when the dead-man switch triggers automatic rollback."""


def check_root_privileges(dry_run: bool = False) -> bool:
    """Verify if the current process has root privileges (CWE-250).

    Args:
        dry_run: If True, bypasses root requirement for safe simulation.

    Returns:
        True if running as root or in dry-run mode.

    Raises:
        PrivilegeError: If running as non-root without dry-run mode.
    """
    if dry_run:
        return True

    # Check effective UID on POSIX
    if hasattr(os, "geteuid"):
        if os.geteuid() == 0:
            return True
        raise PrivilegeError(
            "Root privileges (os.geteuid() == 0) are required for system fault injection. "
            "Execute with sudo or pass --dry-run for safe simulation."
        )
    return True


def validate_target_interface(interface: str) -> str:
    """Validate that the network interface is not protected.

    Args:
        interface: Name of the interface (e.g. eth0, wlan0).

    Returns:
        Sanitized interface name.

    Raises:
        ProtectedTargetError: If interface is protected (lo, loopback).
        ValueError: If interface name is empty or invalid.
    """
    if not interface or not isinstance(interface, str):
        raise ValueError("Interface name cannot be empty")

    sanitized = interface.strip().lower()
    if sanitized in PROTECTED_INTERFACES:
        raise ProtectedTargetError(
            f"Interface '{interface}' is protected by security policy (CWE-250 Whitelist). "
            "Disrupting loopback traffic is strictly forbidden."
        )
    return sanitized


def validate_target_pid(pid: int) -> int:
    """Validate that the PID is not protected.

    Args:
        pid: Process ID.

    Returns:
        Validated PID.

    Raises:
        ProtectedTargetError: If PID is 0, 1, self, or parent PID.
        ValueError: If PID is negative.
    """
    if pid <= 0:
        raise ValueError(f"Invalid PID: {pid}. PID must be a positive integer.")

    if pid in PROTECTED_PIDS:
        raise ProtectedTargetError(
            f"PID {pid} is protected by security policy (PID 1 / Init). Termination forbidden."
        )

    current_pid = os.getpid()
    parent_pid = os.getppid()
    if pid in (current_pid, parent_pid):
        raise ProtectedTargetError(
            f"Target PID {pid} is the current process or its parent. Self-termination forbidden."
        )

    return pid


def validate_target_process_name(name: str) -> str:
    """Validate that the process name is not protected.

    Args:
        name: Name of the process.

    Returns:
        Sanitized process name.

    Raises:
        ProtectedTargetError: If process name matches protected system services.
        ValueError: If process name is empty.
    """
    if not name or not isinstance(name, str):
        raise ValueError("Process name cannot be empty")

    sanitized = name.strip().lower()
    # Check exact match or basename
    base = os.path.basename(sanitized)
    if sanitized in PROTECTED_PROCESS_NAMES or base in PROTECTED_PROCESS_NAMES:
        raise ProtectedTargetError(
            f"Process '{name}' is a critical system service protected by whitelist (CWE-250). "
            "Termination forbidden."
        )
    return sanitized


@dataclass
class RollbackAction:
    """Represents a registered atomic rollback step."""

    callback: Callable[[], Any]
    description: str


class SafetyGuard:
    """Coordinates dead-man switches, atomic rollbacks, concurrency locks, and signal handlers."""

    def __init__(
        self,
        lock_file_path: str = DEFAULT_LOCK_FILE,
        lock_timeout: float = DEFAULT_LOCK_TIMEOUT,
        auto_lock: bool = True,
    ) -> None:
        self.lock_file_path = lock_file_path
        self.lock_timeout = lock_timeout
        self.auto_lock = auto_lock

        self._lock_fd: Optional[int] = None
        self._rollback_stack: List[RollbackAction] = []
        self._lock = threading.RLock()

        # Dead-man switch timer state
        self._dead_man_timer: Optional[threading.Timer] = None
        self._dead_man_active: bool = False
        self._dead_man_timeout: float = MAX_EXPERIMENT_DURATION
        self._dead_man_callback: Optional[Callable[[], None]] = None

        # Signal handlers state
        self._old_signal_handlers: dict[int, Any] = {}
        self._signals_registered: bool = False
        self._cleaned_up: bool = False

        if self.auto_lock:
            self.acquire_lock()

        self._register_safety_handlers()

    def acquire_lock(self) -> None:
        """Acquire non-blocking flock with bounded timeout (CWE-362/377)."""
        start_time = time.monotonic()
        try:
            self._lock_fd = os.open(
                self.lock_file_path,
                os.O_CREAT | os.O_RDWR | os.O_TRUNC,
                0o600,
            )
        except OSError as e:
            raise LockAcquisitionError(f"Failed to open lock file '{self.lock_file_path}': {e}") from e

        while True:
            try:
                fcntl.flock(self._lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                # Write current PID into lockfile
                os.write(self._lock_fd, f"{os.getpid()}\n".encode("utf-8"))
                return
            except (BlockingIOError, OSError):
                if (time.monotonic() - start_time) >= self.lock_timeout:
                    if self._lock_fd is not None:
                        try:
                            os.close(self._lock_fd)
                        except OSError:
                            pass
                        self._lock_fd = None
                    raise LockAcquisitionError(
                        f"Could not acquire experiment lock within {self.lock_timeout}s timeout. "
                        "Another chaos experiment may be running."
                    )
                time.sleep(0.05)

    def release_lock(self) -> None:
        """Release the concurrency lock safely."""
        if self._lock_fd is not None:
            try:
                fcntl.flock(self._lock_fd, fcntl.LOCK_UN)
                os.close(self._lock_fd)
            except OSError:
                pass
            finally:
                self._lock_fd = None
            try:
                if os.path.exists(self.lock_file_path):
                    os.unlink(self.lock_file_path)
            except OSError:
                pass

    def register_rollback(self, callback: Callable[[], Any], description: str = "") -> None:
        """Register an atomic rollback action onto the LIFO stack."""
        with self._lock:
            self._rollback_stack.append(RollbackAction(callback=callback, description=description))

    def rollback_all(self) -> List[str]:
        """Execute all registered rollbacks in LIFO order and clear the stack."""
        executed: List[str] = []
        with self._lock:
            actions = list(reversed(self._rollback_stack))
            self._rollback_stack.clear()

        for action in actions:
            try:
                action.callback()
                executed.append(action.description or "unnamed_rollback")
            except Exception as e:
                # Log to stderr and continue rollbacks to ensure complete rollback attempt
                sys.stderr.write(f"[Chaos SafetyGuard] Rollback failed for '{action.description}': {e}\n")
                executed.append(f"FAILED: {action.description} ({e})")
        return executed

    def start_dead_man(
        self,
        timeout_seconds: float = 10.0,
        on_timeout_callback: Optional[Callable[[], None]] = None,
    ) -> None:
        """Start the Dead-Man Switch watchdog timer.

        Args:
            timeout_seconds: Hard cutoff duration (capped at MAX_EXPERIMENT_DURATION).
            on_timeout_callback: Optional callback invoked on timeout.
        """
        with self._lock:
            self.stop_dead_man()

            bounded_timeout = min(max(0.1, timeout_seconds), MAX_EXPERIMENT_DURATION)
            self._dead_man_timeout = bounded_timeout
            self._dead_man_callback = on_timeout_callback
            self._dead_man_active = True

            def _on_timeout() -> None:
                sys.stderr.write(
                    f"\n[Chaos SafetyGuard] ⚠️ DEAD-MAN SWITCH TRIGGERED ({bounded_timeout}s timeout). "
                    "Executing atomic rollback!\n"
                )
                if self._dead_man_callback is not None:
                    try:
                        self._dead_man_callback()
                    except Exception as err:
                        sys.stderr.write(f"[Chaos SafetyGuard] Error in dead-man callback: {err}\n")
                self.rollback_all()

            self._dead_man_timer = threading.Timer(bounded_timeout, _on_timeout)
            self._dead_man_timer.daemon = True
            self._dead_man_timer.start()

    def heartbeat(self) -> None:
        """Reset / feed the dead-man switch timer with the same duration."""
        with self._lock:
            if self._dead_man_active and self._dead_man_timer is not None:
                self.start_dead_man(
                    timeout_seconds=self._dead_man_timeout,
                    on_timeout_callback=self._dead_man_callback,
                )

    def stop_dead_man(self) -> None:
        """Cancel and disarm the dead-man switch timer."""
        if self._dead_man_timer is not None:
            self._dead_man_timer.cancel()
            self._dead_man_timer = None
        self._dead_man_active = False

    @property
    def is_dead_man_active(self) -> bool:
        """Return whether dead-man switch is currently active."""
        return self._dead_man_active

    @property
    def rollback_count(self) -> int:
        """Return number of pending rollback actions."""
        with self._lock:
            return len(self._rollback_stack)

    def _register_safety_handlers(self) -> None:
        """Register atexit and POSIX signal handlers."""
        atexit.register(self.cleanup)

        # Only register signal handlers if in main thread
        if threading.current_thread() is threading.main_thread():
            for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
                try:
                    self._old_signal_handlers[sig] = signal.getsignal(sig)
                    signal.signal(sig, self._handle_signal)
                    self._signals_registered = True
                except (ValueError, OSError, AttributeError):
                    pass

    def _handle_signal(self, signum: int, frame: Any) -> None:
        """Handle incoming termination signals and guarantee cleanup."""
        sys.stderr.write(f"\n[Chaos SafetyGuard] Received signal {signum}. Performing emergency rollback...\n")
        self.cleanup()
        old_handler = self._old_signal_handlers.get(signum)
        if callable(old_handler) and old_handler not in (signal.SIG_IGN, signal.SIG_DFL, self._handle_signal):
            old_handler(signum, frame)
        else:
            sys.exit(128 + signum)

    def cleanup(self) -> None:
        """Guaranteed cleanup: disarms timer, executes rollbacks, and releases lock."""
        with self._lock:
            if self._cleaned_up:
                return
            self._cleaned_up = True

        self.stop_dead_man()
        self.rollback_all()
        self.release_lock()

        # Restore signals
        if self._signals_registered and threading.current_thread() is threading.main_thread():
            for sig, handler in self._old_signal_handlers.items():
                if handler is not None:
                    try:
                        signal.signal(sig, handler)
                    except (ValueError, OSError):
                        pass

    def __enter__(self) -> SafetyGuard:
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.cleanup()
