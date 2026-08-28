"""Additional tests for Sandbox Verifier to achieve 95%+ coverage."""

from __future__ import annotations

import subprocess
import pytest

from refactorer.nodes.verifier import SandboxVerifier


def test_sandbox_verifier_subprocess_exception(monkeypatch: pytest.MonkeyPatch):
    def mock_run(*args, **kwargs):
        raise OSError("Subprocess spawn error")

    monkeypatch.setattr(subprocess, "run", mock_run)
    verifier = SandboxVerifier(timeout_seconds=5.0)
    res = verifier.verify_code_and_tests("def f(): pass", "def test_f(): pass")

    assert res.mypy_passed is False
    assert res.pytest_passed is False
    assert "Subprocess spawn error" in res.mypy_output or res.error_message is not None


def test_sandbox_verifier_mypy_timeout(monkeypatch: pytest.MonkeyPatch):
    def mock_run(*args, **kwargs):
        raise subprocess.TimeoutExpired(cmd=["mypy"], timeout=1.0)

    monkeypatch.setattr(subprocess, "run", mock_run)
    verifier = SandboxVerifier(timeout_seconds=1.0)
    res = verifier.verify_code_and_tests("def f(): pass", "def test_f(): pass")

    assert "timed out" in res.mypy_output
