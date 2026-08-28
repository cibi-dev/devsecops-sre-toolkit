"""Additional tests for Graph async runners and error handling."""

from __future__ import annotations

import asyncio
import pytest

from refactorer.graph import run_refactorer_async


@pytest.mark.asyncio
async def test_run_refactorer_async_timeout():
    # Extremely small timeout to test timeout handling path
    state = await run_refactorer_async(
        source_code="def slow_func(): pass",
        target_path="slow.py",
        timeout_seconds=0.0001,
    )
    assert state.error is not None
    assert "timeout" in state.error.lower() or state.is_complete is False


@pytest.mark.asyncio
async def test_run_refactorer_async_exception_handling(monkeypatch: pytest.MonkeyPatch):
    import refactorer.graph as graph_module

    def mock_create_graph(*args, **kwargs):
        raise RuntimeError("Graph creation failed")

    monkeypatch.setattr(graph_module, "create_refactorer_graph", mock_create_graph)

    state = await run_refactorer_async(
        source_code="def f(): pass",
        target_path="f.py",
    )
    assert state.error is not None
    assert "Graph creation failed" in state.error
