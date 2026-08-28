"""LangGraph StateGraph assembly for autonomous code self-healing with SQLite checkpointer."""

from __future__ import annotations

import asyncio
import logging
import sqlite3
import uuid
from typing import Any

from langgraph.checkpoint.memory import MemorySaver
from langgraph.checkpoint.sqlite import SqliteSaver
from langgraph.graph import END, START, StateGraph

from healer.nodes.analyzer import analyzer_node
from healer.nodes.gatekeeper import gatekeeper_node, route_gatekeeper
from healer.nodes.patcher import patcher_node
from healer.nodes.tester import tester_node, tester_node_async
from healer.state import CodePatchState

logger = logging.getLogger(__name__)

# Default execution boundaries for graph cyclic execution (Guardrails #10 & #17)
DEFAULT_MAX_ITERATIONS: int = 3
CANONICAL_RECURSION_LIMIT: int = 25
GRAPH_TIMEOUT_SECONDS: float = 30.0


def route_after_analyzer(state: CodePatchState) -> str:
    """Route to END if already clean on initial analysis, otherwise route to patcher."""
    if state.get("is_clean", False):
        return END
    return "patcher"


def build_healer_graph(use_async_tester: bool = False) -> StateGraph:
    """Construct the uncompiled StateGraph workflow for code healing."""
    builder = StateGraph(CodePatchState)

    # 1. Add Nodes
    builder.add_node("analyzer", analyzer_node)
    builder.add_node("patcher", patcher_node)
    if use_async_tester:
        builder.add_node("tester", tester_node_async)
    else:
        builder.add_node("tester", tester_node)
    builder.add_node("gatekeeper", gatekeeper_node)

    # 2. Add Edges & Conditional Transitions
    builder.add_edge(START, "analyzer")

    builder.add_conditional_edges(
        "analyzer",
        route_after_analyzer,
        {
            END: END,
            "patcher": "patcher",
        },
    )

    builder.add_edge("patcher", "tester")
    builder.add_edge("tester", "gatekeeper")

    builder.add_conditional_edges(
        "gatekeeper",
        route_gatekeeper,
        {
            "clean": END,
            "max_iterations_reached": END,
            "continue": "analyzer",
        },
    )

    return builder


def create_healer_graph(
    checkpointer: Any | None = None,
    db_path: str = ":memory:",
    use_async_tester: bool = False,
) -> Any:
    """Assemble and compile the StateGraph with SqliteSaver checkpointer."""
    builder = build_healer_graph(use_async_tester=use_async_tester)

    if checkpointer is None:
        if use_async_tester:
            checkpointer = MemorySaver()
        else:
            conn = sqlite3.connect(db_path, check_same_thread=False)
            checkpointer = SqliteSaver(conn)
            checkpointer.setup()

    return builder.compile(checkpointer=checkpointer)


def create_initial_state(
    code: str,
    source_file: str = "target.py",
    bandit_report: dict[str, Any] | None = None,
    max_iterations: int = DEFAULT_MAX_ITERATIONS,
    dry_run: bool = False,
) -> CodePatchState:
    """Create a standardized initial state for the healer graph."""
    return {
        "source_file": source_file,
        "original_code": code,
        "current_code": code,
        "bandit_report": bandit_report or {},
        "findings": [],
        "proposed_patch": code,
        "patch_history": [],
        "test_output": "",
        "test_passed": False,
        "is_clean": False,
        "iterations": 0,
        "max_iterations": max_iterations,
        "error_message": None,
        "dry_run": dry_run,
        "diff": "",
    }


def run_healer(
    code: str,
    source_file: str = "target.py",
    bandit_report: dict[str, Any] | None = None,
    max_iterations: int = DEFAULT_MAX_ITERATIONS,
    recursion_limit: int = CANONICAL_RECURSION_LIMIT,
    db_path: str = ":memory:",
    thread_id: str | None = None,
    dry_run: bool = False,
) -> CodePatchState:
    """Synchronously execute the full autonomous code healing loop."""
    conn = sqlite3.connect(db_path, check_same_thread=False)
    try:
        checkpointer = SqliteSaver(conn)
        checkpointer.setup()
        builder = build_healer_graph(use_async_tester=False)
        app: Any = builder.compile(checkpointer=checkpointer)

        initial_state = create_initial_state(
            code=code,
            source_file=source_file,
            bandit_report=bandit_report,
            max_iterations=max_iterations,
            dry_run=dry_run,
        )

        t_id = thread_id or f"healer-{uuid.uuid4().hex[:8]}"
        config = {
            "configurable": {"thread_id": t_id},
            "recursion_limit": recursion_limit,
        }

        final_state: CodePatchState = app.invoke(initial_state, config=config)
        return final_state
    finally:
        try:
            conn.close()
        except Exception:
            pass


async def run_healer_async(
    code: str,
    source_file: str = "target.py",
    bandit_report: dict[str, Any] | None = None,
    max_iterations: int = DEFAULT_MAX_ITERATIONS,
    recursion_limit: int = CANONICAL_RECURSION_LIMIT,
    timeout_seconds: float = GRAPH_TIMEOUT_SECONDS,
    db_path: str = ":memory:",
    thread_id: str | None = None,
    dry_run: bool = False,
) -> CodePatchState:
    """Asynchronously execute the autonomous code healing loop with timeout bounding."""
    app = create_healer_graph(db_path=db_path, use_async_tester=True)
    initial_state = create_initial_state(
        code=code,
        source_file=source_file,
        bandit_report=bandit_report,
        max_iterations=max_iterations,
        dry_run=dry_run,
    )

    t_id = thread_id or f"healer-async-{uuid.uuid4().hex[:8]}"
    config = {
        "configurable": {"thread_id": t_id},
        "recursion_limit": recursion_limit,
    }

    async with asyncio.timeout(timeout_seconds):
        final_state: CodePatchState = await app.ainvoke(initial_state, config=config)
        return final_state
