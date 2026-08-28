"""StateGraph assembly and multi-agent workflow execution for code refactoring.

Integrates ASTInspector, TypeAnnotator, TestGenerator, and SandboxVerifier nodes.
Adheres strictly to SECURITY.md:
- #15: Pydantic v2 validation & AST Guardrails.
- #16: Human-in-the-loop interfaces.
- #17: Bounded cycles (recursion_limit <= 4) & execution timeouts.
"""

from __future__ import annotations

import asyncio
import sqlite3
from typing import Any, Dict, Optional
import uuid

from langgraph.checkpoint.sqlite import SqliteSaver
from langgraph.graph import END, START, StateGraph

from refactorer.inspector import ASTInspector
from refactorer.nodes.annotator import annotator_node
from refactorer.nodes.test_gen import test_gen_node
from refactorer.nodes.verifier import verifier_node
from refactorer.state import RefactorGraphState, RefactorProposal, RefactorState, VerificationResult


def inspector_node(state: Dict[str, Any]) -> Dict[str, Any]:
    """LangGraph node execution function for initial AST Inspection."""
    source_code = state.get("source_code", "")
    target_path = state.get("target_path", "module.py")

    inspector = ASTInspector(file_path=target_path)
    try:
        type_issues, missing_branches, _ = inspector.inspect_source(source_code)
        return {
            "current_code": source_code,
            "type_issues": [iss.model_dump() for iss in type_issues],
            "missing_branches": [br.model_dump() for br in missing_branches],
        }
    except Exception as e:
        return {
            "error": f"Inspector failed: {str(e)}",
            "is_complete": False,
        }


def evaluator_router(state: Dict[str, Any]) -> str:
    """Conditional routing edge deciding convergence, retry, or termination."""
    if state.get("error"):
        return END

    if state.get("is_complete", False):
        return END

    iterations = state.get("iterations", 0)
    max_iter = state.get("max_iterations", 3)

    if iterations >= max_iter:
        return END

    return "annotator"


def create_refactorer_graph(db_path: Optional[str] = None) -> Any:
    """Construct and compile the LangGraph StateGraph with SQLite persistence.

    Args:
        db_path: Optional SQLite database file path. If None, uses in-memory SQLite.

    Returns:
        Compiled LangGraph workflow executable.
    """
    builder: Any = StateGraph(RefactorGraphState)

    # 1. Register Nodes
    builder.add_node("inspector", inspector_node)
    builder.add_node("annotator", annotator_node)
    builder.add_node("test_gen", test_gen_node)
    builder.add_node("verifier", verifier_node)

    # 2. Register Linear and Conditional Edges
    builder.add_edge(START, "inspector")
    builder.add_edge("inspector", "annotator")
    builder.add_edge("annotator", "test_gen")
    builder.add_edge("test_gen", "verifier")

    builder.add_conditional_edges(
        "verifier",
        evaluator_router,
        {
            "annotator": "annotator",
            END: END,
        },
    )

    # 3. Setup SQLite Checkpointer (SECURITY.md Standard #17)
    conn_str = db_path if db_path else ":memory:"
    conn = sqlite3.connect(conn_str, check_same_thread=False)
    checkpointer = SqliteSaver(conn)
    checkpointer.setup()

    return builder.compile(checkpointer=checkpointer)


async def run_refactorer_async(
    source_code: str,
    target_path: str = "module.py",
    target_coverage: float = 90.0,
    strict_mode: bool = True,
    max_iterations: int = 3,
    db_path: Optional[str] = None,
    thread_id: Optional[str] = None,
    timeout_seconds: float = 30.0,
) -> RefactorState:
    """Asynchronously execute the bounded multi-agent refactoring workflow.

    Args:
        source_code: Original Python source code.
        target_path: Display file path.
        target_coverage: Desired test coverage percentage (>= 90.0).
        strict_mode: Enforce strict MyPy conformance.
        max_iterations: Hard recursion bounding (<= 4).
        db_path: Optional SQLite checkpoint path.
        thread_id: Unique thread identifier for state checkpoints.
        timeout_seconds: Global timeout bounding (default 30.0s).

    Returns:
        Final validated RefactorState.
    """
    bounded_max_iter = min(max_iterations, 4)
    active_thread_id = thread_id or f"refactor-{uuid.uuid4().hex[:8]}"

    initial_state: Dict[str, Any] = {
        "target_path": target_path,
        "source_code": source_code,
        "type_issues": [],
        "missing_branches": [],
        "current_code": source_code,
        "current_tests": "",
        "verification_history": [],
        "iterations": 0,
        "max_iterations": bounded_max_iter,
        "target_coverage": target_coverage,
        "strict_mode": strict_mode,
        "is_complete": False,
        "error": None,
    }

    try:
        graph_app = create_refactorer_graph(db_path=db_path)
        config = {
            "configurable": {"thread_id": active_thread_id},
            "recursion_limit": bounded_max_iter * 4 + 2,
        }

        async with asyncio.timeout(timeout_seconds):
            # Run graph execution in thread pool to avoid blocking async event loop
            loop = asyncio.get_running_loop()
            final_dict = await loop.run_in_executor(
                None, graph_app.invoke, initial_state, config
            )
    except TimeoutError:
        return RefactorState(
            target_path=target_path,
            source_code=source_code,
            current_code=initial_state.get("current_code", source_code),
            error=f"Refactoring exceeded execution timeout limit ({timeout_seconds}s)",
            max_iterations=bounded_max_iter,
            target_coverage=target_coverage,
            strict_mode=strict_mode,
            is_complete=False,
        )
    except Exception as e:
        return RefactorState(
            target_path=target_path,
            source_code=source_code,
            current_code=initial_state.get("current_code", source_code),
            error=f"Workflow execution exception: {str(e)}",
            max_iterations=bounded_max_iter,
            target_coverage=target_coverage,
            strict_mode=strict_mode,
            is_complete=False,
        )

    # Convert dictionary state back to validated Pydantic model
    return RefactorState(
        target_path=final_dict.get("target_path", target_path),
        source_code=final_dict.get("source_code", source_code),
        type_issues=final_dict.get("type_issues", []),
        missing_branches=final_dict.get("missing_branches", []),
        current_code=final_dict.get("current_code", ""),
        current_tests=final_dict.get("current_tests", ""),
        verification_history=final_dict.get("verification_history", []),
        iterations=final_dict.get("iterations", 0),
        max_iterations=final_dict.get("max_iterations", bounded_max_iter),
        target_coverage=final_dict.get("target_coverage", target_coverage),
        strict_mode=final_dict.get("strict_mode", strict_mode),
        is_complete=final_dict.get("is_complete", False),
        error=final_dict.get("error"),
    )


def run_refactorer(
    source_code: str,
    target_path: str = "module.py",
    target_coverage: float = 90.0,
    strict_mode: bool = True,
    max_iterations: int = 3,
    db_path: Optional[str] = None,
    thread_id: Optional[str] = None,
    timeout_seconds: float = 30.0,
) -> RefactorState:
    """Synchronously execute the bounded multi-agent refactoring workflow.

    Args:
        source_code: Original Python source code.
        target_path: Target file path.
        target_coverage: Target test coverage percentage.
        strict_mode: Enforce strict MyPy check.
        max_iterations: Bounded iterations.
        db_path: Optional SQLite checkpoint path.
        thread_id: Optional session thread ID.
        timeout_seconds: Timeout in seconds.

    Returns:
        Final validated RefactorState.
    """
    return asyncio.run(
        run_refactorer_async(
            source_code=source_code,
            target_path=target_path,
            target_coverage=target_coverage,
            strict_mode=strict_mode,
            max_iterations=max_iterations,
            db_path=db_path,
            thread_id=thread_id,
            timeout_seconds=timeout_seconds,
        )
    )
