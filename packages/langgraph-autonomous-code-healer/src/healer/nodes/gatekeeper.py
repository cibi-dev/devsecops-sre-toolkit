"""Gatekeeper node and conditional edge routing for the LangGraph code healer."""

from __future__ import annotations

import logging
from typing import Any, Literal

from healer.state import CodePatchState

logger = logging.getLogger(__name__)

# Allowed routing outcomes
GateOutcome = Literal["clean", "max_iterations_reached", "continue"]


def evaluate_stop_condition(state: CodePatchState) -> GateOutcome:
    """Evaluate whether the code is clean, max iterations were hit, or to continue healing."""
    is_clean = state.get("is_clean", False)
    current_iterations = state.get("iterations", 0)
    max_iterations = state.get("max_iterations", 3)

    if is_clean:
        logger.info("Gatekeeper: Code is CLEAN. Healing cycle complete.")
        return "clean"

    if current_iterations >= max_iterations:
        logger.warning(
            "Gatekeeper: Max iterations (%d/%d) reached without achieving clean status.",
            current_iterations,
            max_iterations,
        )
        return "max_iterations_reached"

    logger.info(
        "Gatekeeper: Vulnerabilities remain. Continuing to iteration %d/%d.",
        current_iterations + 1,
        max_iterations,
    )
    return "continue"


def gatekeeper_node(state: CodePatchState) -> dict[str, Any]:
    """LangGraph node: Evaluates gate status and prepares final summary messages."""
    outcome = evaluate_stop_condition(state)
    is_clean = state.get("is_clean", False)
    iterations = state.get("iterations", 0)
    max_iterations = state.get("max_iterations", 3)

    if outcome == "clean":
        msg = f"SUCCESS: Code successfully healed and verified in {iterations} iteration(s)."
    elif outcome == "max_iterations_reached":
        msg = f"STOPPED: Reached max iteration limit ({iterations}/{max_iterations}). Manual review required."
    else:
        msg = f"PROGRESS: Iteration {iterations}/{max_iterations} completed. Scheduling next remediation pass."

    return {
        "error_message": None if is_clean else msg,
    }


def route_gatekeeper(state: CodePatchState) -> str:
    """Conditional routing function for LangGraph edges."""
    return evaluate_stop_condition(state)
