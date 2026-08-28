"""Unit tests for healer.nodes.gatekeeper stop condition evaluation and routing."""

from __future__ import annotations

from healer.nodes.gatekeeper import (
    evaluate_stop_condition,
    gatekeeper_node,
    route_gatekeeper,
)
from healer.state import CodePatchState


def test_evaluate_stop_condition_clean():
    """Test stop condition returns 'clean' when is_clean is True."""
    state: CodePatchState = {
        "source_file": "app.py",
        "original_code": "x = 1\n",
        "current_code": "x = 1\n",
        "bandit_report": {},
        "findings": [],
        "proposed_patch": "",
        "patch_history": [],
        "test_output": "ALL CHECKS PASSED",
        "test_passed": True,
        "is_clean": True,
        "iterations": 1,
        "max_iterations": 3,
        "error_message": None,
        "dry_run": False,
        "diff": "",
    }

    assert evaluate_stop_condition(state) == "clean"
    assert route_gatekeeper(state) == "clean"

    node_res = gatekeeper_node(state)
    assert node_res["error_message"] is None


def test_evaluate_stop_condition_max_iterations_reached():
    """Test stop condition returns 'max_iterations_reached' when iterations exceed limit."""
    state: CodePatchState = {
        "source_file": "app.py",
        "original_code": "import pickle\n",
        "current_code": "import pickle\n",
        "bandit_report": {},
        "findings": [{"test_id": "B301"}],
        "proposed_patch": "",
        "patch_history": [],
        "test_output": "FAILED",
        "test_passed": False,
        "is_clean": False,
        "iterations": 3,
        "max_iterations": 3,
        "error_message": None,
        "dry_run": False,
        "diff": "",
    }

    assert evaluate_stop_condition(state) == "max_iterations_reached"
    assert route_gatekeeper(state) == "max_iterations_reached"

    node_res = gatekeeper_node(state)
    assert "STOPPED: Reached max iteration limit" in node_res["error_message"]


def test_evaluate_stop_condition_continue():
    """Test stop condition returns 'continue' when issues remain and within budget."""
    state: CodePatchState = {
        "source_file": "app.py",
        "original_code": "import pickle\n",
        "current_code": "import pickle\n",
        "bandit_report": {},
        "findings": [{"test_id": "B301"}],
        "proposed_patch": "",
        "patch_history": [],
        "test_output": "FAILED",
        "test_passed": False,
        "is_clean": False,
        "iterations": 1,
        "max_iterations": 3,
        "error_message": None,
        "dry_run": False,
        "diff": "",
    }

    assert evaluate_stop_condition(state) == "continue"
    assert route_gatekeeper(state) == "continue"

    node_res = gatekeeper_node(state)
    assert "PROGRESS: Iteration 1/3" in node_res["error_message"]
