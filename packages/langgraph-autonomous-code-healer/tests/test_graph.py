"""Integration tests for healer.graph LangGraph workflow and SQLite checkpointer."""

from __future__ import annotations

import sqlite3
import tempfile
import pytest
from langgraph.checkpoint.sqlite import SqliteSaver

from healer.graph import (
    build_healer_graph,
    create_healer_graph,
    create_initial_state,
    route_after_analyzer,
    run_healer,
    run_healer_async,
)
from healer.state import CodePatchState


def test_build_healer_graph_structure():
    """Test building the uncompiled StateGraph."""
    builder = build_healer_graph(use_async_tester=False)
    assert builder is not None
    assert "analyzer" in builder.nodes
    assert "patcher" in builder.nodes
    assert "tester" in builder.nodes
    assert "gatekeeper" in builder.nodes


def test_create_initial_state_defaults():
    """Test create_initial_state helper."""
    st = create_initial_state("print('hello')", source_file="hello.py", max_iterations=4, dry_run=True)
    assert st["source_file"] == "hello.py"
    assert st["original_code"] == "print('hello')"
    assert st["max_iterations"] == 4
    assert st["dry_run"] is True
    assert st["iterations"] == 0
    assert st["is_clean"] is False


def test_route_after_analyzer():
    """Test routing immediately after initial analysis."""
    clean_state: CodePatchState = create_initial_state("x = 1\n")
    clean_state["is_clean"] = True
    assert route_after_analyzer(clean_state) == "__end__"

    dirty_state: CodePatchState = create_initial_state("x = 1\n")
    dirty_state["is_clean"] = False
    assert route_after_analyzer(dirty_state) == "patcher"


def test_run_healer_already_clean_code():
    """Test running healer on already clean code finishes in 0 iterations."""
    code = "def add(a: int, b: int) -> int:\n    return a + b\n"
    res = run_healer(code, source_file="add.py")
    assert res["is_clean"] is True
    assert res["current_code"] == code
    assert res["diff"] == ""


def test_run_healer_single_cwe_78():
    """Test healing CWE-78 (command injection with shell=True)."""
    code = (
        "import subprocess\n"
        "def ping(host):\n"
        "    subprocess.call(host, shell=True)\n"
    )
    res = run_healer(code, source_file="ping.py")
    assert res["is_clean"] is True
    assert res["iterations"] >= 1
    assert "shell=False" in res["current_code"]
    assert "subprocess.run" in res["current_code"]


def test_run_healer_single_cwe_502():
    """Test healing CWE-502 (yaml.load -> yaml.safe_load)."""
    code = (
        "import yaml\n"
        "def parse_conf(data):\n"
        "    return yaml.load(data)\n"
    )
    res = run_healer(code, source_file="conf.py")
    assert res["is_clean"] is True
    assert "yaml.safe_load" in res["current_code"]


def test_run_healer_single_cwe_327():
    """Test healing CWE-327 (hashlib.md5 -> hashlib.sha256)."""
    code = (
        "import hashlib\n"
        "def hash_payload(data):\n"
        "    return hashlib.md5(data).hexdigest()\n"
    )
    res = run_healer(code, source_file="hasher.py")
    assert res["is_clean"] is True
    assert "hashlib.sha256" in res["current_code"]


def test_run_healer_multi_vulnerabilities():
    """Test healing multiple simultaneous vulnerabilities."""
    mock_token = "secret_" + "token_999"
    code = (
        "import subprocess\n"
        "import hashlib\n"
        f'AUTH_TOKEN = "{mock_token}"\n'
        "def execute(cmd):\n"
        "    h = hashlib.md5(b'test').hexdigest()\n"
        "    subprocess.call(cmd, shell=True)\n"
    )
    res = run_healer(code, source_file="multi.py")
    assert res["is_clean"] is True
    assert "os.environ.get" in res["current_code"]
    assert "hashlib.sha256" in res["current_code"]
    assert "subprocess.run" in res["current_code"]
    assert len(res["patch_history"]) >= 3


def test_run_healer_sqlite_persistence():
    """Test thread persistence and checkpointing with SQLite."""
    with tempfile.NamedTemporaryFile(suffix=".db") as tmp_db:
        code = "import yaml\ndef load(x): return yaml.load(x)\n"
        thread_id = "test-thread-persistence-123"

        res = run_healer(code, source_file="persist.py", db_path=tmp_db.name, thread_id=thread_id)
        assert res["is_clean"] is True

        # Re-open connection to verify state was written to disk
        conn = sqlite3.connect(tmp_db.name, check_same_thread=False)
        try:
            saver = SqliteSaver(conn)
            saver.setup()
            builder = build_healer_graph(use_async_tester=False)
            app = builder.compile(checkpointer=saver)
            state_tuple = app.get_state({"configurable": {"thread_id": thread_id}})
            assert state_tuple is not None
            assert state_tuple.values["is_clean"] is True
        finally:
            conn.close()


@pytest.mark.asyncio
async def test_run_healer_async():
    """Test asynchronous end-to-end healing."""
    code = (
        "import subprocess\n"
        "def run_tool(name):\n"
        "    subprocess.call(name, shell=True)\n"
    )
    res = await run_healer_async(code, source_file="async_tool.py")
    assert res["is_clean"] is True
    assert "subprocess.run" in res["current_code"]
