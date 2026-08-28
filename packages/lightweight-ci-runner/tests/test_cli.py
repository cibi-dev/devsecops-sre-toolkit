"""
Unit tests for CLI subcommands and error handling.
"""

import json
from pathlib import Path
import pytest

from runner.cli import main, parse_env_args


def test_parse_env_args():
    assert parse_env_args(None) == {}
    assert parse_env_args([]) == {}
    parsed = parse_env_args(["KEY=VALUE", "FLAG", "FOO=BAR=BAZ"])
    assert parsed == {"KEY": "VALUE", "FLAG": "", "FOO": "BAR=BAZ"}


def test_cli_help(capsys):
    ret = main([])
    assert ret == 0
    captured = capsys.readouterr()
    assert "usage:" in captured.out or "lightweight-ci" in captured.out


def test_cli_validate_success(tmp_path: Path):
    pipeline_file = tmp_path / ".ci-pipeline.yml"
    pipeline_file.write_text(
        """
        stages: [lint, test]
        jobs:
          lint_job:
            stage: lint
            script: echo lint
          test_job:
            stage: test
            script: echo test
        """,
        encoding="utf-8",
    )
    ret = main(["validate", "-f", str(pipeline_file)])
    assert ret == 0


def test_cli_validate_invalid_syntax(tmp_path: Path):
    pipeline_file = tmp_path / "bad.yml"
    pipeline_file.write_text("invalid: [yaml", encoding="utf-8")
    ret = main(["validate", "-f", str(pipeline_file)])
    assert ret == 2


def test_cli_validate_circular_dependency(tmp_path: Path):
    pipeline_file = tmp_path / "cycle.yml"
    pipeline_file.write_text(
        """
        jobs:
          A:
            needs: [B]
            script: echo A
          B:
            needs: [A]
            script: echo B
        """,
        encoding="utf-8",
    )
    ret = main(["validate", "-f", str(pipeline_file)])
    assert ret == 2


def test_cli_graph_ascii(tmp_path: Path, capsys):
    pipeline_file = tmp_path / ".ci-pipeline.yml"
    pipeline_file.write_text(
        """
        jobs:
          step1:
            script: echo 1
          step2:
            needs: [step1]
            script: echo 2
        """,
        encoding="utf-8",
    )
    ret = main(["graph", "-f", str(pipeline_file), "--format", "ascii"])
    assert ret == 0
    captured = capsys.readouterr()
    assert "PIPELINE EXECUTION DAG" in captured.out


def test_cli_graph_dot(tmp_path: Path, capsys):
    pipeline_file = tmp_path / ".ci-pipeline.yml"
    pipeline_file.write_text(
        """
        jobs:
          step1:
            script: echo 1
        """,
        encoding="utf-8",
    )
    ret = main(["graph", "-f", str(pipeline_file), "--format", "dot"])
    assert ret == 0
    captured = capsys.readouterr()
    assert "digraph PipelineDAG" in captured.out


def test_cli_dry_run(tmp_path: Path, capsys):
    pipeline_file = tmp_path / ".ci-pipeline.yml"
    pipeline_file.write_text(
        """
        jobs:
          run_job:
            script: echo "Running dry"
        """,
        encoding="utf-8",
    )
    junit_file = tmp_path / "dry_report.xml"
    ret = main(["dry-run", "-f", str(pipeline_file), "-j", str(junit_file)])
    assert ret == 0
    assert junit_file.is_file()


def test_cli_run_success(tmp_path: Path):
    pipeline_file = tmp_path / ".ci-pipeline.yml"
    pipeline_file.write_text(
        """
        name: CLI Run Success
        jobs:
          hello:
            script: echo "Hello from CLI"
        """,
        encoding="utf-8",
    )
    junit_file = tmp_path / "junit.xml"
    ret = main(["run", "-f", str(pipeline_file), "-j", str(junit_file), "--no-color"])
    assert ret == 0
    assert junit_file.is_file()


def test_cli_run_json_output(tmp_path: Path, capsys):
    pipeline_file = tmp_path / ".ci-pipeline.yml"
    pipeline_file.write_text(
        """
        name: JSON Test
        jobs:
          simple:
            script: echo "json test"
        """,
        encoding="utf-8",
    )
    ret = main(["run", "-f", str(pipeline_file), "--json"])
    assert ret == 0
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert data["pipeline_name"] == "JSON Test"
    assert data["success"] is True


def test_cli_run_failure(tmp_path: Path):
    pipeline_file = tmp_path / ".ci-pipeline.yml"
    pipeline_file.write_text(
        """
        name: CLI Run Failure
        jobs:
          fail_job:
            script: python3 -c "import sys; sys.exit(1)"
        """,
        encoding="utf-8",
    )
    ret = main(["run", "-f", str(pipeline_file), "--no-color"])
    assert ret == 1


def test_cli_run_file_error():
    ret = main(["run", "-f", "/non/existent/path.yml"])
    assert ret == 2


def test_cli_run_with_env_and_stage(tmp_path: Path):
    pipeline_file = tmp_path / ".ci-pipeline.yml"
    pipeline_file.write_text(
        """
        stages: [lint, test]
        jobs:
          lint_job:
            stage: lint
            script: echo "linting"
          test_job:
            stage: test
            script: python3 -c "import os; assert os.environ.get('CLI_ENV') == 'passed'"
        """,
        encoding="utf-8",
    )
    ret = main([
        "run",
        "-f", str(pipeline_file),
        "-s", "test",
        "-e", "CLI_ENV=passed",
        "--concurrency", "2",
        "--no-color",
    ])
    assert ret == 0


def test_cli_graph_error():
    ret = main(["graph", "-f", "/non/existent/file.yml"])
    assert ret == 2


def test_cli_dry_run_error():
    ret = main(["dry-run", "-f", "/non/existent/file.yml"])
    assert ret == 2
