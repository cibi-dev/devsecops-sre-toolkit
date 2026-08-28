"""
Unit tests for Pipeline YAML parser and Pydantic validation.
Tests CWE-20, CWE-502, and CWE-400 mitigations.
"""

import tempfile
from pathlib import Path
import pytest

from runner.parser import (
    MAX_PIPELINE_FILE_SIZE,
    ParserError,
    PipelineModel,
    SecurityError,
    parse_pipeline_file,
    parse_pipeline_yaml,
)


def test_parse_valid_simple_pipeline():
    yaml_content = """
    name: Simple Test Pipeline
    concurrency: 2
    jobs:
      lint:
        script:
          - flake8 .
      test:
        needs: [lint]
        script: pytest -v
    """
    pipeline = parse_pipeline_yaml(yaml_content)
    assert pipeline.name == "Simple Test Pipeline"
    assert pipeline.concurrency == 2
    assert "lint" in pipeline.jobs
    assert "test" in pipeline.jobs
    assert pipeline.jobs["lint"].script == ["flake8 ."]
    assert pipeline.jobs["test"].script == ["pytest -v"]
    assert pipeline.jobs["test"].needs == ["lint"]


def test_parse_multiline_script_string():
    yaml_content = """
    jobs:
      build:
        script: |
          echo "Building step 1"
          echo "Building step 2"
        before_script: echo "Starting build"
        after_script: echo "Clean build"
    """
    pipeline = parse_pipeline_yaml(yaml_content)
    job = pipeline.jobs["build"]
    assert job.script == ['echo "Building step 1"', 'echo "Building step 2"']
    assert job.before_script == ['echo "Starting build"']
    assert job.after_script == ['echo "Clean build"']


def test_parse_matrix_expansion():
    yaml_content = """
    name: Matrix Test
    jobs:
      test:
        stage: test
        matrix:
          python: ["3.10", "3.11"]
          os: ["ubuntu", "alpine"]
        script:
          - echo "Running on ${{ matrix.os }} with python ${{ matrix.python }}"
          - 'echo "Target: $matrix.os"'
    """
    pipeline = parse_pipeline_yaml(yaml_content)
    assert len(pipeline.jobs) == 4
    expected_names = {
        "test[python=3.10,os=ubuntu]",
        "test[python=3.10,os=alpine]",
        "test[python=3.11,os=ubuntu]",
        "test[python=3.11,os=alpine]",
    }
    assert set(pipeline.jobs.keys()) == expected_names
    job_ubuntu = pipeline.jobs["test[python=3.10,os=ubuntu]"]
    assert 'echo "Running on ubuntu with python 3.10"' in job_ubuntu.script
    assert 'echo "Target: ubuntu"' in job_ubuntu.script
    assert job_ubuntu.env["MATRIX_PYTHON"] == "3.10"
    assert job_ubuntu.env["MATRIX_OS"] == "ubuntu"


def test_parse_matrix_dependency_expansion():
    yaml_content = """
    jobs:
      matrix_job:
        matrix:
          env_name: ["dev", "prod"]
        script: echo "Matrix ${{ matrix.env_name }}"
      deploy:
        needs: [matrix_job]
        script: echo "Deploying after all matrix combinations"
    """
    pipeline = parse_pipeline_yaml(yaml_content)
    assert "matrix_job[env_name=dev]" in pipeline.jobs
    assert "matrix_job[env_name=prod]" in pipeline.jobs
    deploy_job = pipeline.jobs["deploy"]
    assert set(deploy_job.needs) == {"matrix_job[env_name=dev]", "matrix_job[env_name=prod]"}


def test_parse_implicit_stage_dependencies():
    yaml_content = """
    stages:
      - lint
      - test
      - deploy
    jobs:
      lint_job:
        stage: lint
        script: flake8 .
      test_job1:
        stage: test
        script: pytest tests/unit
      test_job2:
        stage: test
        script: pytest tests/integration
      deploy_job:
        stage: deploy
        script: ./deploy.sh
    """
    pipeline = parse_pipeline_yaml(yaml_content)
    assert pipeline.jobs["lint_job"].needs == []
    assert set(pipeline.jobs["test_job1"].needs) == {"lint_job"}
    assert set(pipeline.jobs["test_job2"].needs) == {"lint_job"}
    assert set(pipeline.jobs["deploy_job"].needs) == {"test_job1", "test_job2"}


def test_parse_invalid_stage_rejection():
    yaml_content = """
    stages:
      - build
      - test
    jobs:
      invalid_job:
        stage: deploy
        script: echo "Unknown stage"
    """
    with pytest.raises(ParserError, match="not in declared pipeline stages"):
        parse_pipeline_yaml(yaml_content)


def test_parse_empty_script_rejection():
    yaml_content = """
    jobs:
      empty_job:
        script: ""
    """
    with pytest.raises(ParserError):
        parse_pipeline_yaml(yaml_content)


def test_parse_invalid_yaml_syntax():
    yaml_content = "jobs: [invalid: yaml: syntax: {"
    with pytest.raises(ParserError, match="Invalid YAML syntax"):
        parse_pipeline_yaml(yaml_content)


def test_parse_non_dict_yaml():
    yaml_content = "- list item 1\n- list item 2"
    with pytest.raises(ParserError, match="top-level mapping"):
        parse_pipeline_yaml(yaml_content)


def test_parse_empty_jobs_rejection():
    yaml_content = "name: Empty Pipeline\njobs: {}"
    with pytest.raises(ParserError, match="at least one job"):
        parse_pipeline_yaml(yaml_content)


def test_parse_file_size_limit_security_string():
    # Construct a string > 1MB
    large_comment = "# " + ("A" * (MAX_PIPELINE_FILE_SIZE + 100))
    yaml_content = f"{large_comment}\njobs:\n  run:\n    script: echo 1\n"
    with pytest.raises(SecurityError, match="exceeds maximum allowed size of 1MB"):
        parse_pipeline_yaml(yaml_content)


def test_parse_file_size_limit_security_file(tmp_path: Path):
    oversized_file = tmp_path / "oversized.yml"
    oversized_file.write_bytes(b"A" * (MAX_PIPELINE_FILE_SIZE + 50))
    with pytest.raises(SecurityError, match="exceeds maximum allowed size of 1MB"):
        parse_pipeline_file(oversized_file)


def test_parse_file_not_found():
    with pytest.raises(FileNotFoundError):
        parse_pipeline_file("/non/existent/path/pipeline.yml")


def test_parse_pipeline_file_success(tmp_path: Path):
    pipeline_file = tmp_path / ".ci-pipeline.yml"
    pipeline_file.write_text(
        """
        name: File Test
        env:
          GLOBAL_VAR: "true"
        secrets:
          - API_KEY
        jobs:
          test:
            env:
              JOB_VAR: "yes"
            script: pytest
        """,
        encoding="utf-8",
    )
    pipeline = parse_pipeline_file(pipeline_file)
    assert pipeline.name == "File Test"
    assert pipeline.env["GLOBAL_VAR"] == "true"
    assert pipeline.secrets == ["API_KEY"]
    assert pipeline.jobs["test"].env["GLOBAL_VAR"] == "true"
    assert pipeline.jobs["test"].env["JOB_VAR"] == "yes"
