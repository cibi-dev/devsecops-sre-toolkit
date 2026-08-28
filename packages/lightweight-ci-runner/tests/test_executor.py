"""
Unit tests for Asynchronous Job and Pipeline Executor.
"""

import asyncio
import pytest

from runner.executor import (
    JobExecutor,
    JobResult,
    JobStatus,
    PipelineExecutor,
)
from runner.parser import JobDefinition, PipelineDefinition


@pytest.mark.asyncio
async def test_job_executor_success():
    executor = JobExecutor()
    job = JobDefinition(
        name="test_echo",
        original_name="test_echo",
        stage="test",
        script=["echo 'Hello CI'"],
    )
    result = await executor.execute_job(job)
    assert result.status == JobStatus.SUCCESS
    assert result.exit_code == 0
    assert "Hello CI" in result.stdout
    assert result.duration_seconds >= 0


@pytest.mark.asyncio
async def test_job_executor_before_after_scripts():
    executor = JobExecutor()
    job = JobDefinition(
        name="test_lifecycle",
        original_name="test_lifecycle",
        stage="test",
        before_script=["echo 'BEFORE'"],
        script=["echo 'MAIN'"],
        after_script=["echo 'AFTER'"],
    )
    result = await executor.execute_job(job)
    assert result.status == JobStatus.SUCCESS
    assert "BEFORE" in result.stdout
    assert "MAIN" in result.stdout
    assert "AFTER" in result.stdout


@pytest.mark.asyncio
async def test_job_executor_failure():
    executor = JobExecutor()
    job = JobDefinition(
        name="test_fail",
        original_name="test_fail",
        stage="test",
        script=["python3 -c 'import sys; sys.exit(42)'"],
    )
    result = await executor.execute_job(job)
    assert result.status == JobStatus.FAILED
    assert result.exit_code == 42


@pytest.mark.asyncio
async def test_job_executor_timeout():
    executor = JobExecutor()
    job = JobDefinition(
        name="test_timeout",
        original_name="test_timeout",
        stage="test",
        script=["sleep 3"],
        timeout=0.2,
    )
    result = await executor.execute_job(job)
    assert result.status == JobStatus.TIMED_OUT
    assert "timed out" in result.stderr.lower()


@pytest.mark.asyncio
async def test_job_executor_retry_mechanism():
    executor = JobExecutor()
    # Script that fails
    job = JobDefinition(
        name="test_retry",
        original_name="test_retry",
        stage="test",
        script=["python3 -c 'import sys; sys.exit(1)'"],
        retry=2,
    )
    result = await executor.execute_job(job)
    assert result.status == JobStatus.FAILED
    assert result.retry_count == 2


@pytest.mark.asyncio
async def test_job_executor_when_conditions():
    executor = JobExecutor()

    # Upstream failed
    upstream_failed = {
        "job_a": JobResult(
            name="job_a", stage="build", status=JobStatus.FAILED, exit_code=1
        )
    }

    # Job with on_success should be SKIPPED
    job_on_success = JobDefinition(
        name="job_b",
        original_name="job_b",
        stage="test",
        needs=["job_a"],
        when="on_success",
        script=["echo should not run"],
    )
    res_b = await executor.execute_job(job_on_success, upstream_results=upstream_failed)
    assert res_b.status == JobStatus.SKIPPED

    # Job with on_failure should RUN
    job_on_failure = JobDefinition(
        name="job_c",
        original_name="job_c",
        stage="notify",
        needs=["job_a"],
        when="on_failure",
        script=["echo 'Handling failure'"],
    )
    res_c = await executor.execute_job(job_on_failure, upstream_results=upstream_failed)
    assert res_c.status == JobStatus.SUCCESS

    # Job with always should RUN
    job_always = JobDefinition(
        name="job_d",
        original_name="job_d",
        stage="cleanup",
        needs=["job_a"],
        when="always",
        script=["echo 'Always runs'"],
    )
    res_d = await executor.execute_job(job_always, upstream_results=upstream_failed)
    assert res_d.status == JobStatus.SUCCESS


@pytest.mark.asyncio
async def test_job_executor_allow_failure():
    executor = PipelineExecutor(concurrency=2)
    pipeline = PipelineDefinition(
        name="Allow Failure Test",
        stages=["build", "test"],
        jobs={
            "flaky_job": JobDefinition(
                name="flaky_job",
                original_name="flaky_job",
                stage="build",
                script=["python3 -c 'import sys; sys.exit(1)'"],
                allow_failure=True,
            ),
            "next_job": JobDefinition(
                name="next_job",
                original_name="next_job",
                stage="test",
                needs=["flaky_job"],
                when="on_success",
                script=["echo 'Running despite flaky failure'"],
            ),
        },
    )
    res = await executor.execute_pipeline(pipeline)
    assert res.success is True
    assert res.job_results["flaky_job"].status == JobStatus.FAILED
    assert res.job_results["next_job"].status == JobStatus.SUCCESS


@pytest.mark.asyncio
async def test_job_executor_env_propagation():
    executor = JobExecutor()
    job = JobDefinition(
        name="env_job",
        original_name="env_job",
        stage="test",
        env={"CUSTOM_KEY": "CUSTOM_VALUE"},
        script=["python3 -c \"import os; print('KEY=' + os.environ.get('CUSTOM_KEY', ''))\""],
    )
    result = await executor.execute_job(job, pipeline_env={"GLOBAL_KEY": "GLOBAL_VAL"})
    assert result.status == JobStatus.SUCCESS
    assert "KEY=CUSTOM_VALUE" in result.stdout


@pytest.mark.asyncio
async def test_pipeline_executor_full_run():
    pipeline = PipelineDefinition(
        name="Full Pipeline",
        stages=["build", "test"],
        jobs={
            "build_1": JobDefinition(name="build_1", original_name="build_1", stage="build", script=["echo b1"]),
            "build_2": JobDefinition(name="build_2", original_name="build_2", stage="build", script=["echo b2"]),
            "test_1": JobDefinition(name="test_1", original_name="test_1", stage="test", needs=["build_1", "build_2"], script=["echo t1"]),
        },
    )
    executor = PipelineExecutor(concurrency=3)
    res = await executor.execute_pipeline(pipeline)
    assert res.success is True
    assert res.total_jobs == 3
    assert res.passed_jobs == 3
    assert res.failed_jobs == 0
    assert res.skipped_jobs == 0


@pytest.mark.asyncio
async def test_pipeline_executor_target_stages_filter():
    pipeline = PipelineDefinition(
        name="Stage Filter Pipeline",
        stages=["build", "test", "deploy"],
        jobs={
            "build_job": JobDefinition(name="build_job", original_name="build_job", stage="build", script=["echo build"]),
            "test_job": JobDefinition(name="test_job", original_name="test_job", stage="test", script=["echo test"]),
            "deploy_job": JobDefinition(name="deploy_job", original_name="deploy_job", stage="deploy", script=["echo deploy"]),
        },
    )
    executor = PipelineExecutor(concurrency=2)
    res = await executor.execute_pipeline(pipeline, target_stages=["build"])
    assert res.job_results["build_job"].status == JobStatus.SUCCESS
    assert res.job_results["test_job"].status == JobStatus.SKIPPED
    assert res.job_results["deploy_job"].status == JobStatus.SKIPPED


@pytest.mark.asyncio
async def test_pipeline_executor_dry_run():
    pipeline = PipelineDefinition(
        name="Dry Run Pipeline",
        jobs={
            "simulated": JobDefinition(name="simulated", original_name="simulated", stage="default", script=["do_something_heavy"]),
        },
    )
    executor = PipelineExecutor()
    res = await executor.execute_pipeline(pipeline, dry_run=True)
    assert res.success is True
    assert "[DRY-RUN]" in res.job_results["simulated"].stdout
