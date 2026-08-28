"""
Asynchronous Process-Isolated Job and Pipeline Execution Engine.
Implements bounded concurrency, job timeouts (CWE-400), retries, and output capture.
"""

from __future__ import annotations

import asyncio
import os
import signal
import time
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Set, Union

from pydantic import BaseModel, Field

from runner.dag import DAG
from runner.parser import JobDefinition, PipelineDefinition
from runner.sandbox import (
    build_sanitized_env,
    sanitize_output,
    tokenize_command,
    validate_working_dir,
)


class JobStatus(str, Enum):
    """Lifecycle status of a pipeline job."""
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"
    SKIPPED = "SKIPPED"
    TIMED_OUT = "TIMED_OUT"
    CANCELLED = "CANCELLED"


class JobResult(BaseModel):
    """Summary execution outcome for an individual job."""
    name: str
    stage: str
    status: JobStatus
    exit_code: int = 0
    duration_seconds: float = 0.0
    stdout: str = ""
    stderr: str = ""
    error_message: Optional[str] = None
    retry_count: int = 0
    start_time: Optional[float] = None
    end_time: Optional[float] = None
    allow_failure: bool = False


class PipelineResult(BaseModel):
    """Aggregate result of an entire pipeline run."""
    pipeline_name: str
    success: bool
    total_duration_seconds: float
    job_results: Dict[str, JobResult] = Field(default_factory=dict)
    total_jobs: int = 0
    passed_jobs: int = 0
    failed_jobs: int = 0
    skipped_jobs: int = 0


class JobExecutor:
    """Executes a single job within an isolated process sandbox."""

    def __init__(self, allowed_root: Optional[Union[str, Path]] = None) -> None:
        self.allowed_root = allowed_root

    async def _run_command(
        self,
        cmd_tokens: List[str],
        env: Dict[str, str],
        working_dir: Path,
        timeout: float,
    ) -> tuple[int, str, str, bool]:
        """
        Executes a tokenized command using asyncio.create_subprocess_exec (shell=False).
        Returns (exit_code, stdout_str, stderr_str, timed_out).
        """
        process = None
        try:
            # CWE-78: subprocess execution with discrete argument tokens and shell=False
            process = await asyncio.create_subprocess_exec(
                *cmd_tokens,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=str(working_dir),
                env=env,
            )

            # CWE-400: Explicit timeout bounding
            stdout_bytes, stderr_bytes = await asyncio.wait_for(
                process.communicate(),
                timeout=timeout,
            )
            exit_code = process.returncode if process.returncode is not None else 0
            stdout_str = stdout_bytes.decode("utf-8", errors="replace")
            stderr_str = stderr_bytes.decode("utf-8", errors="replace")
            return exit_code, stdout_str, stderr_str, False

        except asyncio.TimeoutError:
            if process:
                try:
                    process.kill()
                    await process.wait()
                except Exception:
                    pass
            return -1, "", f"Job timed out after exceeding timeout limit of {timeout}s (CWE-400 prevention)", True

        except Exception as e:
            if process:
                try:
                    process.kill()
                except Exception:
                    pass
            return 1, "", f"Command execution error: {e}", False

    async def execute_job(
        self,
        job: JobDefinition,
        pipeline_env: Optional[Dict[str, str]] = None,
        secrets: Optional[List[str]] = None,
        upstream_results: Optional[Dict[str, JobResult]] = None,
    ) -> JobResult:
        """
        Executes a job definition according to dependency conditions, retries, and scripts.
        """
        start_ts = time.time()
        upstream_results = upstream_results or {}
        secrets = secrets or []

        # 1. Evaluate 'when' condition relative to upstream dependencies
        should_skip = False
        skip_reason = ""

        if job.needs:
            upstream_deps = [upstream_results[dep] for dep in job.needs if dep in upstream_results]
            has_failed_upstream = any(
                d.status in (JobStatus.FAILED, JobStatus.TIMED_OUT) and not d.allow_failure
                for d in upstream_deps
            )
            has_skipped_upstream = any(d.status == JobStatus.SKIPPED for d in upstream_deps)

            if job.when == "on_success":
                if has_failed_upstream:
                    should_skip = True
                    skip_reason = "Skipped: Upstream dependency failed"
                elif has_skipped_upstream:
                    should_skip = True
                    skip_reason = "Skipped: Upstream dependency was skipped"

            elif job.when == "on_failure":
                if not has_failed_upstream:
                    should_skip = True
                    skip_reason = "Skipped: No upstream dependencies failed (when: on_failure)"

        if should_skip:
            duration = time.time() - start_ts
            return JobResult(
                name=job.name,
                stage=job.stage,
                status=JobStatus.SKIPPED,
                exit_code=0,
                duration_seconds=round(duration, 4),
                stdout="",
                stderr=skip_reason,
                start_time=start_ts,
                end_time=time.time(),
                allow_failure=job.allow_failure,
            )

        # 2. Setup execution environment and working directory
        try:
            working_dir = validate_working_dir(job.working_dir, allowed_root=self.allowed_root)
        except Exception as e:
            duration = time.time() - start_ts
            return JobResult(
                name=job.name,
                stage=job.stage,
                status=JobStatus.FAILED,
                exit_code=2,
                duration_seconds=round(duration, 4),
                stdout="",
                stderr=f"Security / Working directory validation error: {e}",
                error_message=str(e),
                start_time=start_ts,
                end_time=time.time(),
                allow_failure=job.allow_failure,
            )

        env = build_sanitized_env(pipeline_env, job.env, secrets)
        env["CI_JOB_NAME"] = job.name
        env["CI_STAGE"] = job.stage

        # Combine execution scripts
        all_scripts = list(job.before_script) + list(job.script) + list(job.after_script)

        # 3. Retry loop
        max_attempts = job.retry + 1
        current_attempt = 0
        final_status = JobStatus.SUCCESS
        final_exit_code = 0
        final_stdout_chunks: List[str] = []
        final_stderr_chunks: List[str] = []
        final_error_msg: Optional[str] = None

        while current_attempt < max_attempts:
            current_attempt += 1
            attempt_stdout: List[str] = []
            attempt_stderr: List[str] = []
            attempt_failed = False
            timed_out = False

            for cmd_str in all_scripts:
                try:
                    tokens = tokenize_command(cmd_str)
                except ValueError as e:
                    attempt_stderr.append(f"Command tokenization error: {e}")
                    attempt_failed = True
                    final_exit_code = 2
                    final_error_msg = str(e)
                    break

                exit_code, out, err, is_timeout = await self._run_command(
                    tokens, env, working_dir, job.timeout
                )

                if out:
                    attempt_stdout.append(out)
                if err:
                    attempt_stderr.append(err)

                if is_timeout:
                    timed_out = True
                    attempt_failed = True
                    final_exit_code = -1
                    final_error_msg = f"Job exceeded timeout of {job.timeout}s"
                    break

                if exit_code != 0:
                    attempt_failed = True
                    final_exit_code = exit_code
                    final_error_msg = f"Command '{cmd_str}' exited with code {exit_code}"
                    break

            final_stdout_chunks = attempt_stdout
            final_stderr_chunks = attempt_stderr

            if timed_out:
                final_status = JobStatus.TIMED_OUT
                break  # Do not retry on timeout

            if not attempt_failed:
                final_status = JobStatus.SUCCESS
                final_exit_code = 0
                final_error_msg = None
                break
            else:
                final_status = JobStatus.FAILED
                if current_attempt < max_attempts:
                    # Optional brief pause before retry
                    await asyncio.sleep(0.05)

        duration = time.time() - start_ts
        raw_stdout = "\n".join(final_stdout_chunks)
        raw_stderr = "\n".join(final_stderr_chunks)

        # CWE-209 / CWE-532: Log sanitization
        sanitized_stdout = sanitize_output(raw_stdout, secrets)
        sanitized_stderr = sanitize_output(raw_stderr, secrets)

        return JobResult(
            name=job.name,
            stage=job.stage,
            status=final_status,
            exit_code=final_exit_code,
            duration_seconds=round(duration, 4),
            stdout=sanitized_stdout,
            stderr=sanitized_stderr,
            error_message=final_error_msg,
            retry_count=current_attempt - 1,
            start_time=start_ts,
            end_time=time.time(),
            allow_failure=job.allow_failure,
        )


class PipelineExecutor:
    """Orchestrates concurrent execution of jobs across the DAG with bounded concurrency."""

    def __init__(
        self,
        concurrency: int = 4,
        allowed_root: Optional[Union[str, Path]] = None,
    ) -> None:
        self.concurrency = max(1, concurrency)
        self.job_executor = JobExecutor(allowed_root=allowed_root)

    async def execute_pipeline(
        self,
        pipeline: PipelineDefinition,
        target_stages: Optional[List[str]] = None,
        dry_run: bool = False,
    ) -> PipelineResult:
        """
        Executes all jobs in the pipeline according to DAG topological dependencies.
        """
        start_ts = time.time()
        dag = DAG.from_pipeline(pipeline)
        dag.validate()

        effective_concurrency = min(self.concurrency, pipeline.concurrency)
        semaphore = asyncio.Semaphore(effective_concurrency)

        results: Dict[str, JobResult] = {}
        completed_events: Dict[str, asyncio.Event] = {
            job_name: asyncio.Event() for job_name in pipeline.jobs
        }

        async def run_single_job(job: JobDefinition) -> None:
            # Check target stages filter
            if target_stages and job.stage not in target_stages:
                # Mark as skipped if stage is not targeted
                results[job.name] = JobResult(
                    name=job.name,
                    stage=job.stage,
                    status=JobStatus.SKIPPED,
                    exit_code=0,
                    duration_seconds=0.0,
                    stdout="",
                    stderr=f"Skipped: Stage '{job.stage}' was not targeted for execution",
                    start_time=time.time(),
                    end_time=time.time(),
                    allow_failure=job.allow_failure,
                )
                completed_events[job.name].set()
                return

            # Wait for all direct upstream dependencies to finish
            for dep_name in job.needs:
                if dep_name in completed_events:
                    await completed_events[dep_name].wait()

            if dry_run:
                # Dry run mode: simulate execution
                await asyncio.sleep(0.001)
                results[job.name] = JobResult(
                    name=job.name,
                    stage=job.stage,
                    status=JobStatus.SUCCESS,
                    exit_code=0,
                    duration_seconds=0.001,
                    stdout=f"[DRY-RUN] Would execute {len(job.script)} commands in stage '{job.stage}'",
                    stderr="",
                    start_time=time.time(),
                    end_time=time.time(),
                    allow_failure=job.allow_failure,
                )
                completed_events[job.name].set()
                return

            # Execute job with bounded concurrency
            async with semaphore:
                result = await self.job_executor.execute_job(
                    job=job,
                    pipeline_env=pipeline.env,
                    secrets=pipeline.secrets,
                    upstream_results=results,
                )
                results[job.name] = result
                completed_events[job.name].set()

        # Launch all job runner tasks concurrently
        tasks = [asyncio.create_task(run_single_job(job)) for job in pipeline.jobs.values()]
        await asyncio.gather(*tasks)

        total_duration = time.time() - start_ts

        # Tally metrics
        total = len(results)
        passed = sum(1 for r in results.values() if r.status == JobStatus.SUCCESS)
        skipped = sum(1 for r in results.values() if r.status == JobStatus.SKIPPED)
        failed = sum(
            1 for r in results.values()
            if r.status in (JobStatus.FAILED, JobStatus.TIMED_OUT, JobStatus.CANCELLED)
        )

        # Pipeline is considered successful if all unskipped jobs succeeded,
        # or if failed jobs had allow_failure=True
        critical_failures = any(
            r.status in (JobStatus.FAILED, JobStatus.TIMED_OUT, JobStatus.CANCELLED) and not r.allow_failure
            for r in results.values()
        )
        overall_success = not critical_failures

        return PipelineResult(
            pipeline_name=pipeline.name,
            success=overall_success,
            total_duration_seconds=round(total_duration, 4),
            job_results=results,
            total_jobs=total,
            passed_jobs=passed,
            failed_jobs=failed,
            skipped_jobs=skipped,
        )
