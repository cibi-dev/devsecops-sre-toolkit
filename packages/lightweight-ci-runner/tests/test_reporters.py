"""
Unit tests for ConsoleReporter and reporter utilities.
"""

from runner.dag import DAG
from runner.executor import JobResult, JobStatus, PipelineResult
from runner.parser import JobDefinition
from runner.reporters.console import ConsoleReporter


def test_console_reporter_colored_and_uncolored():
    rep_color = ConsoleReporter(color=True)
    rep_plain = ConsoleReporter(color=False)

    assert rep_plain._c("text", ConsoleReporter.GREEN) == "text"


def test_console_reporter_print_header(capsys):
    rep = ConsoleReporter(color=False)
    rep.print_header("My Pipeline", 10, 4)
    out = capsys.readouterr().out
    assert "PIPELINE: My Pipeline" in out
    assert "Total Jobs: 10" in out
    assert "Concurrency: 4" in out


def test_console_reporter_job_results(capsys):
    rep = ConsoleReporter(color=False)

    # Success
    r1 = JobResult(name="j1", stage="build", status=JobStatus.SUCCESS, duration_seconds=1.0)
    rep.print_job_result(r1)

    # Failed
    r2 = JobResult(name="j2", stage="test", status=JobStatus.FAILED, duration_seconds=2.0, stderr="Error log line 1\nError log line 2")
    rep.print_job_result(r2)

    # Failed with allow_failure
    r3 = JobResult(name="j3", stage="test", status=JobStatus.FAILED, duration_seconds=0.5, allow_failure=True)
    rep.print_job_result(r3)

    # Timed out
    r4 = JobResult(name="j4", stage="test", status=JobStatus.TIMED_OUT, duration_seconds=5.0, retry_count=1)
    rep.print_job_result(r4)

    # Skipped
    r5 = JobResult(name="j5", stage="deploy", status=JobStatus.SKIPPED, duration_seconds=0.0)
    rep.print_job_result(r5)

    out = capsys.readouterr().out
    assert "PASSED" in out
    assert "FAILED" in out
    assert "ALLOWED" in out
    assert "TIMEOUT" in out
    assert "SKIPPED" in out
    assert "retried 1x" in out
    assert "Error log line 1" in out


def test_console_reporter_summary(capsys):
    rep = ConsoleReporter(color=False)

    res_success = PipelineResult(
        pipeline_name="Success P",
        success=True,
        total_duration_seconds=3.14,
        total_jobs=2,
        passed_jobs=2,
        failed_jobs=0,
        skipped_jobs=0,
    )
    rep.print_summary(res_success)
    out = capsys.readouterr().out
    assert "PIPELINE SUCCEEDED" in out
    assert "3.140 seconds" in out

    res_failed = PipelineResult(
        pipeline_name="Fail P",
        success=False,
        total_duration_seconds=1.5,
        total_jobs=2,
        passed_jobs=1,
        failed_jobs=1,
        skipped_jobs=0,
    )
    rep.print_summary(res_failed)
    out2 = capsys.readouterr().out
    assert "PIPELINE FAILED" in out2


def test_console_reporter_graph_and_dry_run(capsys):
    rep = ConsoleReporter(color=False)
    dag = DAG()
    j1 = JobDefinition(name="job1", original_name="job1", stage="build", script=["echo 1"])
    j2 = JobDefinition(name="job2", original_name="job2", stage="test", needs=["job1"], script=["echo 2"])
    dag.add_job(j1)
    dag.add_job(j2)
    dag.add_dependency("job2", "job1")

    rep.print_dag_graph(dag)
    out = capsys.readouterr().out
    assert "PIPELINE EXECUTION DAG" in out

    rep.print_dry_run_plan([[j1], [j2]])
    out2 = capsys.readouterr().out
    assert "DRY-RUN: PLANNED EXECUTION STAGES" in out2
    assert "job1" in out2
    assert "job2" in out2
