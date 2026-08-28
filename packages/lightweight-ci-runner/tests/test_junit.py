"""
Unit tests for JUnit XML Reporter schema conformity and formatting.
"""

import xml.etree.ElementTree as ET
from pathlib import Path

try:
    from defusedxml.ElementTree import fromstring as safe_fromstring
except ImportError:
    safe_fromstring = ET.fromstring  # type: ignore

from runner.executor import JobResult, JobStatus, PipelineResult
from runner.reporters.junit import generate_junit_xml


def test_generate_junit_xml_structure():
    job1 = JobResult(
        name="job_lint",
        stage="lint",
        status=JobStatus.SUCCESS,
        duration_seconds=1.234,
        stdout="All files linted cleanly",
    )
    job2 = JobResult(
        name="job_test",
        stage="test",
        status=JobStatus.FAILED,
        duration_seconds=2.500,
        stderr="AssertionError: expected 1 == 2",
        error_message="Test failure",
    )
    job3 = JobResult(
        name="job_timeout",
        stage="test",
        status=JobStatus.TIMED_OUT,
        duration_seconds=5.000,
        stderr="Job timed out",
    )
    job4 = JobResult(
        name="job_deploy",
        stage="deploy",
        status=JobStatus.SKIPPED,
        duration_seconds=0.000,
        stderr="Skipped upstream failure",
    )

    pipeline_result = PipelineResult(
        pipeline_name="Enterprise CI Test",
        success=False,
        total_duration_seconds=8.734,
        job_results={
            "job_lint": job1,
            "job_test": job2,
            "job_timeout": job3,
            "job_deploy": job4,
        },
        total_jobs=4,
        passed_jobs=1,
        failed_jobs=2,
        skipped_jobs=1,
    )

    xml_content = generate_junit_xml(pipeline_result)
    assert xml_content.startswith("<?xml")

    # Verify it parses as valid XML
    root = safe_fromstring(xml_content.replace('<?xml version="1.0" encoding="UTF-8"?>\n', ""))  # nosec B314
    assert root.tag == "testsuites"
    assert root.attrib["name"] == "Enterprise CI Test"
    assert root.attrib["tests"] == "4"
    assert root.attrib["failures"] == "1"
    assert root.attrib["errors"] == "1"
    assert root.attrib["skipped"] == "1"

    # Verify testsuites children
    suites = list(root.findall("testsuite"))
    stage_names = {s.attrib["name"] for s in suites}
    assert stage_names == {"lint", "test", "deploy"}

    # Find testcase in lint
    lint_suite = [s for s in suites if s.attrib["name"] == "lint"][0]
    lint_tc = lint_suite.find("testcase")
    assert lint_tc is not None
    assert lint_tc.attrib["name"] == "job_lint"
    assert lint_tc.find("system-out").text == "All files linted cleanly"

    # Find testcase in test
    test_suite = [s for s in suites if s.attrib["name"] == "test"][0]
    testcases = {tc.attrib["name"]: tc for tc in test_suite.findall("testcase")}
    assert testcases["job_test"].find("failure") is not None
    assert testcases["job_timeout"].find("error") is not None


def test_generate_junit_xml_escaping():
    special_chars_job = JobResult(
        name="job_special",
        stage="test",
        status=JobStatus.FAILED,
        duration_seconds=0.5,
        stdout="Output with <tags> & \"quotes\" & 'single'",
        stderr="Error with <xml_conflict> & symbols",
        error_message="Message with <tag> & `code`",
    )

    res = PipelineResult(
        pipeline_name="Special <Chars> & Pipeline",
        success=False,
        total_duration_seconds=0.5,
        job_results={"job_special": special_chars_job},
        total_jobs=1,
        passed_jobs=0,
        failed_jobs=1,
        skipped_jobs=0,
    )

    xml_content = generate_junit_xml(res)
    # Parse to verify XML validity
    root = safe_fromstring(xml_content.split("\n", 1)[1])  # nosec B314
    assert root.attrib["name"] == "Special <Chars> & Pipeline"
    tc = root.find("testsuite").find("testcase")
    failure = tc.find("failure")
    assert "<xml_conflict>" in failure.text


def test_generate_junit_xml_write_file(tmp_path: Path):
    pipeline_result = PipelineResult(
        pipeline_name="File Output Test",
        success=True,
        total_duration_seconds=1.0,
        job_results={
            "job1": JobResult(
                name="job1", stage="build", status=JobStatus.SUCCESS, duration_seconds=1.0
            )
        },
        total_jobs=1,
        passed_jobs=1,
        failed_jobs=0,
        skipped_jobs=0,
    )

    out_file = tmp_path / "reports" / "junit.xml"
    generate_junit_xml(pipeline_result, output_path=out_file)
    assert out_file.is_file()
    assert "<testsuites" in out_file.read_text(encoding="utf-8")
