"""
JUnit XML Reporter compliant with standard CI/CD XML test report schemas.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Optional, Union

from runner.executor import JobResult, JobStatus, PipelineResult


def _indent_xml(elem: ET.Element, level: int = 0) -> None:
    """Pretty prints XML element in-place with standard indentation."""
    i = "\n" + level * "  "
    if len(elem):
        if not elem.text or not elem.text.strip():
            elem.text = i + "  "
        if not elem.tail or not elem.tail.strip():
            elem.tail = i
        for subelem in elem:
            _indent_xml(subelem, level + 1)
        if not elem.tail or not elem.tail.strip():
            elem.tail = i
    else:
        if level and (not elem.tail or not elem.tail.strip()):
            elem.tail = i


def generate_junit_xml(
    pipeline_result: PipelineResult,
    output_path: Optional[Union[str, Path]] = None,
) -> str:
    """
    Generates a compliant JUnit XML string from PipelineResult and optionally writes to file.
    """
    # Group jobs by stage
    stages_map: Dict[str, List[JobResult]] = defaultdict(list)
    for job_res in pipeline_result.job_results.values():
        stages_map[job_res.stage].append(job_res)

    total_failures = sum(
        1 for r in pipeline_result.job_results.values()
        if r.status == JobStatus.FAILED
    )
    total_errors = sum(
        1 for r in pipeline_result.job_results.values()
        if r.status in (JobStatus.TIMED_OUT, JobStatus.CANCELLED)
    )

    testsuites = ET.Element("testsuites", {
        "name": pipeline_result.pipeline_name,
        "tests": str(pipeline_result.total_jobs),
        "failures": str(total_failures),
        "errors": str(total_errors),
        "skipped": str(pipeline_result.skipped_jobs),
        "time": f"{pipeline_result.total_duration_seconds:.3f}",
    })

    for stage_name, jobs in sorted(stages_map.items()):
        stage_tests = len(jobs)
        stage_failures = sum(1 for r in jobs if r.status == JobStatus.FAILED)
        stage_errors = sum(1 for r in jobs if r.status in (JobStatus.TIMED_OUT, JobStatus.CANCELLED))
        stage_skipped = sum(1 for r in jobs if r.status == JobStatus.SKIPPED)
        stage_duration = sum(r.duration_seconds for r in jobs)

        testsuite = ET.SubElement(testsuites, "testsuite", {
            "name": stage_name,
            "tests": str(stage_tests),
            "failures": str(stage_failures),
            "errors": str(stage_errors),
            "skipped": str(stage_skipped),
            "time": f"{stage_duration:.3f}",
        })

        for job in jobs:
            testcase = ET.SubElement(testsuite, "testcase", {
                "classname": f"pipeline.{stage_name}",
                "name": job.name,
                "time": f"{job.duration_seconds:.3f}",
            })

            if job.status == JobStatus.FAILED:
                msg = job.error_message or "Job script execution failed with non-zero exit code"
                failure = ET.SubElement(testcase, "failure", {
                    "message": msg,
                    "type": "JobFailure",
                })
                failure.text = job.stderr or msg

            elif job.status == JobStatus.TIMED_OUT:
                msg = job.error_message or "Job exceeded allocated execution timeout limit"
                error = ET.SubElement(testcase, "error", {
                    "message": msg,
                    "type": "JobTimeout",
                })
                error.text = job.stderr or msg

            elif job.status == JobStatus.SKIPPED:
                skipped = ET.SubElement(testcase, "skipped", {
                    "message": job.stderr or "Job skipped due to dependency rules",
                })

            if job.stdout:
                sys_out = ET.SubElement(testcase, "system-out")
                sys_out.text = job.stdout

            if job.stderr:
                sys_err = ET.SubElement(testcase, "system-err")
                sys_err.text = job.stderr

    _indent_xml(testsuites)
    xml_declaration = '<?xml version="1.0" encoding="UTF-8"?>\n'
    xml_str = xml_declaration + ET.tostring(testsuites, encoding="utf-8").decode("utf-8")

    if output_path:
        out_p = Path(output_path).resolve()
        out_p.parent.mkdir(parents=True, exist_ok=True)
        out_p.write_text(xml_str, encoding="utf-8")

    return xml_str
