"""
Console Reporter with ANSI formatting, live status output, and summary tables.
"""

from __future__ import annotations

import sys
from typing import List

from runner.dag import DAG
from runner.executor import JobResult, JobStatus, PipelineResult
from runner.parser import JobDefinition


class ConsoleReporter:
    """Renders formatted CLI progress and summary reports."""

    GREEN = "\033[92m"
    RED = "\033[91m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    BOLD = "\033[1m"
    RESET = "\033[0m"

    def __init__(self, color: bool = True) -> None:
        self.color = color and sys.stdout.isatty()

    def _c(self, text: str, color_code: str) -> str:
        if not self.color:
            return text
        return f"{color_code}{text}{self.RESET}"

    def print_header(self, pipeline_name: str, total_jobs: int, concurrency: int) -> None:
        print(self._c("=" * 65, self.CYAN))
        print(self._c(f" 🚀 PIPELINE: {pipeline_name}", self.BOLD))
        print(self._c(f"    Total Jobs: {total_jobs} | Concurrency: {concurrency}", self.BLUE))
        print(self._c("=" * 65, self.CYAN))

    def print_job_result(self, result: JobResult) -> None:
        if result.status == JobStatus.SUCCESS:
            badge = self._c(" ✔ PASSED ", self.GREEN)
        elif result.status == JobStatus.FAILED:
            if result.allow_failure:
                badge = self._c(" ⚠ ALLOWED ", self.YELLOW)
            else:
                badge = self._c(" ✖ FAILED ", self.RED)
        elif result.status == JobStatus.TIMED_OUT:
            badge = self._c(" ⏱ TIMEOUT ", self.MAGENTA)
        elif result.status == JobStatus.SKIPPED:
            badge = self._c(" ⊘ SKIPPED ", self.YELLOW)
        else:
            badge = self._c(f" ? {result.status.value} ", self.BLUE)

        dur = f"({result.duration_seconds:.2f}s)"
        retry_str = f" [retried {result.retry_count}x]" if result.retry_count > 0 else ""
        print(f"[{badge}] [{result.stage:<10}] {result.name} {dur}{retry_str}")

        if result.status in (JobStatus.FAILED, JobStatus.TIMED_OUT) and not result.allow_failure:
            if result.stderr:
                indent_err = "\n".join("    | " + line for line in result.stderr.strip().splitlines())
                print(self._c(indent_err, self.RED))

    def print_summary(self, result: PipelineResult) -> None:
        print(self._c("\n" + "=" * 65, self.CYAN))
        status_text = (
            self._c("✔ PIPELINE SUCCEEDED", self.GREEN + self.BOLD)
            if result.success
            else self._c("✖ PIPELINE FAILED", self.RED + self.BOLD)
        )
        print(f" Status:   {status_text}")
        print(f" Duration: {result.total_duration_seconds:.3f} seconds")
        print(f" Summary:  {result.passed_jobs} passed, {result.failed_jobs} failed, {result.skipped_jobs} skipped (total {result.total_jobs})")
        print(self._c("=" * 65 + "\n", self.CYAN))

    def print_dag_graph(self, dag: DAG) -> None:
        print(self._c(dag.to_ascii(), self.CYAN))

    def print_dry_run_plan(self, layers: List[List[JobDefinition]]) -> None:
        print(self._c("=" * 65, self.CYAN))
        print(self._c(" 📋 DRY-RUN: PLANNED EXECUTION STAGES", self.BOLD))
        print(self._c("=" * 65, self.CYAN))
        for idx, layer in enumerate(layers):
            print(self._c(f"\n[Parallel Stage {idx + 1}] ({len(layer)} job{'s' if len(layer) > 1 else ''})", self.BOLD))
            for job in layer:
                deps = f" (needs: {', '.join(job.needs)})" if job.needs else ""
                print(f"  • {job.name} [stage: {job.stage}, timeout: {job.timeout}s]{deps}")
                for cmd in job.script:
                    print(f"      $ {cmd}")
        print(self._c("\n" + "=" * 65 + "\n", self.CYAN))
