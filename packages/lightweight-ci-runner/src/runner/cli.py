"""
Command-Line Interface (CLI) for Lightweight CI Runner.
Subcommands: run, validate, graph, dry-run.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path
from typing import List, Optional

from runner.dag import DAG, CircularDependencyError, DependencyError
from runner.executor import PipelineExecutor
from runner.parser import (
    ParserError,
    SecurityError,
    parse_pipeline_file,
)
from runner.reporters.console import ConsoleReporter
from runner.reporters.junit import generate_junit_xml


def parse_env_args(env_list: Optional[List[str]]) -> dict[str, str]:
    """Parses list of KEY=VALUE strings into dictionary."""
    result: dict[str, str] = {}
    if not env_list:
        return result
    for item in env_list:
        if "=" in item:
            k, v = item.split("=", 1)
            result[k.strip()] = v.strip()
        else:
            result[item.strip()] = ""
    return result


async def run_command(args: argparse.Namespace) -> int:
    """Executes the pipeline run subcommand."""
    pipeline_file = Path(args.file).resolve()
    no_color = getattr(args, "no_color", False)
    reporter = ConsoleReporter(color=not no_color)

    try:
        pipeline = parse_pipeline_file(pipeline_file)
    except (SecurityError, ParserError, FileNotFoundError, Exception) as e:
        print(f"Error: {e}", file=sys.stderr)
        return 2

    # CLI env overrides
    cli_env = parse_env_args(args.env)
    if cli_env:
        pipeline.env.update(cli_env)
        for job in pipeline.jobs.values():
            job.env.update(cli_env)

    concurrency = args.concurrency if args.concurrency is not None else pipeline.concurrency
    target_stages = args.stage if args.stage else None

    if not args.json:
        reporter.print_header(pipeline.name, len(pipeline.jobs), concurrency)

    executor = PipelineExecutor(concurrency=concurrency)
    result = await executor.execute_pipeline(
        pipeline=pipeline,
        target_stages=target_stages,
        dry_run=False,
    )

    if not args.json:
        for job_res in result.job_results.values():
            reporter.print_job_result(job_res)
        reporter.print_summary(result)
    else:
        print(json.dumps(result.model_dump(), indent=2))

    if args.junit:
        generate_junit_xml(result, output_path=args.junit)
        if not args.json:
            print(f"Report generated: {args.junit}")

    return 0 if result.success else 1


def validate_command(args: argparse.Namespace) -> int:
    """Validates the syntax and DAG integrity of a pipeline file without execution."""
    pipeline_file = Path(args.file).resolve()
    try:
        pipeline = parse_pipeline_file(pipeline_file)
        dag = DAG.from_pipeline(pipeline)
        dag.validate()
        layers = dag.get_execution_layers()
        print(f"✔ Pipeline '{pipeline.name}' is valid.")
        print(f"  Total jobs: {len(pipeline.jobs)}")
        print(f"  Parallel execution layers: {len(layers)}")
        return 0
    except (SecurityError, ParserError, DependencyError, CircularDependencyError, FileNotFoundError, Exception) as e:
        print(f"Validation Error: {e}", file=sys.stderr)
        return 2


def graph_command(args: argparse.Namespace) -> int:
    """Generates ASCII or DOT visual representation of the pipeline DAG."""
    pipeline_file = Path(args.file).resolve()
    no_color = getattr(args, "no_color", False)
    try:
        pipeline = parse_pipeline_file(pipeline_file)
        dag = DAG.from_pipeline(pipeline)
        dag.validate()
    except Exception as e:
        print(f"Error loading DAG: {e}", file=sys.stderr)
        return 2

    if args.format == "dot":
        print(dag.to_dot())
    else:
        reporter = ConsoleReporter(color=not no_color)
        reporter.print_dag_graph(dag)

    return 0


async def dry_run_command(args: argparse.Namespace) -> int:
    """Simulates pipeline execution step-by-step."""
    pipeline_file = Path(args.file).resolve()
    no_color = getattr(args, "no_color", False)
    reporter = ConsoleReporter(color=not no_color)

    try:
        pipeline = parse_pipeline_file(pipeline_file)
        dag = DAG.from_pipeline(pipeline)
        dag.validate()
    except Exception as e:
        print(f"Error loading pipeline: {e}", file=sys.stderr)
        return 2

    layers = dag.get_execution_layers()
    reporter.print_dry_run_plan(layers)

    executor = PipelineExecutor(concurrency=pipeline.concurrency)
    result = await executor.execute_pipeline(pipeline=pipeline, dry_run=True)

    if args.junit:
        generate_junit_xml(result, output_path=args.junit)
        print(f"Dry-run report generated: {args.junit}")

    return 0


def create_parser() -> argparse.ArgumentParser:
    """Constructs the argument parser for the CLI."""
    common_parser = argparse.ArgumentParser(add_help=False)
    common_parser.add_argument("--no-color", action="store_true", help="Disable colored output")

    parser = argparse.ArgumentParser(
        prog="lightweight-ci",
        description="Enterprise DAG-based lightweight CI/CD pipeline runner.",
        parents=[common_parser],
    )

    subparsers = parser.add_subparsers(dest="command", help="Subcommand to execute")

    # Run subcommand
    run_parser = subparsers.add_parser("run", help="Execute the pipeline", parents=[common_parser])
    run_parser.add_argument("-f", "--file", default=".ci-pipeline.yml", help="Path to pipeline file")
    run_parser.add_argument("-j", "--junit", default=None, help="Path to write JUnit XML report")
    run_parser.add_argument("-c", "--concurrency", type=int, default=None, help="Max parallel jobs")
    run_parser.add_argument("-s", "--stage", action="append", help="Filter by specific stage(s)")
    run_parser.add_argument("-e", "--env", action="append", help="Set environment variable (KEY=VAL)")
    run_parser.add_argument("--json", action="store_true", help="Output results in JSON format")

    # Validate subcommand
    val_parser = subparsers.add_parser("validate", help="Validate pipeline syntax and DAG integrity", parents=[common_parser])
    val_parser.add_argument("-f", "--file", default=".ci-pipeline.yml", help="Path to pipeline file")

    # Graph subcommand
    graph_parser = subparsers.add_parser("graph", help="Display execution graph (ASCII or DOT)", parents=[common_parser])
    graph_parser.add_argument("-f", "--file", default=".ci-pipeline.yml", help="Path to pipeline file")
    graph_parser.add_argument("--format", choices=["ascii", "dot"], default="ascii", help="Graph format")

    # Dry-run subcommand
    dry_parser = subparsers.add_parser("dry-run", help="Simulate pipeline execution without running scripts", parents=[common_parser])
    dry_parser.add_argument("-f", "--file", default=".ci-pipeline.yml", help="Path to pipeline file")
    dry_parser.add_argument("-j", "--junit", default=None, help="Path to write JUnit XML report")

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    """CLI entrypoint."""
    parser = create_parser()
    args = parser.parse_args(argv)

    if not args.command:
        parser.print_help()
        return 0

    if args.command == "run":
        return asyncio.run(run_command(args))
    elif args.command == "validate":
        return validate_command(args)
    elif args.command == "graph":
        return graph_command(args)
    elif args.command == "dry-run":
        return asyncio.run(dry_run_command(args))

    return 0


if __name__ == "__main__":
    sys.exit(main())
