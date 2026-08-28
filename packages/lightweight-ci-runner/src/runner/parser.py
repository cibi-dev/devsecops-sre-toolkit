"""
Secure Pipeline YAML Parser with Pydantic v2 validation.
Implements CWE-20, CWE-502, and CWE-400 mitigations.
"""

from __future__ import annotations

import itertools
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

import yaml
from pydantic import BaseModel, Field, field_validator, model_validator


# Security constraint: Maximum allowed YAML pipeline file size (1MB) to prevent CWE-400 (DoS/Billion Laughs)
MAX_PIPELINE_FILE_SIZE = 1024 * 1024  # 1,048,576 bytes


class SecurityError(ValueError):
    """Raised when security boundaries or resource limits are breached."""
    pass


class ParserError(ValueError):
    """Raised when pipeline syntax or schema validation fails."""
    pass


class JobModel(BaseModel):
    """Declarative specification of a pipeline job."""
    stage: str = Field(default="default", description="Pipeline stage for the job")
    needs: List[str] = Field(default_factory=list, description="Explicit dependencies on other jobs")
    script: Union[List[str], str] = Field(..., description="Commands to execute in the job")
    before_script: List[str] = Field(default_factory=list, description="Commands to execute before main script")
    after_script: List[str] = Field(default_factory=list, description="Commands to execute after main script")
    env: Dict[str, str] = Field(default_factory=dict, description="Environment variables for the job")
    matrix: Dict[str, List[Any]] = Field(default_factory=dict, description="Matrix build dimensions")
    timeout: float = Field(default=300.0, gt=0, description="Job execution timeout in seconds")
    retry: int = Field(default=0, ge=0, description="Number of retry attempts upon failure")
    allow_failure: bool = False
    when: str = Field(
        default="on_success",
        pattern=r"^(on_success|always|on_failure)$",
        description="Execution condition relative to upstream dependencies"
    )
    working_dir: Optional[str] = Field(default=None, description="Working directory for job execution")

    @field_validator("script", mode="before")
    @classmethod
    def normalize_script(cls, v: Any) -> List[str]:
        if isinstance(v, str):
            lines = [line.strip() for line in v.strip().splitlines() if line.strip()]
            if not lines:
                raise ValueError("Script field cannot be empty")
            return lines
        elif isinstance(v, list):
            if not v:
                raise ValueError("Script list cannot be empty")
            return [str(item).strip() for item in v if str(item).strip()]
        raise ValueError("Script must be a string or a list of strings")

    @field_validator("before_script", "after_script", mode="before")
    @classmethod
    def normalize_script_list(cls, v: Any) -> List[str]:
        if isinstance(v, str):
            return [line.strip() for line in v.strip().splitlines() if line.strip()]
        elif isinstance(v, list):
            return [str(item).strip() for item in v if str(item).strip()]
        return []

    @field_validator("env", mode="before")
    @classmethod
    def normalize_env(cls, v: Any) -> Dict[str, str]:
        if isinstance(v, dict):
            return {str(k): str(val) for k, val in v.items()}
        return {}


class PipelineModel(BaseModel):
    """Root model for pipeline configuration."""
    name: str = Field(default="CI Pipeline", description="Human-readable pipeline name")
    env: Dict[str, str] = Field(default_factory=dict, description="Global pipeline environment variables")
    secrets: List[str] = Field(default_factory=list, description="Names of secret environment variables to mask")
    stages: List[str] = Field(default_factory=list, description="Ordered stages of execution")
    concurrency: int = Field(default=4, gt=0, description="Maximum concurrent running jobs")
    jobs: Dict[str, JobModel] = Field(..., description="Mapping of job identifiers to job configurations")

    @model_validator(mode="after")
    def validate_jobs_and_stages(self) -> PipelineModel:
        if not self.jobs:
            raise ValueError("Pipeline must declare at least one job in 'jobs'")

        if self.stages:
            for j_name, j_model in self.jobs.items():
                if j_model.stage != "default" and j_model.stage not in self.stages:
                    raise ValueError(
                        f"Job '{j_name}' declared stage '{j_model.stage}' which is not in declared pipeline stages: {self.stages}"
                    )
        return self

    @field_validator("env", mode="before")
    @classmethod
    def normalize_pipeline_env(cls, v: Any) -> Dict[str, str]:
        if isinstance(v, dict):
            return {str(k): str(val) for k, val in v.items()}
        return {}


class JobDefinition(BaseModel):
    """Resolved and expanded job definition ready for DAG resolution and execution."""
    name: str
    original_name: str
    stage: str
    needs: List[str] = Field(default_factory=list)
    script: List[str]
    before_script: List[str] = Field(default_factory=list)
    after_script: List[str] = Field(default_factory=list)
    env: Dict[str, str] = Field(default_factory=dict)
    matrix_vars: Dict[str, str] = Field(default_factory=dict)
    timeout: float = 300.0
    retry: int = 0
    allow_failure: bool = False
    when: str = "on_success"
    working_dir: Optional[str] = None


class PipelineDefinition(BaseModel):
    """Complete parsed pipeline ready for DAG resolution."""
    name: str
    env: Dict[str, str] = Field(default_factory=dict)
    secrets: List[str] = Field(default_factory=list)
    stages: List[str] = Field(default_factory=list)
    concurrency: int = 4
    jobs: Dict[str, JobDefinition] = Field(default_factory=dict)


def _substitute_matrix_vars(text: str, matrix_vars: Dict[str, str]) -> str:
    """Substitute ${{ matrix.KEY }}, $matrix.KEY, and ${KEY} patterns."""
    result = text
    for key, value in matrix_vars.items():
        result = re.sub(rf"\${{\{{\s*matrix\.{re.escape(key)}\s*\}}\}}", str(value), result)
        result = re.sub(rf"\$matrix\.{re.escape(key)}\b", str(value), result)
        result = re.sub(rf"\${{\s*{re.escape(key)}\s*}}", str(value), result)
    return result


def _expand_matrix_job(job_name: str, job_model: JobModel, default_stage: str) -> List[JobDefinition]:
    """Expands a matrix job into individual JobDefinitions."""
    actual_stage = job_model.stage if job_model.stage != "default" else default_stage
    if not job_model.matrix:
        return [
            JobDefinition(
                name=job_name,
                original_name=job_name,
                stage=actual_stage,
                needs=list(job_model.needs),
                script=list(job_model.script),
                before_script=list(job_model.before_script),
                after_script=list(job_model.after_script),
                env=dict(job_model.env),
                matrix_vars={},
                timeout=job_model.timeout,
                retry=job_model.retry,
                allow_failure=job_model.allow_failure,
                when=job_model.when,
                working_dir=job_model.working_dir,
            )
        ]

    keys = list(job_model.matrix.keys())
    value_lists = [job_model.matrix[k] for k in keys]
    combinations = list(itertools.product(*value_lists))

    expanded_jobs: List[JobDefinition] = []
    for combo in combinations:
        matrix_dict = {keys[i]: str(combo[i]) for i in range(len(keys))}
        suffix = ",".join(f"{k}={v}" for k, v in matrix_dict.items())
        expanded_name = f"{job_name}[{suffix}]"

        rendered_script = [_substitute_matrix_vars(cmd, matrix_dict) for cmd in job_model.script]
        rendered_before = [_substitute_matrix_vars(cmd, matrix_dict) for cmd in job_model.before_script]
        rendered_after = [_substitute_matrix_vars(cmd, matrix_dict) for cmd in job_model.after_script]

        rendered_env = {}
        for k, v in job_model.env.items():
            rendered_env[k] = _substitute_matrix_vars(v, matrix_dict)
        for k, v in matrix_dict.items():
            rendered_env[f"MATRIX_{k.upper()}"] = v

        expanded_jobs.append(
            JobDefinition(
                name=expanded_name,
                original_name=job_name,
                stage=actual_stage,
                needs=list(job_model.needs),
                script=rendered_script,
                before_script=rendered_before,
                after_script=rendered_after,
                env=rendered_env,
                matrix_vars=matrix_dict,
                timeout=job_model.timeout,
                retry=job_model.retry,
                allow_failure=job_model.allow_failure,
                when=job_model.when,
                working_dir=job_model.working_dir,
            )
        )

    return expanded_jobs


def parse_pipeline_yaml(yaml_content: str) -> PipelineDefinition:
    """
    Parses pipeline YAML string using secure parser and validates with Pydantic v2.
    Enforces CWE-502 (yaml.safe_load) and CWE-400 (anti-DoS size limit).
    """
    if len(yaml_content.encode("utf-8")) > MAX_PIPELINE_FILE_SIZE:
        raise SecurityError(
            f"Pipeline content exceeds maximum allowed size of 1MB ({len(yaml_content.encode('utf-8'))} bytes > {MAX_PIPELINE_FILE_SIZE} bytes). CWE-400 prevention."
        )

    try:
        # CWE-502: Use yaml.safe_load exclusively
        raw_data = yaml.safe_load(yaml_content)
    except yaml.YAMLError as e:
        raise ParserError(f"Invalid YAML syntax: {e}") from e

    if not isinstance(raw_data, dict):
        raise ParserError("Pipeline YAML must contain a top-level mapping (dictionary)")

    try:
        pipeline_model = PipelineModel.model_validate(raw_data)
    except Exception as e:
        raise ParserError(f"Pipeline schema validation failed: {e}") from e

    default_stage = pipeline_model.stages[0] if pipeline_model.stages else "default"

    # Expand all jobs
    expanded_jobs_dict: Dict[str, JobDefinition] = {}
    original_to_expanded_map: Dict[str, List[str]] = {}

    for job_name, job_model in pipeline_model.jobs.items():
        expanded = _expand_matrix_job(job_name, job_model, default_stage)
        expanded_names = [j.name for j in expanded]
        original_to_expanded_map[job_name] = expanded_names
        for j in expanded:
            expanded_jobs_dict[j.name] = j

    # Resolve dependencies: if a job depends on an original name that was expanded into matrix jobs,
    # expand its 'needs' list to include all children
    for j in expanded_jobs_dict.values():
        resolved_needs: List[str] = []
        for dep in j.needs:
            if dep in original_to_expanded_map:
                resolved_needs.extend(original_to_expanded_map[dep])
            else:
                resolved_needs.append(dep)
        j.needs = resolved_needs

    # Stage-based implicit dependencies:
    # If stages are defined and a job has NO explicit needs, link to all jobs in the immediately preceding stage
    if pipeline_model.stages:
        stage_order = {stage: idx for idx, stage in enumerate(pipeline_model.stages)}
        stage_jobs: Dict[str, List[str]] = {s: [] for s in pipeline_model.stages}
        for j_name, j_def in expanded_jobs_dict.items():
            if j_def.stage in stage_jobs:
                stage_jobs[j_def.stage].append(j_name)

        for j_name, j_def in expanded_jobs_dict.items():
            if not j_def.needs and j_def.stage in stage_order:
                current_idx = stage_order[j_def.stage]
                if current_idx > 0:
                    prev_stage = pipeline_model.stages[current_idx - 1]
                    j_def.needs = list(stage_jobs.get(prev_stage, []))

    # Inherit global pipeline environment variables into jobs
    for j_def in expanded_jobs_dict.values():
        merged_env = dict(pipeline_model.env)
        merged_env.update(j_def.env)
        j_def.env = merged_env

    effective_stages = pipeline_model.stages if pipeline_model.stages else list({j.stage for j in expanded_jobs_dict.values()})

    return PipelineDefinition(
        name=pipeline_model.name,
        env=pipeline_model.env,
        secrets=pipeline_model.secrets,
        stages=effective_stages,
        concurrency=pipeline_model.concurrency,
        jobs=expanded_jobs_dict,
    )


def parse_pipeline_file(file_path: Union[str, Path]) -> PipelineDefinition:
    """
    Reads and parses a pipeline YAML file safely.
    Validates existence, file size limit (CWE-400), and syntax.
    """
    path = Path(file_path).resolve()
    if not path.is_file():
        raise FileNotFoundError(f"Pipeline file not found: {path}")

    file_size = os.path.getsize(path)
    if file_size > MAX_PIPELINE_FILE_SIZE:
        raise SecurityError(
            f"Pipeline file '{path.name}' exceeds maximum allowed size of 1MB ({file_size} bytes > {MAX_PIPELINE_FILE_SIZE} bytes). CWE-400 prevention."
        )

    content = path.read_text(encoding="utf-8")
    return parse_pipeline_yaml(content)
