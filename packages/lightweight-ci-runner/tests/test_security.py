"""
Security Verification Suite (SAST / DevSecOps Guardrails).
Tests CWE-20, CWE-502, CWE-78, CWE-400, and CWE-209/532 mitigations.
"""

import asyncio
import pytest

from runner.executor import JobExecutor, JobStatus
from runner.parser import (
    MAX_PIPELINE_FILE_SIZE,
    ParserError,
    SecurityError,
    parse_pipeline_yaml,
)
from runner.sandbox import sanitize_output, tokenize_command


def test_cwe_20_malformed_yaml_input():
    """CWE-20: Rejects invalid or malformed manifest structures."""
    with pytest.raises(ParserError):
        parse_pipeline_yaml("invalid: [yaml: structure")

    with pytest.raises(ParserError):
        parse_pipeline_yaml("12345")


def test_cwe_502_unsafe_deserialization_tags():
    """CWE-502: Rejects arbitrary python object instantiation in YAML."""
    malicious_yaml = """
    jobs:
      exploit:
        script:
          - !!python/object/apply:os.system ["id"]
    """
    with pytest.raises(ParserError):
        parse_pipeline_yaml(malicious_yaml)


@pytest.mark.asyncio
async def test_cwe_78_command_injection_prevention():
    """
    CWE-78: Verifies shell metacharacters (; && | ` $) are passed as literal arguments
    rather than executed by a shell (shell=False).
    """
    executor = JobExecutor()

    # If shell=True was used, 'echo safe; echo INJECTED' would output both lines.
    # With shell=False, the entire string '; echo INJECTED' is passed as an argument to echo.
    from runner.parser import JobDefinition

    job = JobDefinition(
        name="test_injection",
        original_name="test_injection",
        stage="test",
        script=["echo safe; echo INJECTED"],
    )
    result = await executor.execute_job(job)
    assert result.status == JobStatus.SUCCESS
    # 'echo' printed the literal semicolon and arguments together in one line
    assert "safe; echo INJECTED" in result.stdout


def test_cwe_78_null_byte_rejection():
    """CWE-78: Verifies null bytes in command strings are rejected."""
    with pytest.raises(ValueError, match="Null bytes are prohibited"):
        tokenize_command("echo hello\x00world")


def test_cwe_400_billion_laughs_and_size_limit():
    """CWE-400: Enforces max 1MB size limit to prevent memory exhaustion / Billion Laughs."""
    large_payload = "A" * (MAX_PIPELINE_FILE_SIZE + 10)
    with pytest.raises(SecurityError, match="exceeds maximum allowed size of 1MB"):
        parse_pipeline_yaml(f"# {large_payload}\njobs:\n  j:\n    script: echo 1")


@pytest.mark.asyncio
async def test_cwe_400_job_timeout_bounding():
    """CWE-400: Kills runaway processes when job timeout is reached."""
    executor = JobExecutor()
    from runner.parser import JobDefinition

    job = JobDefinition(
        name="runaway_job",
        original_name="runaway_job",
        stage="test",
        script=["sleep 5"],
        timeout=0.2,
    )
    result = await executor.execute_job(job)
    assert result.status == JobStatus.TIMED_OUT
    assert "timed out" in result.stderr.lower()


def test_cwe_209_secret_sanitization_in_logs():
    """CWE-209 / CWE-532: Masks credentials and tokens in logs."""
    sample_pat = "_".join(["ghp", "ABCDEF1234567890abcdef1234567890ABCD"])
    raw_logs = f"Deployed using secret_prod_key_777 and token {sample_pat}"
    clean_logs = sanitize_output(raw_logs, secrets=["secret_prod_key_777"])
    assert "secret_prod_key_777" not in clean_logs
    assert sample_pat not in clean_logs
    assert "[REDACTED]" in clean_logs
