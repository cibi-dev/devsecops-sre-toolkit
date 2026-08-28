"""Security and DevSecOps Guardrail Tests (CWE-400, CWE-20, CWE-502, CWE-209, CWE-22)."""

import os
import numpy as np
import pandas as pd
import pytest
from pydantic import ValidationError

from slo.cli import load_dataset, safe_resolve_path
from slo.error_budget import SLODefinition
from slo.reporter import redact_data_structures, redact_sensitive_text
from slo.sli_calculator import calculate_timeseries_sli


def test_cwe_400_memory_quota_enforcement():
    """Test that huge DataFrames exceeding memory limits raise ValueError (CWE-400)."""
    # Create a DataFrame with 100,000 rows
    df = pd.DataFrame({
        "timestamp": pd.date_range("2026-01-01", periods=100000, freq="s"),
        "good_events": np.ones(100000, dtype=np.int64) * 99,
        "total_events": np.ones(100000, dtype=np.int64) * 100,
    })

    # When quota is set lower than df size (e.g. 0.001 MB), it should be rejected
    with pytest.raises(ValueError, match="exceeds memory quota"):
        calculate_timeseries_sli(df, max_memory_mb=0.001)


def test_cwe_20_and_502_strict_schema_validation():
    """Test strict Pydantic v2 validation against malformed or injected definitions."""
    # Invalid target type or value
    with pytest.raises(ValidationError):
        SLODefinition(name="test", service="test", target="not_a_number")  # type: ignore

    # Out of range target
    with pytest.raises(ValidationError):
        SLODefinition(name="test", service="test", target=1.0001)

    with pytest.raises(ValidationError):
        SLODefinition(name="test", service="test", target=-0.001)

    # Extra malicious attributes forbidden (extra='forbid')
    with pytest.raises(ValidationError):
        SLODefinition(
            name="test",
            service="test",
            target=0.999,
            malicious_payload="__import__('os').system('id')",  # type: ignore
        )


def test_cwe_209_information_exposure_sanitization():
    """Test that sensitive credentials and tokens are systematically sanitized."""
    sensitive_log = "Error in auth service: bearer_token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.xyz and api_key='sk-prod-987654321'"
    redacted = redact_sensitive_text(sensitive_log)

    assert "sk-prod-987654321" not in redacted
    assert "[REDACTED]" in redacted

    complex_dict = {
        "user": "admin",
        "access_token": "secret_abc123",
        "api_secret": "my_secret_key",
        "nested": {
            "password": "p@ssword!",
            "normal_field": "public_data",
        },
    }
    redacted_dict = redact_data_structures(complex_dict)
    assert redacted_dict["access_token"] == "[REDACTED]"
    assert redacted_dict["api_secret"] == "[REDACTED]"
    assert redacted_dict["nested"]["password"] == "[REDACTED]"
    assert redacted_dict["nested"]["normal_field"] == "public_data"


def test_cwe_22_path_traversal_defense(tmp_path):
    """Test path traversal mitigation."""
    # Test valid temporary file
    temp_file = tmp_path / "valid.csv"
    temp_file.write_text("timestamp,good_events,total_events\n2026-08-27T00:00:00Z,99,100\n")

    resolved = safe_resolve_path(str(temp_file))
    assert os.path.exists(resolved)

    # Non-existent file in isolated tmp directory
    non_existent = tmp_path / "non_existent_file_xyz_12345.csv"
    with pytest.raises(FileNotFoundError):
        safe_resolve_path(str(non_existent))

    # Directory instead of file
    with pytest.raises(ValueError, match="not a regular file"):
        safe_resolve_path(str(tmp_path))
