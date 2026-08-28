"""DevSecOps & Security verification tests (CWE-250, CWE-269, CWE-78, CWE-22, CWE-209)."""

import ast
import os
import pytest
from unittest.mock import patch

from cis.backup_manager import BackupManager
from cis.remediator import CISRemediator
from cis.rules.base import (
    AuditResult,
    RemediationResult,
    RollbackResult,
    resolve_target_path,
    safe_read_file,
)
from cis.scanner import CISScanner


def test_cwe_250_scanner_privilege_warning(capsys):
    """CWE-250: Read-only scanner alerts when executed with root privileges unnecessarily."""
    with patch("os.geteuid", return_value=0):
        _ = CISScanner(root_prefix="", suppress_root_warning=False)
        captured = capsys.readouterr()
        assert "SECURITY WARNING (CWE-250)" in captured.err


def test_cwe_269_remediator_requires_root():
    """CWE-269: Mutating remediator strictly enforces root privileges on live hosts."""
    with patch("os.geteuid", return_value=1000):
        with pytest.raises(PermissionError, match="CIS Remediation requires root privileges"):
            CISRemediator(enforce_root=True, root_prefix="")


def test_cwe_78_no_shell_true_in_codebase():
    """CWE-78: Verify that no subprocess call uses shell=True anywhere in src/."""
    src_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "../src"))

    for root, _, files in os.walk(src_dir):
        for file in files:
            if file.endswith(".py"):
                path = os.path.join(root, file)
                with open(path, "r", encoding="utf-8") as f:
                    tree = ast.parse(f.read(), filename=path)

                for node in ast.walk(tree):
                    if isinstance(node, ast.Call):
                        # Check keyword arguments for shell=True
                        for kw in node.keywords:
                            if kw.arg == "shell":
                                if isinstance(kw.value, ast.Constant) and kw.value.value is True:
                                    pytest.fail(f"Vulnerability CWE-78 detected: shell=True in {path}:{node.lineno}")


def test_cwe_22_path_traversal_defense(tmp_path):
    """CWE-22: Commonpath validation rejects directory traversal escapes."""
    sandbox = str(tmp_path / "sandbox")
    os.makedirs(sandbox)

    with pytest.raises(ValueError, match="Path traversal detected"):
        resolve_target_path(sandbox, "../../../etc/shadow")

    with pytest.raises(ValueError, match="Path traversal detected"):
        resolve_target_path(sandbox, "/etc/passwd/../../../../root/.ssh/id_rsa")

    # Backup manager path traversal defense
    bm = BackupManager(root_prefix=sandbox)
    with pytest.raises(ValueError, match="Path traversal detected"):
        bm.backup_file(os.path.join(sandbox, "../../etc/shadow"))


def test_cwe_400_file_size_quota(tmp_path):
    """CWE-400: Large file reading is rejected to prevent memory exhaustion DoS."""
    large_file = tmp_path / "huge.txt"
    large_file.write_text("A" * 100)

    # Safe read with tiny limit triggers size limit
    with pytest.raises(ValueError, match="exceeds size limit"):
        safe_read_file(str(large_file), max_bytes=50)


def test_cwe_502_pydantic_extra_forbid():
    """CWE-502: Strict model validation rejects unapproved injected fields."""
    with pytest.raises(Exception):
        AuditResult(
            rule_id="TEST-01",
            name="Test",
            section="Sec",
            status="PASSED",
            severity="LOW",
            details="OK",
            injected_field="malicious_payload",  # Should fail extra='forbid'
        )
