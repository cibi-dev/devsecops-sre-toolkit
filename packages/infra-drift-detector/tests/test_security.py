"""Dedicated DevSecOps and CWE controls security test suite."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import pytest
from pydantic import ValidationError

from drift.comparator import DriftComparator
from drift.inspectors.files import FileInspector
from drift.inspectors.packages import PackageInspector
from drift.inspectors.services import ServiceInspector
from drift.inspectors.sysctl import SysctlInspector
from drift.parser import FileSizeExceededError, ManifestParseError, parse_manifest, sanitize_secrets
from drift.schema import FileDesired, Manifest, ServiceDesired, SysctlDesired, UserDesired


def test_cwe_798_no_hardcoded_secrets_in_codebase():
    """Verify that source files do not contain obvious raw secret strings."""
    src_dir = Path(__file__).resolve().parent.parent / "src"
    suspicious_substrings = [
        "ghp_" + "realtoken_forbidden_test_val",
        "AKIA" + "IOSFODNN7EXAMPLE",
        "BEGIN" + " RSA PRIVATE KEY",
    ]
    for py_file in src_dir.rglob("*.py"):
        content = py_file.read_text(encoding="utf-8")
        for bad in suspicious_substrings:
            assert bad not in content, f"Found suspicious secret in {py_file}"


def test_cwe_250_269_strict_read_only_guarantee(tmp_path: Path):
    """Verify that full audit execution performs ZERO mutations on the filesystem."""
    # Create test filesystem fixture
    test_file = tmp_path / "protected_config.conf"
    test_file.write_text("secure_config_line = True\n", encoding="utf-8")
    test_file.chmod(0o640)

    # Record initial metadata
    initial_stat = test_file.stat()
    initial_hash = hashlib.sha256(test_file.read_bytes()).hexdigest()
    initial_dir_list = list(tmp_path.iterdir())

    # Build manifest targeting the file and live inspectors
    manifest = Manifest(
        name="read-only-audit-verification",
        files=[FileDesired(path=str(test_file), mode="0644", state="present")],
        users=[UserDesired(name="root")],
        services=[ServiceDesired(name="systemd-journald")],
        sysctl=[SysctlDesired(key="net.ipv4.ip_forward", value="1")],
    )

    comparator = DriftComparator()
    result = comparator.compare(manifest)

    # Re-verify that filesystem was untouched
    after_stat = test_file.stat()
    after_hash = hashlib.sha256(test_file.read_bytes()).hexdigest()
    after_dir_list = list(tmp_path.iterdir())

    assert initial_stat.st_mtime_ns == after_stat.st_mtime_ns, "File modification time altered!"
    assert initial_stat.st_mode == after_stat.st_mode, "File permissions altered!"
    assert initial_hash == after_hash, "File content altered!"
    assert initial_dir_list == after_dir_list, "Directory contents altered (files created/deleted)!"
    assert result.total_checked >= 4


def test_cwe_78_command_injection_prevention():
    """Verify that injection payloads in service and package inspectors are rejected safely."""
    bad_inputs = [
        "nginx; cat /etc/passwd",
        "app && rm -rf /",
        "$(reboot)",
        "service`id`",
        "foo|nc -l 8080",
    ]

    service_inspector = ServiceInspector()
    package_inspector = PackageInspector()

    for bad in bad_inputs:
        # Pydantic schema validation rejection
        with pytest.raises(ValidationError):
            ServiceDesired(name=bad)

        # Service inspector runtime defense
        svc_state = service_inspector.inspect_service(bad)
        assert svc_state.exists is False
        assert svc_state.active_state == "invalid"

        # Package inspector runtime defense
        pkg_state = package_inspector.inspect_package(bad)
        assert pkg_state.installed is False


def test_cwe_22_path_traversal_prevention(tmp_path: Path):
    """Verify that path traversal sequences are blocked in sysctl and file validation."""
    traversal_keys = [
        "../../etc/shadow",
        "net.ipv4/../../../etc/passwd",
        "/etc/shadow",
    ]

    sysctl_inspector = SysctlInspector(proc_sys_root=tmp_path)
    for bad_key in traversal_keys:
        assert sysctl_inspector.get_parameter_path(bad_key) is None
        state = sysctl_inspector.inspect_key(bad_key)
        assert state.exists is False

    with pytest.raises(ValidationError):
        FileDesired(path="/etc/../../shadow")


def test_cwe_400_manifest_size_limit_anti_dos(tmp_path: Path):
    """Verify that manifests exceeding 1MB limit are rejected to prevent DoS (CWE-400)."""
    large_manifest = tmp_path / "bomb.yaml"
    # Create file > 1MB (1,048,577 bytes)
    large_manifest.write_text("a" * (1024 * 1024 + 10), encoding="utf-8")

    with pytest.raises(FileSizeExceededError):
        parse_manifest(large_manifest)

    # Test raw string size limit
    large_str = "version: '1.0'\n" + "#" * (1024 * 1024 + 10)
    with pytest.raises(FileSizeExceededError):
        parse_manifest(large_str)


def test_cwe_502_safe_deserialization_blocks_code_execution():
    """Verify that PyYAML safe_load prevents arbitrary object deserialization (CWE-502)."""
    malicious_yaml = """
    name: test
    exploit: !!python/object/apply:os.system ["echo PWNED"]
    """
    with pytest.raises(ManifestParseError):
        parse_manifest(malicious_yaml)


def test_cwe_502_forbids_extra_unvalidated_fields():
    """Verify that extra unvalidated fields in manifest fail validation."""
    invalid_dict = """
    name: hardened
    version: '1.0'
    malicious_injected_block:
      payload: true
    """
    with pytest.raises(ManifestParseError):
        parse_manifest(invalid_dict)


def test_cwe_209_pii_and_token_redaction():
    """Verify that sensitive credential formats are redacted from all outputs."""
    raw = (
        "Found user token ghp_1234567890abcdefghijklmnopqrstuvwxyz "
        "and OpenAI key sk-abcdef123456789012345678 "
        "and AWS key AKIAIOSFODNN7EXAMPLE "
        "and password: 'SuperSecretPassword123!'"
    )
    sanitized = sanitize_secrets(raw)
    assert "ghp_1234567890abcdefghijklmnopqrstuvwxyz" not in sanitized
    assert "sk-abcdef123456789012345678" not in sanitized
    assert "AKIAIOSFODNN7EXAMPLE" not in sanitized
    assert "SuperSecretPassword123!" not in sanitized
    assert "[REDACTED" in sanitized
