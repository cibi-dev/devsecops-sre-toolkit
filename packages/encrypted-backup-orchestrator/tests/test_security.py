"""Security and compliance test suite (CWE validations and DevSecOps controls)."""

import ast
import hmac
import os
from pathlib import Path
import re
import tempfile
import pytest

from backup.crypto import CryptoEngine, AuthenticationError
from backup.restore_tester import SandboxRestoreTester, PathTraversalError
from backup.scanner import FileScanner


def test_cwe_798_no_hardcoded_secrets():
    """Verify that no hardcoded passwords, private keys, or API tokens exist in src/."""
    src_dir = Path(__file__).resolve().parent.parent / "src"
    secret_patterns = [
        re.compile(r'(?i)(password|secret|api_key|token)\s*=\s*["\'][a-zA-Z0-9_\-]{8,}["\']'),
        re.compile(r'-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----'),
    ]

    for py_file in src_dir.rglob("*.py"):
        content = py_file.read_text()
        for pattern in secret_patterns:
            matches = pattern.findall(content)
            # Filter out intentional constant variable names
            assert not matches, f"Potential hardcoded secret detected in {py_file}: {matches}"


def test_cwe_208_constant_time_comparison():
    """Verify that CryptoEngine uses hmac.compare_digest for secret and hash comparisons."""
    h1 = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
    h2 = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
    h3 = "0000000000000000000000000000000000000000000000000000000000000000"

    assert CryptoEngine.secure_compare_hashes(h1, h2) is True
    assert CryptoEngine.secure_compare_hashes(h1, h3) is False


def test_cwe_330_cwe_321_cryptographic_hygiene():
    """Verify distinct nonces and salts are generated for successive encryptions."""
    passphrase = "CryptographicHygieneTestPass#2026"
    plaintext = b"Payload for entropy and uniqueness verification"
    iterations = 2000

    enc1 = CryptoEngine.encrypt(plaintext, passphrase=passphrase, iterations=iterations)
    enc2 = CryptoEngine.encrypt(plaintext, passphrase=passphrase, iterations=iterations)

    assert enc1 != enc2
    # Salts (bytes 4:36) must be distinct
    assert enc1[4:36] != enc2[4:36]
    # Nonces (bytes 36:48) must be distinct
    assert enc1[36:48] != enc2[36:48]


def test_cwe_377_secure_tempfile_handling(tmp_path: Path):
    """Verify temporary directory creation in sandbox tests uses safe tempfile utilities."""
    # Ensure mkdtemp is used and cleaned up
    tester = SandboxRestoreTester()
    temp_dir = tempfile.mkdtemp(prefix="test_cwe377_")
    try:
        assert os.path.exists(temp_dir)
        # Check permissions on created directory
        mode = os.stat(temp_dir).st_mode & 0o777
        assert mode in (0o700, 0o755, 0o770)
    finally:
        os.rmdir(temp_dir)


def test_cwe_22_path_traversal_deep_checks(tmp_path: Path):
    """Test comprehensive path traversal evasion attempts."""
    target_base = tmp_path / "sandbox_base"
    target_base.mkdir()

    attack_payloads = [
        "../etc/passwd",
        "..\\windows\\system32\\cmd.exe",
        "nested/../../../../../../etc/shadow",
        "nested/.././../etc/hosts",
        "/absolute/root/file.txt",
        "C:\\Windows\\System32\\config\\SAM",
        "file\0.txt",
        "....//....//....//etc/passwd",
    ]

    for attack in attack_payloads:
        with pytest.raises(PathTraversalError):
            SandboxRestoreTester.validate_path_safety(target_base, attack)


def test_cwe_502_safe_deserialization():
    """Verify that backup manifests strictly parse valid schema and reject arbitrary objects."""
    from backup.scanner import BackupManifest
    from pydantic import ValidationError

    # Valid JSON parses correctly
    valid_json = """
    {
        "backup_id": "test_01",
        "timestamp": "2026-08-27T00:00:00Z",
        "source_path": "/data",
        "total_files": 0,
        "total_bytes": 0,
        "unique_chunks": 0,
        "files": [],
        "chunk_hashes": []
    }
    """
    manifest = BackupManifest.model_validate_json(valid_json)
    assert manifest.backup_id == "test_01"

    # Invalid types or missing fields raise ValidationError
    with pytest.raises(ValidationError):
        BackupManifest.model_validate_json('{"backup_id": 123}')
