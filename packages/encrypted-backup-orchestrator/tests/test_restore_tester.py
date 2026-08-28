"""Tests for SandboxRestoreTester and end-to-end disaster recovery verification."""

import hashlib
import os
from pathlib import Path
import pytest

from backup.compress import Compressor, CompressionAlgorithm
from backup.crypto import CryptoEngine
from backup.restore_tester import (
    SandboxRestoreTester,
    PathTraversalError,
    FileVerificationStatus,
)
from backup.scanner import FileScanner, BackupManifest, BlockInfo, FileEntry


def test_path_traversal_defense(tmp_path: Path):
    """Test CWE-22 path traversal defense mechanisms."""
    target_dir = tmp_path / "restore_target"
    target_dir.mkdir()

    # Valid safe relative path
    safe_path = SandboxRestoreTester.validate_path_safety(target_dir, "subdir/file.txt")
    assert str(safe_path).startswith(str(target_dir.resolve()))

    # Traversal attempts with ..
    with pytest.raises(PathTraversalError):
        SandboxRestoreTester.validate_path_safety(target_dir, "../../../etc/passwd")

    with pytest.raises(PathTraversalError):
        SandboxRestoreTester.validate_path_safety(target_dir, "subdir/../../escape.txt")

    # Absolute path attempts
    with pytest.raises(PathTraversalError):
        SandboxRestoreTester.validate_path_safety(target_dir, "/etc/shadow")

    # Null byte injection
    with pytest.raises(PathTraversalError):
        SandboxRestoreTester.validate_path_safety(target_dir, "file.txt\0.evil")

    # Empty or non-string path
    with pytest.raises(PathTraversalError):
        SandboxRestoreTester.validate_path_safety(target_dir, "")


def test_e2e_backup_restore_roundtrip(tmp_path: Path):
    """Test full cycle: scan -> compress -> encrypt -> store -> restore -> verify."""
    source_dir = tmp_path / "source"
    source_dir.mkdir()
    repo_dir = tmp_path / "repo"
    chunks_dir = repo_dir / "chunks"
    chunks_dir.mkdir(parents=True)
    target_dir = tmp_path / "restore_dest"

    # Populate source files
    (source_dir / "file1.txt").write_text("Disaster Recovery File One Content" * 20)
    (source_dir / "empty.txt").write_bytes(b"")
    sub = source_dir / "sub"
    sub.mkdir()
    (sub / "nested.bin").write_bytes(b"\x00\x01\x02\x03\xff\xfe" * 50)

    # 1. Scan
    scanner = FileScanner(source_dir, chunk_size=128)
    scan_result, chunk_pool = scanner.scan()

    passphrase = "SecureE2ETestPassword#123"
    iterations = 2000

    # 2. Compress and Encrypt Chunks into Repo
    for chunk_hash, chunk_data in chunk_pool.items():
        compressed, _ = Compressor.compress(chunk_data, algorithm=CompressionAlgorithm.ZSTD)
        encrypted = CryptoEngine.encrypt(compressed, passphrase=passphrase, iterations=iterations)

        sub_dir = chunks_dir / chunk_hash[:2]
        sub_dir.mkdir(exist_ok=True)
        (sub_dir / chunk_hash).write_bytes(encrypted)

    manifest = BackupManifest(
        backup_id="bkp_e2e_01",
        timestamp="2026-08-27T12:00:00Z",
        source_path=str(source_dir),
        total_files=scan_result.total_files,
        total_bytes=scan_result.total_bytes,
        unique_chunks=scan_result.unique_chunks_count,
        compression_algorithm="zstd",
        is_encrypted=True,
        kdf_iterations=iterations,
        files=scan_result.files,
        chunk_hashes=scan_result.chunk_hashes,
    )

    # 3. Restore to target directory
    tester = SandboxRestoreTester()
    statuses = tester.restore_manifest(manifest, repo_dir, target_dir, passphrase=passphrase)

    assert len(statuses) == 3
    assert all(s.passed for s in statuses)

    # Check restored file contents directly
    assert (target_dir / "file1.txt").read_text() == (source_dir / "file1.txt").read_text()
    assert (target_dir / "empty.txt").read_bytes() == b""
    assert (target_dir / "sub" / "nested.bin").read_bytes() == (sub / "nested.bin").read_bytes()


def test_sandbox_restore_lifecycle_cleanup(tmp_path: Path):
    """Test automated sandbox restore test and verify temporary directory is deleted."""
    source_dir = tmp_path / "source"
    source_dir.mkdir()
    repo_dir = tmp_path / "repo"
    chunks_dir = repo_dir / "chunks"
    chunks_dir.mkdir(parents=True)

    (source_dir / "doc.txt").write_text("Enterprise Documentation Sandbox Test")

    scanner = FileScanner(source_dir, chunk_size=512)
    scan_result, chunk_pool = scanner.scan()

    passphrase = "SandboxPassphrase2026"
    iterations = 2000

    for chunk_hash, chunk_data in chunk_pool.items():
        compressed, _ = Compressor.compress(chunk_data, algorithm=CompressionAlgorithm.ZSTD)
        encrypted = CryptoEngine.encrypt(compressed, passphrase=passphrase, iterations=iterations)
        (chunks_dir / chunk_hash).write_bytes(encrypted)

    manifest = BackupManifest(
        backup_id="bkp_sandbox_01",
        timestamp="2026-08-27T12:00:00Z",
        source_path=str(source_dir),
        total_files=scan_result.total_files,
        total_bytes=scan_result.total_bytes,
        unique_chunks=scan_result.unique_chunks_count,
        compression_algorithm="zstd",
        is_encrypted=True,
        kdf_iterations=iterations,
        files=scan_result.files,
        chunk_hashes=scan_result.chunk_hashes,
    )

    tester = SandboxRestoreTester()
    result = tester.run_sandbox_test(manifest, repo_dir, passphrase=passphrase)

    assert result.success is True
    assert result.files_passed == 1
    assert result.files_failed == 0
    assert result.verification_rate == 100.0
    assert result.duration_seconds >= 0.0

    # Ensure sandbox directory was deleted
    if result.sandbox_dir:
        assert not os.path.exists(result.sandbox_dir)


def test_restore_missing_chunk(tmp_path: Path):
    """Test error reporting when a chunk file is missing in repository."""
    repo_dir = tmp_path / "missing_repo"
    chunks_dir = repo_dir / "chunks"
    chunks_dir.mkdir(parents=True)

    file_entry = FileEntry(
        rel_path="missing_chunk.txt",
        size=100,
        mtime=0.0,
        sha256="abc123",
        blocks=[
            BlockInfo(
                chunk_hash="deadbeef12345678",
                offset=0,
                size=100,
                chunk_index=0,
            )
        ],
    )

    tester = SandboxRestoreTester()
    status = tester.restore_file(
        file_entry=file_entry,
        chunks_dir=chunks_dir,
        destination_path=tmp_path / "out.txt",
        is_encrypted=False,
    )
    assert status.passed is False
    assert "Missing chunk file" in (status.error or "")


def test_restore_encrypted_without_passphrase(tmp_path: Path):
    """Test that restoring encrypted backup without passphrase fails gracefully."""
    repo_dir = tmp_path / "enc_repo"
    chunks_dir = repo_dir / "chunks"
    chunks_dir.mkdir(parents=True)

    chunk_hash = "1122334455667788"
    (chunks_dir / chunk_hash).write_bytes(b"some_encrypted_content")

    file_entry = FileEntry(
        rel_path="secret.txt",
        size=20,
        mtime=0.0,
        sha256="hash123",
        blocks=[
            BlockInfo(
                chunk_hash=chunk_hash,
                offset=0,
                size=20,
                chunk_index=0,
            )
        ],
    )

    tester = SandboxRestoreTester()
    status = tester.restore_file(
        file_entry=file_entry,
        chunks_dir=chunks_dir,
        destination_path=tmp_path / "out.txt",
        is_encrypted=True,
        passphrase=None,
    )
    assert status.passed is False
    assert "Passphrase required" in (status.error or "")


def test_restore_tampered_chunk_fails(tmp_path: Path):
    """Test that tampering with stored chunk fails sandbox verification."""
    source_dir = tmp_path / "source"
    source_dir.mkdir()
    repo_dir = tmp_path / "repo"
    chunks_dir = repo_dir / "chunks"
    chunks_dir.mkdir(parents=True)

    (source_dir / "critical.db").write_bytes(b"CRITICAL_DATABASE_PAYLOAD_ABCDEF" * 10)

    scanner = FileScanner(source_dir, chunk_size=512)
    scan_result, chunk_pool = scanner.scan()

    passphrase = "TamperDetectionTest"
    iterations = 2000

    for chunk_hash, chunk_data in chunk_pool.items():
        compressed, _ = Compressor.compress(chunk_data, algorithm=CompressionAlgorithm.ZSTD)
        encrypted = CryptoEngine.encrypt(compressed, passphrase=passphrase, iterations=iterations)
        # Corrupt the payload written to disk
        corrupted = bytearray(encrypted)
        corrupted[-5] ^= 0xFF
        (chunks_dir / chunk_hash).write_bytes(bytes(corrupted))

    manifest = BackupManifest(
        backup_id="bkp_corrupt_test",
        timestamp="2026-08-27T12:00:00Z",
        source_path=str(source_dir),
        total_files=scan_result.total_files,
        total_bytes=scan_result.total_bytes,
        unique_chunks=scan_result.unique_chunks_count,
        compression_algorithm="zstd",
        is_encrypted=True,
        kdf_iterations=iterations,
        files=scan_result.files,
        chunk_hashes=scan_result.chunk_hashes,
    )

    tester = SandboxRestoreTester()
    result = tester.run_sandbox_test(manifest, repo_dir, passphrase=passphrase)

    assert result.success is False
    assert result.files_failed == 1
    assert len(result.errors) > 0
