"""
Automated Disaster Recovery (DR) Sandbox Restore and Verification Engine.
"""

from __future__ import annotations

import atexit
import hashlib
import hmac
import os
from pathlib import Path
import re
import shutil
import tempfile
import time
from typing import List, Optional

from pydantic import BaseModel, Field

from backup.compress import Compressor
from backup.crypto import CryptoEngine
from backup.scanner import BackupManifest, FileEntry


class PathTraversalError(Exception):
    """Raised when an entry path attempts directory traversal outside target sandbox (CWE-22)."""


class IntegrityVerificationError(Exception):
    """Raised when restored file SHA-256 checksum does not match manifest (CWE-208)."""


class RestoreError(Exception):
    """Raised when restoration encounters an unexpected failure."""


class FileVerificationStatus(BaseModel):
    """Integrity verification outcome for a single restored file."""

    rel_path: str
    expected_sha256: str
    restored_sha256: str
    expected_size: int
    restored_size: int
    passed: bool
    error: Optional[str] = None


class RestoreTestResult(BaseModel):
    """Aggregate result of an automated sandbox restore test."""

    backup_id: str
    success: bool
    total_files: int
    files_passed: int
    files_failed: int
    verification_rate: float = Field(description="Percentage of verified files (0.0 to 100.0)")
    sandbox_dir: Optional[str] = None
    duration_seconds: float
    file_statuses: List[FileVerificationStatus]
    errors: List[str]


class SandboxRestoreTester:
    """Orchestrates sandbox restore testing with strict cryptographic and path validation."""

    def __init__(
        self,
        compressor: Optional[Compressor] = None,
        crypto: Optional[CryptoEngine] = None,
    ) -> None:
        self.compressor = compressor or Compressor()
        self.crypto = crypto or CryptoEngine()

    @staticmethod
    def validate_path_safety(target_dir: str | Path, rel_path: str) -> Path:
        """
        Validate that rel_path stays strictly within target_dir (CWE-22 defense).

        Args:
            target_dir: Base target directory.
            rel_path: Relative path specified in manifest.

        Returns:
            Resolved safe destination Path.

        Raises:
            PathTraversalError: If path contains traversal sequences or escapes root.
        """
        if not rel_path or not isinstance(rel_path, str):
            raise PathTraversalError("Invalid or empty relative path")

        # Reject null bytes
        if "\0" in rel_path:
            raise PathTraversalError("Null byte detected in path")

        # Reject leading slashes, drive letters, or absolute paths
        if rel_path.startswith("/") or rel_path.startswith("\\") or os.path.isabs(rel_path):
            raise PathTraversalError(f"Absolute path not permitted: {rel_path}")

        if re.match(r"^[a-zA-Z]:", rel_path):
            raise PathTraversalError(f"Drive letter path not permitted: {rel_path}")

        # Check for traversal sequences
        path_obj = Path(rel_path)
        if ".." in path_obj.parts or ".." in rel_path:
            raise PathTraversalError(f"Path traversal sequence detected: {rel_path}")

        # Normalize target directory to absolute real path
        target_abs = os.path.realpath(os.path.abspath(str(target_dir)))

        # Compute full destination path and resolve symlinks
        dest_raw = os.path.join(target_abs, rel_path)
        dest_real = os.path.realpath(os.path.abspath(dest_raw))

        try:
            common = os.path.commonpath([target_abs, dest_real])
        except ValueError as exc:
            raise PathTraversalError(f"Cross-drive or invalid path: {rel_path}") from exc

        if common != target_abs:
            raise PathTraversalError(
                f"Path traversal detected: {rel_path} escapes target directory {target_abs}"
            )

        return Path(dest_real)

    def restore_file(
        self,
        file_entry: FileEntry,
        chunks_dir: str | Path,
        destination_path: Path,
        passphrase: Optional[str | bytes] = None,
        is_encrypted: bool = True,
        compression_algo: str = "zstd",
        kdf_iterations: int = 600000,
    ) -> FileVerificationStatus:
        """
        Reconstruct a single file from chunk store and verify SHA-256 hash.

        Args:
            file_entry: FileEntry metadata from manifest.
            chunks_dir: Path to repository chunks directory.
            destination_path: Validated safe destination file path.
            passphrase: Password for decryption if encrypted.
            is_encrypted: Whether chunks are AES-256-GCM encrypted.
            compression_algo: Compression algorithm used on chunks.
            kdf_iterations: PBKDF2 iteration count.

        Returns:
            FileVerificationStatus.
        """
        chunks_path = Path(chunks_dir)
        destination_path.parent.mkdir(parents=True, exist_ok=True)

        if file_entry.size == 0 and not file_entry.blocks:
            # 0-byte file creation
            destination_path.touch(exist_ok=True)
            empty_hash = hashlib.sha256(b"").hexdigest()
            passed = hmac.compare_digest(empty_hash, file_entry.sha256)
            return FileVerificationStatus(
                rel_path=file_entry.rel_path,
                expected_sha256=file_entry.sha256,
                restored_sha256=empty_hash,
                expected_size=0,
                restored_size=0,
                passed=passed,
            )

        file_hasher = hashlib.sha256()
        total_written = 0

        try:
            with open(destination_path, "wb") as out_f:
                for block in file_entry.blocks:
                    # Chunks are stored either partitioned (ab/abcdef...) or flat (abcdef...)
                    chunk_file = chunks_path / block.chunk_hash[:2] / block.chunk_hash
                    if not chunk_file.exists():
                        chunk_file = chunks_path / block.chunk_hash

                    if not chunk_file.exists():
                        raise FileNotFoundError(f"Missing chunk file: {block.chunk_hash}")

                    with open(chunk_file, "rb") as c_f:
                        raw_chunk = c_f.read()

                    # Step 1: Decrypt if encrypted
                    if is_encrypted:
                        if not passphrase:
                            raise ValueError("Passphrase required for encrypted backup")
                        chunk_data = self.crypto.decrypt(
                            raw_chunk,
                            passphrase=passphrase,
                            iterations=kdf_iterations,
                        )
                    else:
                        chunk_data = raw_chunk

                    # Step 2: Decompress
                    chunk_data = self.compressor.decompress(
                        chunk_data,
                        algorithm=compression_algo,
                    )

                    # Step 3: Write and update hash
                    out_f.write(chunk_data)
                    file_hasher.update(chunk_data)
                    total_written += len(chunk_data)

            restored_sha256 = file_hasher.hexdigest()
            passed = (
                hmac.compare_digest(restored_sha256, file_entry.sha256)
                and total_written == file_entry.size
            )

            error_msg = None if passed else (
                f"Hash mismatch: expected {file_entry.sha256}, got {restored_sha256}"
                if not hmac.compare_digest(restored_sha256, file_entry.sha256)
                else f"Size mismatch: expected {file_entry.size}, got {total_written}"
            )

            return FileVerificationStatus(
                rel_path=file_entry.rel_path,
                expected_sha256=file_entry.sha256,
                restored_sha256=restored_sha256,
                expected_size=file_entry.size,
                restored_size=total_written,
                passed=passed,
                error=error_msg,
            )
        except Exception as exc:
            return FileVerificationStatus(
                rel_path=file_entry.rel_path,
                expected_sha256=file_entry.sha256,
                restored_sha256="",
                expected_size=file_entry.size,
                restored_size=total_written,
                passed=False,
                error=str(exc),
            )

    def restore_manifest(
        self,
        manifest: BackupManifest,
        repo_dir: str | Path,
        target_dir: str | Path,
        passphrase: Optional[str | bytes] = None,
    ) -> List[FileVerificationStatus]:
        """
        Restore all files from manifest into target_dir with path validation.

        Args:
            manifest: Backup manifest.
            repo_dir: Repository root.
            target_dir: Destination directory.
            passphrase: Password for decryption.

        Returns:
            List of FileVerificationStatus for each file.
        """
        repo_path = Path(repo_dir).resolve()
        chunks_dir = repo_path / "chunks"
        statuses: List[FileVerificationStatus] = []

        for file_entry in manifest.files:
            dest_path = self.validate_path_safety(target_dir, file_entry.rel_path)
            status = self.restore_file(
                file_entry=file_entry,
                chunks_dir=chunks_dir,
                destination_path=dest_path,
                passphrase=passphrase,
                is_encrypted=manifest.is_encrypted,
                compression_algo=manifest.compression_algorithm,
                kdf_iterations=manifest.kdf_iterations,
            )
            statuses.append(status)

        return statuses

    def run_sandbox_test(
        self,
        manifest: BackupManifest,
        repo_dir: str | Path,
        passphrase: Optional[str | bytes] = None,
    ) -> RestoreTestResult:
        """
        Execute an automated disaster recovery test in an isolated temporary sandbox (CWE-377).

        Args:
            manifest: Backup manifest.
            repo_dir: Repository root.
            passphrase: Password for decryption.

        Returns:
            RestoreTestResult with 100% hash verification metrics.
        """
        start_time = time.perf_counter()
        sandbox_dir = tempfile.mkdtemp(prefix="dr_sandbox_")

        def _cleanup():
            if os.path.exists(sandbox_dir):
                shutil.rmtree(sandbox_dir, ignore_errors=True)

        atexit.register(_cleanup)

        try:
            statuses = self.restore_manifest(
                manifest=manifest,
                repo_dir=repo_dir,
                target_dir=sandbox_dir,
                passphrase=passphrase,
            )

            total_files = len(statuses)
            files_passed = sum(1 for s in statuses if s.passed)
            files_failed = total_files - files_passed
            verification_rate = (
                round((files_passed / total_files) * 100.0, 2)
                if total_files > 0
                else 100.0
            )

            errors: List[str] = [
                f"{s.rel_path}: {s.error}" for s in statuses if not s.passed and s.error
            ]
            success = (files_failed == 0)

            duration = round(time.perf_counter() - start_time, 4)

            return RestoreTestResult(
                backup_id=manifest.backup_id,
                success=success,
                total_files=total_files,
                files_passed=files_passed,
                files_failed=files_failed,
                verification_rate=verification_rate,
                sandbox_dir=sandbox_dir,
                duration_seconds=duration,
                file_statuses=statuses,
                errors=errors,
            )
        finally:
            _cleanup()
            try:
                atexit.unregister(_cleanup)
            except Exception:
                pass
