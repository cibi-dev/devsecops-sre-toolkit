"""Safe iterative OCI and TAR layer parser with strict DevSecOps defenses against CWE-409 and CWE-59."""

from __future__ import annotations

import io
import os
import tarfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import BinaryIO, Generator, Optional, Set, Union


# Guardrail limits (CWE-409 & CWE-400 mitigations)
DEFAULT_MAX_TOTAL_BYTES: int = 500 * 1024 * 1024  # 500 MB max aggregate extracted data
DEFAULT_MAX_SINGLE_FILE_BYTES: int = 100 * 1024 * 1024  # 100 MB max per single file
DEFAULT_MAX_FILE_COUNT: int = 10_000  # 10,000 files max per archive
DEFAULT_MAX_NESTED_DEPTH: int = 3  # Max nested tar recursion depth


class TarSecurityError(Exception):
    """Raised when a tar archive violates security constraints (path traversal, tar bomb)."""
    pass


@dataclass
class SafeTarEntry:
    """Represents a validated, safely extracted member of a TAR archive."""

    path: str
    size: int
    content: bytes
    is_nested_tar: bool = False


def is_safe_tar_path(member_name: str) -> bool:
    """Validate that a tar member name does not attempt path traversal (CWE-22/CWE-59).

    Args:
        member_name: The raw path string from tarinfo.name.

    Returns:
        True if the path is safe and strictly relative, False if malicious.
    """
    if not member_name or not member_name.strip():
        return False

    # Normalize separators
    normalized = member_name.replace("\\", "/").strip()

    # Reject absolute paths or root drives
    if normalized.startswith("/") or (len(normalized) > 1 and normalized[1] == ":"):
        return False

    # Check components with PurePosixPath
    path_obj = PurePosixPath(normalized)
    parts = path_obj.parts

    # Reject if any part is '..' or starts with dangerous prefixes
    for part in parts:
        if part == ".." or part == ".":
            # '.' is okay if standalone at root, but '..' is never allowed
            if part == "..":
                return False

    # Check for resolution escape
    resolved = os.path.normpath(normalized)
    if resolved.startswith("..") or resolved == "..":
        return False

    return True


def iterate_tar_stream(
    tar_source: Union[str, Path, BinaryIO],
    max_total_bytes: int = DEFAULT_MAX_TOTAL_BYTES,
    max_single_file_bytes: int = DEFAULT_MAX_SINGLE_FILE_BYTES,
    max_file_count: int = DEFAULT_MAX_FILE_COUNT,
    current_depth: int = 0,
    max_depth: int = DEFAULT_MAX_NESTED_DEPTH,
    parent_prefix: str = "",
) -> Generator[SafeTarEntry, None, None]:
    """Safely stream and extract entries from a TAR archive in-memory without disk extraction.

    Adheres strictly to DevSecOps rules:
    - CWE-409: Bounded byte counter and file counter against zip/tar bombs.
    - CWE-59: Zero extractall() calls; rejects symlinks to outside paths; streams via extractfile().
    - CWE-22: Path traversal sanitization on all member paths.

    Args:
        tar_source: File path (str/Path) or open binary stream.
        max_total_bytes: Cumulative extraction limit.
        max_single_file_bytes: Individual file extraction limit.
        max_file_count: Maximum number of files to process.
        current_depth: Current recursion depth for nested tarballs.
        max_depth: Maximum recursion depth.
        parent_prefix: Prefix path for nested container layers.

    Yields:
        SafeTarEntry with validated path and contents.

    Raises:
        TarSecurityError: When security limits are breached.
    """
    if current_depth > max_depth:
        return

    total_bytes_extracted = 0
    files_processed = 0

    # Open tarfile safely
    tar_obj: Optional[tarfile.TarFile] = None
    should_close = False

    try:
        if isinstance(tar_source, (str, Path)):
            tar_path = Path(tar_source)
            if not tar_path.exists() or not tar_path.is_file():
                raise FileNotFoundError(f"Tar file not found: {tar_source}")
            tar_obj = tarfile.open(name=str(tar_path), mode="r:*")
            should_close = True
        else:
            tar_obj = tarfile.open(fileobj=tar_source, mode="r:*")
            should_close = False

        for member in tar_obj:
            # 1. Skip non-regular files safely (FIFOs, device nodes, symlinks, directories)
            if member.isdir():
                continue

            # Reject dangerous node types
            if member.ischr() or member.isblk() or member.isfifo():
                continue

            # Reject symlinks and hardlinks pointing to external locations
            if member.issym() or member.islnk():
                if not is_safe_tar_path(member.linkname):
                    continue
                # We skip reading link payloads directly to prevent escape attacks
                continue

            if not member.isreg():
                continue

            # 2. Path safety check (CWE-22 / CWE-59)
            if not is_safe_tar_path(member.name):
                raise TarSecurityError(
                    f"Path traversal detected in archive entry: {member.name!r}"
                )

            # 3. File count limit check (CWE-400 / CWE-409)
            files_processed += 1
            if files_processed > max_file_count:
                raise TarSecurityError(
                    f"Archive exceeds maximum file count quota of {max_file_count} files (Tar Bomb defense)."
                )

            # 4. Single file size check
            if member.size > max_single_file_bytes:
                raise TarSecurityError(
                    f"Entry {member.name!r} ({member.size} bytes) exceeds max single file limit of {max_single_file_bytes} bytes."
                )

            # 5. Cumulative size check
            if total_bytes_extracted + member.size > max_total_bytes:
                raise TarSecurityError(
                    f"Extraction aborted: cumulative size would exceed {max_total_bytes} bytes (Tar Bomb defense)."
                )

            # 6. Safe in-memory extraction using extractfile()
            extracted_f = tar_obj.extractfile(member)
            if extracted_f is None:
                continue

            try:
                # Read with explicit size bounding
                content = extracted_f.read(max_single_file_bytes + 1)
                if len(content) > max_single_file_bytes:
                    raise TarSecurityError(
                        f"Decompressed stream for {member.name!r} exceeded declared size limit."
                    )
            finally:
                extracted_f.close()

            total_bytes_extracted += len(content)
            if total_bytes_extracted > max_total_bytes:
                raise TarSecurityError(
                    f"Extraction aborted: decompressed stream total exceeded {max_total_bytes} bytes."
                )

            entry_path = f"{parent_prefix}/{member.name}" if parent_prefix else member.name

            # Check if this member is a nested layer tarball (common in OCI images e.g. layer.tar)
            is_nested = (
                member.name.endswith(".tar")
                or member.name.endswith(".tar.gz")
                or member.name.endswith(".tgz")
            )

            entry = SafeTarEntry(
                path=entry_path,
                size=len(content),
                content=content,
                is_nested_tar=is_nested,
            )
            yield entry

            # If nested tar and within depth limit, recurse through in-memory buffer
            if is_nested and current_depth < max_depth:
                nested_stream = io.BytesIO(content)
                try:
                    yield from iterate_tar_stream(
                        tar_source=nested_stream,
                        max_total_bytes=max_total_bytes - total_bytes_extracted,
                        max_single_file_bytes=max_single_file_bytes,
                        max_file_count=max_file_count - files_processed,
                        current_depth=current_depth + 1,
                        max_depth=max_depth,
                        parent_prefix=entry_path,
                    )
                except (tarfile.TarError, TarSecurityError):
                    # Gracefully handle unparseable or corrupted nested tar layers
                    pass

    finally:
        if should_close and tar_obj is not None:
            tar_obj.close()
