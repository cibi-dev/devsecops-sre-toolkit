"""Read-only inspector for file attributes, permissions, ownership, and hashes (CWE-250, CWE-400)."""

from __future__ import annotations

import grp
import hashlib
import os
from pathlib import Path
import pwd
import stat
from typing import NamedTuple

# Max file size to compute hash (50MB) to prevent memory/CPU exhaustion (CWE-400)
MAX_HASH_FILE_BYTES = 50 * 1024 * 1024
HASH_CHUNK_SIZE = 64 * 1024


class FileLiveState(NamedTuple):
    """Live state of a file on the host filesystem."""

    path: str
    exists: bool
    mode: str | None  # 4-digit octal e.g. '0644'
    owner: str | None
    group: str | None
    size: int | None
    sha256: str | None
    error: str | None = None


class FileInspector:
    """Read-only inspector for filesystem metadata and cryptographic checksums."""

    def __init__(self, max_hash_bytes: int = MAX_HASH_FILE_BYTES) -> None:
        self.max_hash_bytes = max_hash_bytes

    def inspect_file(self, target_path: str | Path, compute_sha256: bool = True) -> FileLiveState:
        """Inspect attributes and checksum of a target file.

        Args:
            target_path: Absolute path to inspect.
            compute_sha256: Whether to compute SHA-256 hash.

        Returns:
            FileLiveState with live file attributes.
        """
        p = Path(target_path)
        path_str = str(p)

        try:
            if not p.exists() and not p.is_symlink():
                return FileLiveState(
                    path=path_str,
                    exists=False,
                    mode=None,
                    owner=None,
                    group=None,
                    size=None,
                    sha256=None,
                )
            st = p.stat()
        except (OSError, PermissionError) as exc:
            return FileLiveState(
                path=path_str,
                exists=True,
                mode=None,
                owner=None,
                group=None,
                size=None,
                sha256=None,
                error=f"Permission or I/O error reading stats: {exc}",
            )

        # Extract 4-digit octal mode (e.g. '0644')
        mode_octal = oct(stat.S_IMODE(st.st_mode))[2:].zfill(4)

        # Resolve owner
        try:
            owner_name = pwd.getpwuid(st.st_uid).pw_name
        except (KeyError, Exception):
            owner_name = str(st.st_uid)

        # Resolve group
        try:
            group_name = grp.getgrgid(st.st_gid).gr_name
        except (KeyError, Exception):
            group_name = str(st.st_gid)

        # Compute SHA-256 if requested and file is regular file
        file_sha256: str | None = None
        if compute_sha256 and stat.S_ISREG(st.st_mode):
            if st.st_size <= self.max_hash_bytes:
                try:
                    hasher = hashlib.sha256()
                    with open(p, "rb") as f:
                        while chunk := f.read(HASH_CHUNK_SIZE):
                            hasher.update(chunk)
                    file_sha256 = hasher.hexdigest()
                except (OSError, PermissionError) as exc:
                    file_sha256 = None
            else:
                # File exceeds max hash size
                file_sha256 = "EXCEEDS_MAX_HASH_SIZE"

        return FileLiveState(
            path=path_str,
            exists=True,
            mode=mode_octal,
            owner=owner_name,
            group=group_name,
            size=st.st_size,
            sha256=file_sha256,
        )
