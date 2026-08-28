"""
File scanner and block-level deduplication engine using SHA-256.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from pydantic import BaseModel, Field


class BlockInfo(BaseModel):
    """Metadata for an individual content block."""

    chunk_hash: str = Field(description="SHA-256 hex digest of block content")
    offset: int = Field(ge=0, description="Byte offset within the source file")
    size: int = Field(ge=0, description="Size of the block in bytes")
    chunk_index: int = Field(ge=0, description="Sequential index of block in file")


class FileEntry(BaseModel):
    """Metadata for a scanned file."""

    rel_path: str = Field(description="Normalized relative path from source root")
    size: int = Field(ge=0, description="Total file size in bytes")
    mtime: float = Field(description="Modification timestamp")
    sha256: str = Field(description="Full file SHA-256 digest")
    blocks: List[BlockInfo] = Field(default_factory=list, description="List of block references")


class ScanResult(BaseModel):
    """Aggregate statistics and metadata for a scan operation."""

    source_path: str
    total_files: int
    total_bytes: int
    unique_chunks_count: int
    unique_chunks_bytes: int
    deduplicated_bytes: int
    deduplication_ratio: float
    files: List[FileEntry]
    chunk_hashes: List[str]


class BackupManifest(BaseModel):
    """Complete backup manifest describing files, blocks, and encryption parameters."""

    backup_id: str
    timestamp: str
    backup_name: Optional[str] = None
    source_path: str
    total_files: int
    total_bytes: int
    unique_chunks: int
    compressed_bytes: int = 0
    compression_algorithm: str = "zstd"
    is_encrypted: bool = True
    kdf_iterations: int = 600000
    files: List[FileEntry]
    chunk_hashes: List[str]
    tier: Optional[str] = None
    previous_backup_id: Optional[str] = None


class FileScanner:
    """Scans directory trees, splits files into blocks, and deduplicates via SHA-256."""

    def __init__(self, source_dir: str | Path, chunk_size: int = 65536) -> None:
        """
        Initialize the file scanner.

        Args:
            source_dir: Directory to scan.
            chunk_size: Size of deduplication chunks in bytes (default: 64KB).
        """
        self.source_dir = Path(source_dir).resolve()
        if not self.source_dir.exists():
            raise FileNotFoundError(f"Source directory does not exist: {self.source_dir}")
        if not self.source_dir.is_dir():
            raise NotADirectoryError(f"Source path is not a directory: {self.source_dir}")

        if chunk_size <= 0:
            raise ValueError("chunk_size must be greater than 0")
        self.chunk_size = chunk_size

    def scan(
        self, previous_manifest: Optional[BackupManifest] = None
    ) -> Tuple[ScanResult, Dict[str, bytes]]:
        """
        Scan the source directory tree, compute block hashes, and collect unique chunks.

        Args:
            previous_manifest: Optional previous manifest for incremental delta tracking.

        Returns:
            Tuple of (ScanResult summary, dict of {chunk_hash: chunk_data}).
        """
        files: List[FileEntry] = []
        chunk_pool: Dict[str, bytes] = {}
        chunk_hashes_set: set[str] = set()

        total_bytes = 0
        total_files = 0

        # Collect and sort all regular file paths deterministically
        file_paths: List[Path] = []
        for root, dirs, filenames in os.walk(self.source_dir, followlinks=False):
            dirs.sort()
            for filename in sorted(filenames):
                full_path = Path(root) / filename
                if full_path.is_file() and not full_path.is_symlink():
                    file_paths.append(full_path)

        file_paths.sort()

        # Build fast lookup for previous manifest if provided
        prev_file_map: Dict[str, FileEntry] = {}
        if previous_manifest:
            prev_file_map = {f.rel_path: f for f in previous_manifest.files}

        for path in file_paths:
            rel_path = path.relative_to(self.source_dir).as_posix()
            stat = path.stat()
            file_size = stat.st_size
            mtime = stat.st_mtime

            total_files += 1
            total_bytes += file_size

            # Check if file is completely unchanged based on size, mtime, and previous entry
            prev_entry = prev_file_map.get(rel_path)
            if prev_entry and prev_entry.size == file_size and abs(prev_entry.mtime - mtime) < 1e-4:
                # Re-use previous block metadata without re-reading if unchanged
                files.append(prev_entry)
                for blk in prev_entry.blocks:
                    chunk_hashes_set.add(blk.chunk_hash)
                continue

            blocks: List[BlockInfo] = []
            file_hasher = hashlib.sha256()

            if file_size == 0:
                # Handle 0-byte file
                empty_hash = hashlib.sha256(b"").hexdigest()
                files.append(
                    FileEntry(
                        rel_path=rel_path,
                        size=0,
                        mtime=mtime,
                        sha256=empty_hash,
                        blocks=[],
                    )
                )
                continue

            offset = 0
            chunk_index = 0

            with open(path, "rb") as f:
                while True:
                    chunk = f.read(self.chunk_size)
                    if not chunk:
                        break

                    file_hasher.update(chunk)
                    chunk_hash = hashlib.sha256(chunk).hexdigest()

                    blocks.append(
                        BlockInfo(
                            chunk_hash=chunk_hash,
                            offset=offset,
                            size=len(chunk),
                            chunk_index=chunk_index,
                        )
                    )

                    if chunk_hash not in chunk_pool:
                        chunk_pool[chunk_hash] = chunk
                    chunk_hashes_set.add(chunk_hash)

                    offset += len(chunk)
                    chunk_index += 1

            full_file_sha256 = file_hasher.hexdigest()
            files.append(
                FileEntry(
                    rel_path=rel_path,
                    size=file_size,
                    mtime=mtime,
                    sha256=full_file_sha256,
                    blocks=blocks,
                )
            )

        unique_chunks_count = len(chunk_hashes_set)
        unique_chunks_bytes = sum(len(data) for data in chunk_pool.values())
        deduplicated_bytes = max(0, total_bytes - unique_chunks_bytes)

        deduplication_ratio = (
            round(total_bytes / unique_chunks_bytes, 2)
            if unique_chunks_bytes > 0
            else 1.0
        )

        scan_result = ScanResult(
            source_path=str(self.source_dir),
            total_files=total_files,
            total_bytes=total_bytes,
            unique_chunks_count=unique_chunks_count,
            unique_chunks_bytes=unique_chunks_bytes,
            deduplicated_bytes=deduplicated_bytes,
            deduplication_ratio=deduplication_ratio,
            files=files,
            chunk_hashes=sorted(chunk_hashes_set),
        )

        return scan_result, chunk_pool
