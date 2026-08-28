"""Tests for FileScanner and block-level deduplication engine."""

import hashlib
from pathlib import Path
import tempfile
import pytest

from backup.scanner import FileScanner, BackupManifest, BlockInfo, FileEntry


def test_scanner_invalid_dir(tmp_path: Path):
    """Test scanner validation of source directory and chunk size."""
    non_existent = tmp_path / "non_existent"
    with pytest.raises(FileNotFoundError):
        FileScanner(non_existent)

    regular_file = tmp_path / "file.txt"
    regular_file.write_text("hello")
    with pytest.raises(NotADirectoryError):
        FileScanner(regular_file)

    with pytest.raises(ValueError):
        FileScanner(tmp_path, chunk_size=0)
    with pytest.raises(ValueError):
        FileScanner(tmp_path, chunk_size=-100)


def test_scanner_empty_dir(tmp_path: Path):
    """Test scanning an empty directory."""
    scanner = FileScanner(tmp_path)
    result, chunks = scanner.scan()

    assert result.total_files == 0
    assert result.total_bytes == 0
    assert result.unique_chunks_count == 0
    assert result.deduplication_ratio == 1.0
    assert len(result.files) == 0
    assert len(chunks) == 0


def test_scanner_single_and_zero_byte_file(tmp_path: Path):
    """Test scanning single regular file and 0-byte file."""
    f1 = tmp_path / "zero.txt"
    f1.write_bytes(b"")

    f2 = tmp_path / "data.txt"
    content = b"Enterprise Backup Payload Data 12345"
    f2.write_bytes(content)

    scanner = FileScanner(tmp_path, chunk_size=1024)
    result, chunks = scanner.scan()

    assert result.total_files == 2
    assert result.total_bytes == len(content)
    assert result.unique_chunks_count == 1
    assert len(chunks) == 1

    zero_entry = next(f for f in result.files if f.rel_path == "zero.txt")
    assert zero_entry.size == 0
    assert zero_entry.sha256 == hashlib.sha256(b"").hexdigest()
    assert len(zero_entry.blocks) == 0

    data_entry = next(f for f in result.files if f.rel_path == "data.txt")
    assert data_entry.size == len(content)
    assert data_entry.sha256 == hashlib.sha256(content).hexdigest()
    assert len(data_entry.blocks) == 1


def test_scanner_multi_block_file(tmp_path: Path):
    """Test scanning a file that spans multiple chunks."""
    chunk_size = 64
    total_chunks = 5
    data = b"A" * (chunk_size * total_chunks + 10)  # 330 bytes
    
    file_path = tmp_path / "large.bin"
    file_path.write_bytes(data)

    scanner = FileScanner(tmp_path, chunk_size=chunk_size)
    result, chunks = scanner.scan()

    assert result.total_files == 1
    assert result.total_bytes == len(data)
    entry = result.files[0]
    assert len(entry.blocks) == 6
    assert entry.blocks[0].offset == 0
    assert entry.blocks[0].size == 64
    assert entry.blocks[5].offset == 320
    assert entry.blocks[5].size == 10


def test_scanner_deduplication(tmp_path: Path):
    """Test deduplication ratio when duplicate content exists."""
    block_data = b"Duplicate Block Content ABCDEFGHIJKLMNOPQRSTUVWXYZ 1234567890\n" * 10
    
    # Create 3 identical files
    for i in range(3):
        (tmp_path / f"dup_{i}.txt").write_bytes(block_data)

    scanner = FileScanner(tmp_path, chunk_size=len(block_data))
    result, chunks = scanner.scan()

    assert result.total_files == 3
    assert result.total_bytes == len(block_data) * 3
    assert result.unique_chunks_count == 1
    assert result.unique_chunks_bytes == len(block_data)
    assert result.deduplicated_bytes == len(block_data) * 2
    assert result.deduplication_ratio == 3.0


def test_scanner_incremental_tracking(tmp_path: Path):
    """Test incremental detection using previous manifest."""
    f1 = tmp_path / "unchanged.txt"
    f1.write_bytes(b"Static Content")

    f2 = tmp_path / "modified.txt"
    f2.write_bytes(b"Initial Version")

    scanner = FileScanner(tmp_path, chunk_size=1024)
    result1, chunks1 = scanner.scan()

    manifest1 = BackupManifest(
        backup_id="bkp_001",
        timestamp="2026-08-27T00:00:00Z",
        source_path=str(tmp_path),
        total_files=result1.total_files,
        total_bytes=result1.total_bytes,
        unique_chunks=result1.unique_chunks_count,
        files=result1.files,
        chunk_hashes=result1.chunk_hashes,
    )

    # Modify f2
    f2.write_bytes(b"Updated New Content 2.0")

    result2, chunks2 = scanner.scan(previous_manifest=manifest1)
    assert result2.total_files == 2
    
    # Check that modified file has updated sha256
    mod_entry = next(f for f in result2.files if f.rel_path == "modified.txt")
    assert mod_entry.sha256 == hashlib.sha256(b"Updated New Content 2.0").hexdigest()
    
    unchanged_entry = next(f for f in result2.files if f.rel_path == "unchanged.txt")
    assert unchanged_entry.sha256 == hashlib.sha256(b"Static Content").hexdigest()


def test_scanner_nested_hierarchy(tmp_path: Path):
    """Test scanning nested directory structures."""
    d1 = tmp_path / "sub1" / "sub2"
    d1.mkdir(parents=True)
    (d1 / "nested_file.txt").write_text("nested data")

    d2 = tmp_path / "sub3"
    d2.mkdir()
    (d2 / "another.txt").write_text("another data")

    scanner = FileScanner(tmp_path)
    result, chunks = scanner.scan()

    assert result.total_files == 2
    rel_paths = {f.rel_path for f in result.files}
    assert rel_paths == {"sub1/sub2/nested_file.txt", "sub3/another.txt"}
