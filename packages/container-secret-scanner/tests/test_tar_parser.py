"""Unit tests for safe iterative TAR / OCI layer extraction and DevSecOps protections (CWE-409, CWE-59, CWE-22)."""

import io
import tarfile
import pytest
from pathlib import Path

from scanner.tar_parser import (
    SafeTarEntry,
    TarSecurityError,
    is_safe_tar_path,
    iterate_tar_stream,
)


def test_is_safe_tar_path_valid():
    """Valid relative paths return True."""
    assert is_safe_tar_path("app/main.py")
    assert is_safe_tar_path("var/log/app.log")
    assert is_safe_tar_path("manifest.json")
    assert is_safe_tar_path("dir1/dir2/file.txt")
    assert is_safe_tar_path("./file.txt")


def test_is_safe_tar_path_path_traversal():
    """Path traversal sequences return False (CWE-22 / CWE-59)."""
    assert not is_safe_tar_path("../../etc/shadow")
    assert not is_safe_tar_path("../secret.txt")
    assert not is_safe_tar_path("app/../../etc/passwd")
    assert not is_safe_tar_path("/etc/passwd")
    assert not is_safe_tar_path("/root/.ssh/id_rsa")
    assert not is_safe_tar_path("C:\\Windows\\System32")
    assert not is_safe_tar_path("")
    assert not is_safe_tar_path("   ")
    assert not is_safe_tar_path("..")


def _create_test_tar(entries: dict) -> io.BytesIO:
    """Helper to construct an in-memory tarball."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        for path, content in entries.items():
            info = tarfile.TarInfo(name=path)
            data = content.encode("utf-8") if isinstance(content, str) else content
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    buf.seek(0)
    return buf


def test_iterate_tar_stream_valid(tmp_path: Path):
    """Safely extracts valid entries from a tarball."""
    entries_map = {
        "app/server.py": "print('hello')",
        "config/settings.json": '{"debug": true}',
    }
    tar_buf = _create_test_tar(entries_map)
    tar_path = tmp_path / "test.tar"
    tar_path.write_bytes(tar_buf.getvalue())

    extracted = list(iterate_tar_stream(tar_path))
    assert len(extracted) == 2
    paths = {e.path for e in extracted}
    assert "app/server.py" in paths
    assert "config/settings.json" in paths


def test_iterate_tar_stream_with_fileobj():
    """iterate_tar_stream works with raw in-memory BinaryIO stream."""
    entries_map = {"file.txt": "content"}
    buf = _create_test_tar(entries_map)
    extracted = list(iterate_tar_stream(buf))
    assert len(extracted) == 1
    assert extracted[0].path == "file.txt"


def test_tar_path_traversal_blocked(tmp_path: Path):
    """Tarball containing directory traversal entry raises TarSecurityError."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        info = tarfile.TarInfo(name="../../etc/passwd")
        data = b"root:x:0:0:root:/root:/bin/bash"
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))
    buf.seek(0)

    tar_path = tmp_path / "evil_traversal.tar"
    tar_path.write_bytes(buf.getvalue())

    with pytest.raises(TarSecurityError, match="Path traversal detected"):
        list(iterate_tar_stream(tar_path))


def test_tar_skips_directories_and_devices():
    """Tar parser ignores directory headers, FIFOs, and devices safely."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        # Directory
        d_info = tarfile.TarInfo(name="mydir/")
        d_info.type = tarfile.DIRTYPE
        tar.addfile(d_info)

        # FIFO
        f_info = tarfile.TarInfo(name="myfifo")
        f_info.type = tarfile.FIFOTYPE
        tar.addfile(f_info)

        # Symlink
        s_info = tarfile.TarInfo(name="link_safe")
        s_info.type = tarfile.SYMTYPE
        s_info.linkname = "target.txt"
        tar.addfile(s_info)

        # Regular file
        r_info = tarfile.TarInfo(name="regular.txt")
        r_data = b"hello"
        r_info.size = len(r_data)
        tar.addfile(r_info, io.BytesIO(r_data))

    buf.seek(0)
    entries = list(iterate_tar_stream(buf))
    assert len(entries) == 1
    assert entries[0].path == "regular.txt"


def test_tar_bomb_file_count_limit(tmp_path: Path):
    """Tarball exceeding max file count limit raises TarSecurityError (CWE-409)."""
    entries = {f"file_{i}.txt": f"data_{i}" for i in range(15)}
    tar_buf = _create_test_tar(entries)
    tar_path = tmp_path / "bomb_count.tar"
    tar_path.write_bytes(tar_buf.getvalue())

    with pytest.raises(TarSecurityError, match="maximum file count quota"):
        list(iterate_tar_stream(tar_path, max_file_count=10))


def test_tar_bomb_cumulative_size_limit(tmp_path: Path):
    """Tarball exceeding max cumulative bytes raises TarSecurityError (CWE-409)."""
    entries = {f"file_{i}.txt": "A" * 100 for i in range(5)}
    tar_buf = _create_test_tar(entries)
    tar_path = tmp_path / "bomb_size.tar"
    tar_path.write_bytes(tar_buf.getvalue())

    with pytest.raises(TarSecurityError, match="cumulative size"):
        list(iterate_tar_stream(tar_path, max_total_bytes=300))


def test_tar_bomb_single_file_size_limit(tmp_path: Path):
    """Tarball with single file exceeding single file limit raises TarSecurityError."""
    entries = {"huge.bin": "A" * 500}
    tar_buf = _create_test_tar(entries)
    tar_path = tmp_path / "bomb_single.tar"
    tar_path.write_bytes(tar_buf.getvalue())

    with pytest.raises(TarSecurityError, match="exceeds max single file limit"):
        list(iterate_tar_stream(tar_path, max_single_file_bytes=200))


def test_nested_tar_layer_extraction(tmp_path: Path):
    """Nested OCI layer tarballs are recursively extracted in-memory."""
    # Inner tar
    inner_entries = {"inner/app.py": "print('from inner layer')"}
    inner_buf = _create_test_tar(inner_entries)

    # Outer tar
    outer_buf = io.BytesIO()
    with tarfile.open(fileobj=outer_buf, mode="w") as tar:
        # Add manifest
        m_info = tarfile.TarInfo(name="manifest.json")
        m_data = b'{"Layers": ["layer.tar"]}'
        m_info.size = len(m_data)
        tar.addfile(m_info, io.BytesIO(m_data))

        # Add nested layer.tar
        l_info = tarfile.TarInfo(name="layer.tar")
        l_data = inner_buf.getvalue()
        l_info.size = len(l_data)
        tar.addfile(l_info, io.BytesIO(l_data))

    outer_buf.seek(0)
    tar_path = tmp_path / "container_image.tar"
    tar_path.write_bytes(outer_buf.getvalue())

    extracted = list(iterate_tar_stream(tar_path))
    paths = [e.path for e in extracted]
    assert "manifest.json" in paths
    assert "layer.tar" in paths
    assert any("inner/app.py" in p for p in paths)


def test_nested_tar_depth_limit():
    """Recursion stops when current_depth > max_depth."""
    buf = io.BytesIO()
    entries = list(iterate_tar_stream(buf, current_depth=5, max_depth=3))
    assert entries == []


def test_tar_file_not_found():
    """Non-existent file raises FileNotFoundError."""
    with pytest.raises(FileNotFoundError):
        list(iterate_tar_stream("non_existent_file.tar"))
