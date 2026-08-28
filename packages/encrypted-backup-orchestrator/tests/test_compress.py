"""Tests for Compressor module supporting Zstandard and Gzip."""

import pytest

from backup.compress import (
    CompressionAlgorithm,
    Compressor,
    CompressionError,
    DecompressionError,
)


def test_compress_zstd_roundtrip():
    """Test Zstandard compression and decompression roundtrip."""
    payload = b"Hello, Enterprise Disaster Recovery with Zstandard! " * 50
    compressed, stats = Compressor.compress(payload, algorithm=CompressionAlgorithm.ZSTD, level=3)

    assert len(compressed) < len(payload)
    assert stats.algorithm == "zstd"
    assert stats.original_size == len(payload)
    assert stats.compressed_size == len(compressed)
    assert stats.ratio > 1.0
    assert stats.savings_percent > 0.0

    decompressed = Compressor.decompress(compressed, algorithm=CompressionAlgorithm.ZSTD)
    assert decompressed == payload


def test_compress_gzip_roundtrip():
    """Test Gzip compression and decompression roundtrip."""
    payload = b"Gzip compression testing payload data block... " * 40
    compressed, stats = Compressor.compress(payload, algorithm=CompressionAlgorithm.GZIP, level=6)

    assert len(compressed) < len(payload)
    assert stats.algorithm == "gzip"
    assert stats.ratio > 1.0

    decompressed = Compressor.decompress(compressed, algorithm=CompressionAlgorithm.GZIP)
    assert decompressed == payload


def test_compress_none_passthrough():
    """Test 'none' compression passthrough."""
    payload = b"Raw uncompressed bytes 123456"
    compressed, stats = Compressor.compress(payload, algorithm=CompressionAlgorithm.NONE)

    assert compressed == payload
    assert stats.ratio == 1.0
    assert stats.savings_percent == 0.0

    decompressed = Compressor.decompress(compressed, algorithm=CompressionAlgorithm.NONE)
    assert decompressed == payload


def test_compress_empty_data():
    """Test handling of 0-byte data."""
    compressed, stats = Compressor.compress(b"", algorithm=CompressionAlgorithm.ZSTD)
    assert compressed == b""
    assert stats.original_size == 0
    assert stats.compressed_size == 0
    assert stats.ratio == 1.0

    decompressed = Compressor.decompress(b"", algorithm=CompressionAlgorithm.ZSTD)
    assert decompressed == b""

    # Empty decompress with None
    assert Compressor.decompress(b"") == b""


def test_compress_autodetection():
    """Test magic byte autodection during decompression without explicit algorithm."""
    payload = b"Autodetection test buffer data payload 9876543210 " * 20

    zstd_comp, _ = Compressor.compress(payload, algorithm=CompressionAlgorithm.ZSTD)
    assert Compressor.decompress(zstd_comp) == payload

    gzip_comp, _ = Compressor.compress(payload, algorithm=CompressionAlgorithm.GZIP)
    assert Compressor.decompress(gzip_comp) == payload

    # Unrecognized magic bytes fallback to uncompressed payload
    plain = b"Just plain uncompressed data without magic header"
    assert Compressor.decompress(plain) == plain


def test_compress_invalid_algorithm():
    """Test handling of unknown compression algorithms."""
    with pytest.raises(ValueError, match="Unsupported compression algorithm"):
        Compressor.compress(b"data", algorithm="lzma_unknown")

    with pytest.raises(ValueError, match="Unsupported algorithm"):
        Compressor.decompress(b"data", algorithm="bzip_unknown")


def test_compress_corrupted_decompression():
    """Test that corrupted compressed data raises DecompressionError."""
    corrupted = Compressor.ZSTD_MAGIC + b"\x00\x00\xff\xff" * 10
    with pytest.raises(DecompressionError):
        Compressor.decompress(corrupted, algorithm=CompressionAlgorithm.ZSTD)

    corrupted_gzip = Compressor.GZIP_MAGIC + b"\x00\x00\x11\x22" * 10
    with pytest.raises(DecompressionError):
        Compressor.decompress(corrupted_gzip, algorithm=CompressionAlgorithm.GZIP)


def test_compress_string_enum_conversion():
    """Test passing string names for compression algorithm."""
    data = b"Testing string enum conversions"
    comp_zstd, stats_zstd = Compressor.compress(data, algorithm="zstd")
    assert stats_zstd.algorithm == "zstd"
    assert Compressor.decompress(comp_zstd, algorithm="zstd") == data

    comp_gzip, stats_gzip = Compressor.compress(data, algorithm="gzip")
    assert stats_gzip.algorithm == "gzip"
    assert Compressor.decompress(comp_gzip, algorithm="gzip") == data

    comp_none, stats_none = Compressor.compress(data, algorithm="none")
    assert stats_none.algorithm == "none"
    assert Compressor.decompress(comp_none, algorithm="none") == data
