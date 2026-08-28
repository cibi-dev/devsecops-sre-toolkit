"""
Compression module supporting Zstandard and Gzip block compression.
"""

from __future__ import annotations

from enum import Enum
import gzip
from typing import Optional, Tuple
import zlib

from pydantic import BaseModel, Field
import zstandard


class CompressionAlgorithm(str, Enum):
    """Supported compression algorithms."""

    ZSTD = "zstd"
    GZIP = "gzip"
    NONE = "none"


class CompressionStats(BaseModel):
    """Compression metrics and ratio."""

    algorithm: str = Field(description="Algorithm used")
    original_size: int = Field(ge=0, description="Uncompressed size in bytes")
    compressed_size: int = Field(ge=0, description="Compressed size in bytes")
    ratio: float = Field(description="Compression ratio (original / compressed)")
    savings_percent: float = Field(description="Percentage of space saved")


class CompressionError(Exception):
    """Raised when compression fails."""


class DecompressionError(Exception):
    """Raised when decompression fails."""


class Compressor:
    """Handles block and stream compression/decompression with Zstandard and Gzip."""

    ZSTD_MAGIC = b"\x28\xb5\x2f\xfd"
    GZIP_MAGIC = b"\x1f\x8b"

    @classmethod
    def compress(
        cls,
        data: bytes,
        algorithm: CompressionAlgorithm | str = CompressionAlgorithm.ZSTD,
        level: int = 3,
    ) -> Tuple[bytes, CompressionStats]:
        """
        Compress byte data using the specified algorithm.

        Args:
            data: Raw input bytes.
            algorithm: Compression algorithm ("zstd", "gzip", "none").
            level: Compression level (1-22 for zstd, 1-9 for gzip).

        Returns:
            Tuple of (compressed_bytes, CompressionStats).
        """
        if isinstance(algorithm, str):
            try:
                algo = CompressionAlgorithm(algorithm.lower())
            except ValueError as exc:
                raise ValueError(f"Unsupported compression algorithm: {algorithm}") from exc
        else:
            algo = algorithm

        original_size = len(data)
        if original_size == 0:
            return b"", CompressionStats(
                algorithm=algo.value,
                original_size=0,
                compressed_size=0,
                ratio=1.0,
                savings_percent=0.0,
            )

        try:
            if algo == CompressionAlgorithm.ZSTD:
                # Clamp level between 1 and 22
                clamped_level = max(1, min(level, 22))
                cctx = zstandard.ZstdCompressor(level=clamped_level)
                compressed = cctx.compress(data)
            elif algo == CompressionAlgorithm.GZIP:
                # Clamp level between 1 and 9
                clamped_level = max(1, min(level, 9))
                compressed = gzip.compress(data, compresslevel=clamped_level)
            elif algo == CompressionAlgorithm.NONE:
                compressed = data
            else:
                raise ValueError(f"Unknown compression algorithm: {algo}")
        except Exception as exc:
            raise CompressionError(f"Compression failed with algorithm {algo}: {exc}") from exc

        compressed_size = len(compressed)
        ratio = round(original_size / compressed_size, 2) if compressed_size > 0 else 1.0
        savings = (
            round(((original_size - compressed_size) / original_size) * 100.0, 2)
            if original_size > 0
            else 0.0
        )

        stats = CompressionStats(
            algorithm=algo.value,
            original_size=original_size,
            compressed_size=compressed_size,
            ratio=ratio,
            savings_percent=savings,
        )

        return compressed, stats

    @classmethod
    def decompress(
        cls,
        data: bytes,
        algorithm: Optional[CompressionAlgorithm | str] = None,
    ) -> bytes:
        """
        Decompress data, with auto-detection of algorithm if not specified.

        Args:
            data: Compressed byte payload.
            algorithm: Optional algorithm name. If None, auto-detected from magic bytes.

        Returns:
            Decompressed raw bytes.
        """
        if not data:
            return b""

        detected_algo: Optional[CompressionAlgorithm] = None
        if algorithm is not None:
            if isinstance(algorithm, str):
                try:
                    detected_algo = CompressionAlgorithm(algorithm.lower())
                except ValueError as exc:
                    raise ValueError(f"Unsupported algorithm: {algorithm}") from exc
            else:
                detected_algo = algorithm
        else:
            # Auto-detect via magic bytes
            if data.startswith(cls.ZSTD_MAGIC):
                detected_algo = CompressionAlgorithm.ZSTD
            elif data.startswith(cls.GZIP_MAGIC):
                detected_algo = CompressionAlgorithm.GZIP
            else:
                # If magic bytes do not match standard formats, fallback to none
                detected_algo = CompressionAlgorithm.NONE

        try:
            if detected_algo == CompressionAlgorithm.ZSTD:
                dctx = zstandard.ZstdDecompressor()
                return dctx.decompress(data)
            elif detected_algo == CompressionAlgorithm.GZIP:
                return gzip.decompress(data)
            elif detected_algo == CompressionAlgorithm.NONE:
                return data
            else:
                raise ValueError(f"Unknown algorithm: {detected_algo}")
        except (zstandard.ZstdError, gzip.BadGzipFile, zlib.error, EOFError) as exc:
            raise DecompressionError(f"Decompression failed: {exc}") from exc
        except Exception as exc:
            raise DecompressionError(f"Unexpected error during decompression: {exc}") from exc
