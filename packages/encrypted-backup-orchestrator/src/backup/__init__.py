"""
Encrypted Backup Orchestrator.

Enterprise DR Incremental Backup Orchestrator with Block Deduplication,
Zstandard Compression, AES-256-GCM Encryption, GFS Retention & Automated Sandbox Verification.
"""

from backup.scanner import (
    BlockInfo,
    FileEntry,
    ScanResult,
    BackupManifest,
    FileScanner,
)
from backup.compress import (
    CompressionAlgorithm,
    CompressionStats,
    Compressor,
    CompressionError,
    DecompressionError,
)
from backup.crypto import (
    CryptoEngine,
    CryptoError,
    AuthenticationError,
    InvalidPayloadError,
)
from backup.retention import (
    RetentionPolicy,
    BackupRecord,
    RetentionDecision,
    RetentionResult,
    GFSRetentionManager,
)
from backup.restore_tester import (
    FileVerificationStatus,
    RestoreTestResult,
    SandboxRestoreTester,
    PathTraversalError,
    IntegrityVerificationError,
    RestoreError,
)

__version__ = "0.1.0"
__all__ = [
    "BlockInfo",
    "FileEntry",
    "ScanResult",
    "BackupManifest",
    "FileScanner",
    "CompressionAlgorithm",
    "CompressionStats",
    "Compressor",
    "CompressionError",
    "DecompressionError",
    "CryptoEngine",
    "CryptoError",
    "AuthenticationError",
    "InvalidPayloadError",
    "RetentionPolicy",
    "BackupRecord",
    "RetentionDecision",
    "RetentionResult",
    "GFSRetentionManager",
    "FileVerificationStatus",
    "RestoreTestResult",
    "SandboxRestoreTester",
    "PathTraversalError",
    "IntegrityVerificationError",
    "RestoreError",
]
