"""container-secret-scanner: Enterprise-grade static secret scanner for repositories and OCI containers."""

__version__ = "0.1.0"
__author__ = "cibi-dev"

from scanner.engine import SecretScannerEngine, Finding, ScanOptions, ScanSummary
from scanner.rules import SecretRule, DEFAULT_RULES
from scanner.entropy import shannon_entropy, is_high_entropy

__all__ = [
    "SecretScannerEngine",
    "Finding",
    "ScanOptions",
    "ScanSummary",
    "SecretRule",
    "DEFAULT_RULES",
    "shannon_entropy",
    "is_high_entropy",
    "__version__",
]
