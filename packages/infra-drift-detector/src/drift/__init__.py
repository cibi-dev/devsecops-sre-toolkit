"""infra-drift-detector: Enterprise read-only GitOps infrastructure drift detector for Linux."""

from __future__ import annotations

from drift.comparator import DriftComparator, DriftItem, DriftResult, DriftSeverity, DriftType
from drift.parser import ManifestParseError, parse_manifest, sanitize_secrets
from drift.reporter import DriftReporter
from drift.schema import (
    FileDesired,
    Manifest,
    PackageDesired,
    PortDesired,
    ServiceDesired,
    SysctlDesired,
    UserDesired,
)

__version__ = "0.1.0"
__all__ = [
    "DriftComparator",
    "DriftItem",
    "DriftReporter",
    "DriftResult",
    "DriftSeverity",
    "DriftType",
    "FileDesired",
    "Manifest",
    "ManifestParseError",
    "PackageDesired",
    "PortDesired",
    "ServiceDesired",
    "SysctlDesired",
    "UserDesired",
    "parse_manifest",
    "sanitize_secrets",
]
