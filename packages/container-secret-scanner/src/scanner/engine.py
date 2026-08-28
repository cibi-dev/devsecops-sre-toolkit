"""High-performance multi-threaded secret scanner engine with bounded concurrency and DevSecOps protections."""

from __future__ import annotations

import fnmatch
import os
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterable, List, Optional, Set, Tuple, Union

from scanner.ast_scanner import scan_python_ast
from scanner.entropy import is_high_entropy, shannon_entropy
from scanner.rules import DEFAULT_RULES, SecretRule
from scanner.tar_parser import TarSecurityError, iterate_tar_stream


# Concurrency safety limits (CWE-400)
MAX_WORKER_LIMIT: int = 32
DEFAULT_WORKERS: int = 4

# Standard exclusions to skip high-noise or binary folders
DEFAULT_EXCLUDED_PATTERNS: List[str] = [
    "*.git*",
    "*.venv*",
    "*/.venv/*",
    "*/venv/*",
    "*/node_modules/*",
    "*/__pycache__/*",
    "*.pyc",
    "*.pyo",
    "*.pyd",
    "*.so",
    "*.dylib",
    "*.dll",
    "*.exe",
    "*.png",
    "*.jpg",
    "*.jpeg",
    "*.gif",
    "*.svg",
    "*.ico",
    "*.webp",
    "*.woff*",
    "*.ttf",
    "*.eot",
    "*.pdf",
    "*.zip",
    "*.gz",
    "*.bz2",
    "*.xz",
    "*.7z",
    "*.pytest_cache*",
    "*.mypy_cache*",
    "*.coverage*",
    "*.lock",
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
]


def redact_secret(secret: str) -> str:
    """Sanitize secret tokens for safe display and logging (CWE-209).

    Args:
        secret: Raw secret string.

    Returns:
        Redacted string showing only [REDACTED] or trailing 4 characters.
    """
    if not secret:
        return "[REDACTED]"
    secret_str = str(secret).strip()
    if len(secret_str) <= 8:
        return "[REDACTED]"
    return f"[REDACTED]...{secret_str[-4:]}"


def sanitize_line_context(line: str, raw_secret: str) -> str:
    """Replace occurrences of raw secret in source line context with redacted form."""
    if not line:
        return ""
    redacted = redact_secret(raw_secret)
    # Truncate context line if excessively long (e.g. minified JS/JSON)
    sanitized = line.replace(raw_secret, redacted)
    if len(sanitized) > 200:
        return sanitized[:197] + "..."
    return sanitized.strip()


@dataclass
class Finding:
    """Represents a discovered secret vulnerability."""

    rule_id: str
    rule_name: str
    file_path: str
    line_number: int
    column_number: int
    matched_text: str
    redacted_text: str
    entropy: float
    severity: str
    cwe_id: str
    category: str
    context_line: str


@dataclass
class ScanOptions:
    """Configuration options for scanning execution."""

    max_workers: int = DEFAULT_WORKERS
    entropy_threshold: float = 4.5
    excluded_patterns: List[str] = field(default_factory=lambda: list(DEFAULT_EXCLUDED_PATTERNS))
    max_file_size_bytes: int = 10 * 1024 * 1024  # 10 MB per text file
    enable_ast_scan: bool = True
    rules: Optional[List[SecretRule]] = None

    def __post_init__(self) -> None:
        # Bounded concurrency guardrail (CWE-400)
        self.max_workers = max(1, min(self.max_workers, MAX_WORKER_LIMIT))


@dataclass
class ScanSummary:
    """Aggregated results of a scanning run."""

    files_scanned: int
    bytes_scanned: int
    findings: List[Finding]
    duration_seconds: float
    errors: List[str] = field(default_factory=list)

    @property
    def has_findings(self) -> bool:
        return len(self.findings) > 0

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "CRITICAL")

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "HIGH")

    @property
    def medium_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "MEDIUM")

    @property
    def low_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "LOW")


class SecretScannerEngine:
    """Core multithreaded scanning engine supporting files, directories, TARs, and Git trees."""

    def __init__(self, options: Optional[ScanOptions] = None) -> None:
        self.options = options or ScanOptions()
        self.rules: List[SecretRule] = self.options.rules or DEFAULT_RULES

    def is_path_excluded(self, path: str) -> bool:
        """Check if path matches any exclusion glob patterns."""
        normalized = path.replace("\\", "/")
        for pattern in self.options.excluded_patterns:
            if fnmatch.fnmatch(normalized, pattern) or fnmatch.fnmatch(os.path.basename(normalized), pattern):
                return True
        return False

    def scan_content(self, content: str, file_path: str) -> List[Finding]:
        """Scan string content using compiled regex rules and optional AST analysis.

        Args:
            content: Text content to scan.
            file_path: Virtual or actual file path for reporting.

        Returns:
            List of detected findings.
        """
        findings: List[Finding] = []
        if not content:
            return findings

        lines = content.splitlines()

        # 1. Regex Rule Scanner
        for line_idx, line in enumerate(lines, start=1):
            # Skip empty lines or excessively large minified lines (>50k chars)
            if not line or len(line) > 50_000:
                continue

            for rule in self.rules:
                for match in rule.pattern.finditer(line):
                    # Extract secret token based on rule match_group
                    try:
                        raw_secret = match.group(rule.match_group)
                    except IndexError:
                        raw_secret = match.group(0)

                    if not raw_secret:
                        continue

                    entropy = shannon_entropy(raw_secret)

                    # Apply entropy threshold if required by rule or generic threshold
                    if rule.min_entropy is not None:
                        if entropy < rule.min_entropy:
                            continue

                    col = match.start() + 1
                    redacted = redact_secret(raw_secret)
                    context = sanitize_line_context(line, raw_secret)

                    finding = Finding(
                        rule_id=rule.rule_id,
                        rule_name=rule.name,
                        file_path=file_path,
                        line_number=line_idx,
                        column_number=col,
                        matched_text=raw_secret,
                        redacted_text=redacted,
                        entropy=entropy,
                        severity=rule.severity,
                        cwe_id=rule.cwe_id,
                        category=rule.category,
                        context_line=context,
                    )
                    findings.append(finding)

        # 2. Python AST Scanner (only on .py files)
        if self.options.enable_ast_scan and file_path.endswith(".py"):
            ast_results = scan_python_ast(content, entropy_threshold=self.options.entropy_threshold)
            # Avoid duplicate reporting if already detected by regex
            existing_lines = {f.line_number for f in findings}
            for ast_f in ast_results:
                if ast_f.line_number not in existing_lines:
                    line_idx = ast_f.line_number
                    context = lines[line_idx - 1] if 1 <= line_idx <= len(lines) else ""
                    finding = Finding(
                        rule_id=ast_f.rule_id,
                        rule_name="Hardcoded Secret Assignment",
                        file_path=file_path,
                        line_number=ast_f.line_number,
                        column_number=ast_f.column_number + 1,
                        matched_text=ast_f.secret_value,
                        redacted_text=redact_secret(ast_f.secret_value),
                        entropy=ast_f.entropy,
                        severity="HIGH" if ast_f.confidence == "HIGH" else "MEDIUM",
                        cwe_id=ast_f.cwe_id,
                        category="Static Code Analysis",
                        context_line=sanitize_line_context(context, ast_f.secret_value),
                    )
                    findings.append(finding)

        return findings

    def scan_file(self, file_path: Union[str, Path]) -> Tuple[List[Finding], int, Optional[str]]:
        """Scan an individual file from disk.

        Returns:
            Tuple of (findings, file_size_bytes, error_message_or_None).
        """
        p = Path(file_path)
        if not p.is_file():
            return [], 0, f"Not a valid file: {file_path}"

        try:
            size = p.stat().st_size
            if size > self.options.max_file_size_bytes:
                return [], size, None  # Skip oversized files safely

            # Read with binary check
            with open(p, "rb") as f:
                raw_bytes = f.read(self.options.max_file_size_bytes)

            # Heuristic check for binary files (e.g. presence of null bytes)
            if b"\x00" in raw_bytes[:1024]:
                return [], len(raw_bytes), None

            text = raw_bytes.decode("utf-8", errors="replace")
            findings = self.scan_content(text, str(p))
            return findings, len(raw_bytes), None

        except Exception as e:
            return [], 0, f"Error scanning {file_path}: {e}"

    def scan_directory(self, target_dir: Union[str, Path]) -> ScanSummary:
        """Scan a directory recursively using bounded ThreadPoolExecutor."""
        start_time = time.perf_counter()
        target_path = Path(target_dir).resolve()

        if not target_path.exists() or not target_path.is_dir():
            return ScanSummary(
                files_scanned=0,
                bytes_scanned=0,
                findings=[],
                duration_seconds=0.0,
                errors=[f"Target directory does not exist or is not a directory: {target_dir}"],
            )

        # Collect candidate files
        candidate_files: List[Path] = []
        for root, dirs, files in os.walk(target_path):
            # Prune excluded directories in-place
            dirs[:] = [
                d for d in dirs
                if not self.is_path_excluded(os.path.join(root, d))
                and not d.startswith(".")
            ]

            for file in files:
                full_p = Path(root) / file
                rel_p = str(full_p.relative_to(target_path))
                if not self.is_path_excluded(rel_p):
                    candidate_files.append(full_p)

        all_findings: List[Finding] = []
        errors: List[str] = []
        total_bytes = 0
        total_files = len(candidate_files)

        # Bounded ThreadPoolExecutor execution
        workers = min(self.options.max_workers, max(1, total_files))
        with ThreadPoolExecutor(max_workers=workers) as executor:
            future_to_file = {executor.submit(self.scan_file, f): f for f in candidate_files}
            for future in as_completed(future_to_file):
                f_path = future_to_file[future]
                try:
                    f_findings, f_bytes, err = future.result()
                    total_bytes += f_bytes
                    if err:
                        errors.append(err)
                    if f_findings:
                        all_findings.extend(f_findings)
                except Exception as e:
                    errors.append(f"Unhandled worker error on {f_path}: {e}")

        duration = time.perf_counter() - start_time
        return ScanSummary(
            files_scanned=total_files,
            bytes_scanned=total_bytes,
            findings=all_findings,
            duration_seconds=duration,
            errors=errors,
        )

    def scan_tar(self, tar_path: Union[str, Path]) -> ScanSummary:
        """Safely scan an OCI container layer or TAR archive in-memory without disk extraction."""
        start_time = time.perf_counter()
        p = Path(tar_path).resolve()

        if not p.exists() or not p.is_file():
            return ScanSummary(
                files_scanned=0,
                bytes_scanned=0,
                findings=[],
                duration_seconds=0.0,
                errors=[f"Tar file not found: {tar_path}"],
            )

        all_findings: List[Finding] = []
        errors: List[str] = []
        total_files = 0
        total_bytes = 0

        try:
            for entry in iterate_tar_stream(p):
                # Skip excluded patterns
                if self.is_path_excluded(entry.path):
                    continue

                total_files += 1
                total_bytes += entry.size

                # Skip binary blobs
                if b"\x00" in entry.content[:1024]:
                    continue

                try:
                    text = entry.content.decode("utf-8", errors="replace")
                    f_results = self.scan_content(text, entry.path)
                    if f_results:
                        all_findings.extend(f_results)
                except Exception as e:
                    errors.append(f"Error decoding entry {entry.path}: {e}")

        except TarSecurityError as e:
            errors.append(f"Security constraint violated: {e}")
        except Exception as e:
            errors.append(f"Tar scanning failed: {e}")

        duration = time.perf_counter() - start_time
        return ScanSummary(
            files_scanned=total_files,
            bytes_scanned=total_bytes,
            findings=all_findings,
            duration_seconds=duration,
            errors=errors,
        )

    def scan_git(self, repo_dir: Union[str, Path], commit_or_range: Optional[str] = None) -> ScanSummary:
        """Scan git repository files using safe subprocess calls (CWE-78)."""
        start_time = time.perf_counter()
        repo_path = Path(repo_dir).resolve()

        if not (repo_path / ".git").exists() and not (repo_path / "HEAD").exists():
            return ScanSummary(
                files_scanned=0,
                bytes_scanned=0,
                findings=[],
                duration_seconds=0.0,
                errors=[f"Directory is not a valid Git repository: {repo_dir}"],
            )

        all_findings: List[Finding] = []
        errors: List[str] = []
        total_files = 0
        total_bytes = 0

        try:
            # Query git ls-files safely (shell=False)
            cmd = ["git", "-C", str(repo_path), "ls-files"]
            proc = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=True,
                shell=False,  # CWE-78 mitigation
            )
            files = [f.strip() for f in proc.stdout.splitlines() if f.strip()]

            for rel_file in files:
                if self.is_path_excluded(rel_file):
                    continue

                abs_file = repo_path / rel_file
                if abs_file.is_file():
                    f_results, f_bytes, err = self.scan_file(abs_file)
                    total_files += 1
                    total_bytes += f_bytes
                    if err:
                        errors.append(err)
                    if f_results:
                        all_findings.extend(f_results)

        except subprocess.CalledProcessError as e:
            errors.append(f"Git command failed: {e.stderr.strip()}")
        except Exception as e:
            errors.append(f"Git scan error: {e}")

        duration = time.perf_counter() - start_time
        return ScanSummary(
            files_scanned=total_files,
            bytes_scanned=total_bytes,
            findings=all_findings,
            duration_seconds=duration,
            errors=errors,
        )
