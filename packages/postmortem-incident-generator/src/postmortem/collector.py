"""Read-Only System, Git, and Log Evidence Collector.

Complies with CWE-250 (Least Privilege / Read-Only execution) and CWE-78 (Safe Subprocess Execution).
Guarantees zero-mutation of system and source control state.
All collected data is sanitized via EvidenceSanitizer before output.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from postmortem.sanitizer import sanitize_data, sanitize_dict, sanitize_text


class EvidenceCollector:
    """Safe read-only evidence collector for Linux environments and Git repositories."""

    MAX_LOG_LINES = 1000
    MAX_LINE_LENGTH = 65536
    DEFAULT_TIMEOUT_SECONDS = 10

    def __init__(self, sanitize: bool = True) -> None:
        """Initialize collector with sanitization option."""
        self.sanitize = sanitize

    def collect_system_logs(
        self,
        since: Optional[str] = None,
        lines: int = 100,
        service: Optional[str] = None,
        log_file: Optional[Union[str, Path]] = None,
    ) -> List[str]:
        """Collect system logs via journalctl or log file safely in read-only mode."""
        clamped_lines = min(max(1, lines), self.MAX_LOG_LINES)
        raw_lines: List[str] = []

        if log_file:
            path = Path(log_file)
            if path.is_file():
                try:
                    with path.open("r", encoding="utf-8", errors="replace") as f:
                        lines_read = 0
                        for line in f:
                            raw_lines.append(line.rstrip()[: self.MAX_LINE_LENGTH])
                            lines_read += 1
                            if lines_read >= clamped_lines:
                                break
                except OSError as exc:
                    raw_lines.append(f"[ERROR] Failed to read log file {path}: {exc}")
            else:
                raw_lines.append(f"[WARN] Log file not found: {path}")
        else:
            # Attempt journalctl read-only command execution with shell=False
            journalctl_bin = shutil.which("journalctl")
            if journalctl_bin:
                cmd = [journalctl_bin, "-n", str(clamped_lines), "--no-pager"]
                if since:
                    cmd.extend(["--since", str(since)])
                if service:
                    cmd.extend(["-u", str(service)])

                try:
                    res = subprocess.run(
                        cmd,
                        shell=False,
                        capture_output=True,
                        text=True,
                        timeout=self.DEFAULT_TIMEOUT_SECONDS,
                        check=False,
                    )
                    if res.returncode == 0 and res.stdout.strip():
                        raw_lines = [
                            line[: self.MAX_LINE_LENGTH]
                            for line in res.stdout.splitlines()
                            if line.strip()
                        ]
                    elif res.stderr.strip():
                        raw_lines.append(f"[WARN] journalctl stderr: {res.stderr.strip()}")
                except (subprocess.SubprocessError, OSError) as exc:
                    raw_lines.append(f"[ERROR] journalctl execution failed: {exc}")
            else:
                # Fallback to /var/log/syslog or /var/log/messages if accessible
                for fallback in [Path("/var/log/syslog"), Path("/var/log/messages")]:
                    if fallback.is_file():
                        return self.collect_system_logs(
                            since=since,
                            lines=clamped_lines,
                            service=service,
                            log_file=fallback,
                        )
                raw_lines.append("[INFO] No system log access or journalctl available.")

        if self.sanitize:
            return [sanitize_text(line) for line in raw_lines]
        return raw_lines

    def collect_git_commits(
        self,
        repo_path: Union[str, Path] = ".",
        count: int = 10,
        since: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Collect recent git commits from a repository with author, timestamp and subject."""
        clamped_count = min(max(1, count), 100)
        repo = Path(repo_path).resolve()
        commits: List[Dict[str, Any]] = []

        git_bin = shutil.which("git")
        if not git_bin or not (repo / ".git").exists():
            return commits

        cmd = [
            git_bin,
            "-C",
            str(repo),
            "log",
            f"-n{clamped_count}",
            "--pretty=format:%H|%an|%ad|%s",
            "--date=iso-strict",
        ]
        if since:
            cmd.append(f"--since={since}")

        try:
            res = subprocess.run(
                cmd,
                shell=False,
                capture_output=True,
                text=True,
                timeout=self.DEFAULT_TIMEOUT_SECONDS,
                check=False,
            )
            if res.returncode == 0 and res.stdout.strip():
                for line in res.stdout.splitlines():
                    parts = line.split("|", 3)
                    if len(parts) == 4:
                        commit_dict = {
                            "hash": parts[0].strip(),
                            "author": parts[1].strip(),
                            "date": parts[2].strip(),
                            "message": parts[3].strip(),
                        }
                        if self.sanitize:
                            commit_dict = sanitize_dict(commit_dict)
                        commits.append(commit_dict)
        except (subprocess.SubprocessError, OSError):
            pass

        return commits

    def collect_git_diffs(
        self,
        repo_path: Union[str, Path] = ".",
        commit_range: Optional[str] = "HEAD~1..HEAD",
    ) -> str:
        """Collect sanitized git diffs for a recent commit range or uncommitted state."""
        repo = Path(repo_path).resolve()
        git_bin = shutil.which("git")
        if not git_bin or not (repo / ".git").exists():
            return "[INFO] Not a git repository or git binary unavailable."

        cmd = [git_bin, "-C", str(repo), "diff"]
        if commit_range:
            cmd.append(str(commit_range))

        try:
            res = subprocess.run(
                cmd,
                shell=False,
                capture_output=True,
                text=True,
                timeout=self.DEFAULT_TIMEOUT_SECONDS,
                check=False,
            )
            raw_diff = res.stdout if res.returncode == 0 else (res.stderr or "")
            if not raw_diff.strip():
                raw_diff = "[INFO] No diffs found in the specified range."
        except (subprocess.SubprocessError, OSError) as exc:
            raw_diff = f"[ERROR] git diff execution failed: {exc}"

        return sanitize_text(raw_diff) if self.sanitize else raw_diff

    def collect_saturation_metrics(self) -> Dict[str, Any]:
        """Collect host saturation metrics (CPU load, memory, disk capacity)."""
        metrics: Dict[str, Any] = {}

        # 1. Load Averages & CPU Count
        try:
            load1, load5, load15 = os.getloadavg()
            cpu_count = os.cpu_count() or 1
            metrics["load_avg_1m"] = round(load1, 2)
            metrics["load_avg_5m"] = round(load5, 2)
            metrics["load_avg_15m"] = round(load15, 2)
            metrics["cpu_count"] = cpu_count
            metrics["cpu_saturation_pct"] = round((load1 / cpu_count) * 100, 1)
        except (OSError, AttributeError):
            metrics["load_avg_1m"] = 0.0
            metrics["load_avg_5m"] = 0.0
            metrics["load_avg_15m"] = 0.0
            metrics["cpu_count"] = 1
            metrics["cpu_saturation_pct"] = 0.0

        # 2. Disk Usage
        try:
            disk = shutil.disk_usage("/")
            metrics["disk_total_gb"] = round(disk.total / (1024**3), 2)
            metrics["disk_used_gb"] = round(disk.used / (1024**3), 2)
            metrics["disk_free_gb"] = round(disk.free / (1024**3), 2)
            metrics["disk_percent_used"] = round((disk.used / disk.total) * 100, 1)
        except OSError:
            metrics["disk_total_gb"] = 0.0
            metrics["disk_used_gb"] = 0.0
            metrics["disk_free_gb"] = 0.0
            metrics["disk_percent_used"] = 0.0

        # 3. Memory Information via /proc/meminfo if on Linux
        meminfo_path = Path("/proc/meminfo")
        if meminfo_path.is_file():
            try:
                mem_data: Dict[str, int] = {}
                with meminfo_path.open("r", encoding="utf-8") as f:
                    for line in f:
                        parts = line.split(":")
                        if len(parts) == 2:
                            key = parts[0].strip()
                            val_str = parts[1].strip().split()[0]
                            if val_str.isdigit():
                                mem_data[key] = int(val_str)
                total_kb = mem_data.get("MemTotal", 0)
                avail_kb = mem_data.get("MemAvailable", mem_data.get("MemFree", 0))
                used_kb = max(0, total_kb - avail_kb)
                if total_kb > 0:
                    metrics["memory_total_mb"] = round(total_kb / 1024, 1)
                    metrics["memory_available_mb"] = round(avail_kb / 1024, 1)
                    metrics["memory_used_mb"] = round(used_kb / 1024, 1)
                    metrics["memory_percent_used"] = round((used_kb / total_kb) * 100, 1)
            except OSError:
                pass

        return sanitize_dict(metrics) if self.sanitize else metrics

    def collect_all(
        self,
        service: Optional[str] = None,
        repo_path: Union[str, Path] = ".",
        since: Optional[str] = None,
        lines: int = 100,
        commit_range: Optional[str] = "HEAD~1..HEAD",
    ) -> Dict[str, Any]:
        """Bundle all system logs, git commits, configuration diffs, and saturation metrics."""
        evidence_bundle = {
            "system_logs": self.collect_system_logs(since=since, lines=lines, service=service),
            "git_commits": self.collect_git_commits(repo_path=repo_path, count=10, since=since),
            "git_diffs": self.collect_git_diffs(repo_path=repo_path, commit_range=commit_range),
            "saturation_metrics": self.collect_saturation_metrics(),
        }
        return sanitize_dict(evidence_bundle) if self.sanitize else evidence_bundle
