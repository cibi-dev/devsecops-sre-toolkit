import os
import shutil
import subprocess
from pathlib import Path
from unittest.mock import MagicMock, mock_open, patch

import pytest
from postmortem.collector import EvidenceCollector


def test_collect_system_logs_from_file(tmp_path):
    log_file = tmp_path / "system.log"
    log_file.write_text(
        "2026-08-27 10:00:00 server app[123]: Started service\n"
        "2026-08-27 10:01:00 server app[123]: Connect to db with password=SuperSecretPassword123!\n"
        "2026-08-27 10:02:00 server app[123]: Out of memory panic\n",
        encoding="utf-8",
    )

    collector = EvidenceCollector(sanitize=True)
    logs = collector.collect_system_logs(log_file=log_file, lines=10)

    assert len(logs) == 3
    assert "Started service" in logs[0]
    assert "password=[REDACTED]" in logs[1]
    assert "SuperSecretPassword123!" not in logs[1]


def test_collect_system_logs_file_not_found(tmp_path):
    collector = EvidenceCollector()
    missing_file = tmp_path / "missing.log"
    logs = collector.collect_system_logs(log_file=missing_file)
    assert len(logs) == 1
    assert "[WARN] Log file not found" in logs[0]


def test_collect_system_logs_journalctl_mock():
    collector = EvidenceCollector(sanitize=True)
    mock_res = MagicMock()
    mock_res.returncode = 0
    mock_res.stdout = "Aug 27 14:00:00 host nginx[99]: worker error Bearer secret_token_123456\nAug 27 14:00:01 host nginx[99]: healthy\n"
    mock_res.stderr = ""

    with patch("shutil.which", return_value="/usr/bin/journalctl"), patch("subprocess.run", return_value=mock_res):
        logs = collector.collect_system_logs(lines=50, service="nginx", since="1 hour ago")

    assert len(logs) == 2
    assert "secret_token_123456" not in logs[0]
    assert "[REDACTED]" in logs[0]
    assert "healthy" in logs[1]


def test_collect_system_logs_journalctl_stderr():
    collector = EvidenceCollector()
    mock_res = MagicMock()
    mock_res.returncode = 1
    mock_res.stdout = ""
    mock_res.stderr = "Permission denied opening journal"

    with patch("shutil.which", return_value="/usr/bin/journalctl"), patch("subprocess.run", return_value=mock_res):
        logs = collector.collect_system_logs(lines=10)
    assert any("journalctl stderr" in line for line in logs)


def test_collect_system_logs_journalctl_error():
    collector = EvidenceCollector()
    with patch("shutil.which", return_value="/usr/bin/journalctl"), \
         patch("subprocess.run", side_effect=subprocess.SubprocessError("Timeout expired")):
        logs = collector.collect_system_logs(lines=10)
    assert any("journalctl execution failed" in line for line in logs)


def test_collect_system_logs_fallback_syslog(tmp_path):
    collector = EvidenceCollector()
    mock_syslog = tmp_path / "syslog"
    mock_syslog.write_text("Aug 27 12:00:00 kernel: OOM killer invoked\n", encoding="utf-8")

    with patch("shutil.which", return_value=None), \
         patch("pathlib.Path.is_file", side_effect=lambda: True):
        logs = collector.collect_system_logs(log_file=mock_syslog)
    assert any("OOM killer" in line for line in logs)


def test_collect_system_logs_no_logs_available():
    collector = EvidenceCollector()
    with patch("shutil.which", return_value=None), \
         patch("pathlib.Path.is_file", return_value=False):
        logs = collector.collect_system_logs()
    assert any("No system log access" in line for line in logs)


def test_collect_git_commits(tmp_path):
    repo_dir = tmp_path / "test_repo"
    repo_dir.mkdir()
    (repo_dir / ".git").mkdir()

    mock_res = MagicMock()
    mock_res.returncode = 0
    mock_res.stdout = (
        "a1b2c3d4e5f6|dev-lead <lead@company.com>|2026-08-27T10:00:00Z|feat: add auth with api_key=secret998877\n"
        "1234567890ab|sre-engineer <sre@company.com>|2026-08-27T09:30:00Z|fix: connection pool timeout\n"
    )

    collector = EvidenceCollector(sanitize=True)
    with patch("shutil.which", return_value="/usr/bin/git"), patch("subprocess.run", return_value=mock_res):
        commits = collector.collect_git_commits(repo_path=repo_dir, count=5, since="1 day ago")

    assert len(commits) == 2
    assert commits[0]["hash"] == "a1b2c3d4e5f6"
    assert "secret998877" not in commits[0]["message"]
    assert "api_key=[REDACTED]" in commits[0]["message"]
    assert "[REDACTED]" in commits[0]["author"]


def test_collect_git_diffs(tmp_path):
    repo_dir = tmp_path / "test_repo"
    repo_dir.mkdir()
    (repo_dir / ".git").mkdir()

    mock_res = MagicMock()
    mock_res.returncode = 0
    mock_res.stdout = "--- a/config.yaml\n+++ b/config.yaml\n- timeout: 30\n+ timeout: 5\n+ api_key: 'sk_live_123456789'"

    collector = EvidenceCollector(sanitize=True)
    with patch("shutil.which", return_value="/usr/bin/git"), patch("subprocess.run", return_value=mock_res):
        diff = collector.collect_git_diffs(repo_path=repo_dir, commit_range="HEAD~1..HEAD")

    assert "timeout: 5" in diff
    assert "sk_live_123456789" not in diff
    assert "[REDACTED]" in diff


def test_collect_git_diffs_empty_and_error(tmp_path):
    repo_dir = tmp_path / "test_repo"
    repo_dir.mkdir()
    (repo_dir / ".git").mkdir()

    collector = EvidenceCollector()
    mock_res = MagicMock()
    mock_res.returncode = 0
    mock_res.stdout = ""

    with patch("shutil.which", return_value="/usr/bin/git"), patch("subprocess.run", return_value=mock_res):
        diff = collector.collect_git_diffs(repo_path=repo_dir)
    assert "[INFO] No diffs found" in diff

    with patch("shutil.which", return_value="/usr/bin/git"), \
         patch("subprocess.run", side_effect=subprocess.SubprocessError("git error")):
        diff_err = collector.collect_git_diffs(repo_path=repo_dir)
    assert "[ERROR] git diff execution failed" in diff_err


def test_collect_git_diffs_not_a_repo(tmp_path):
    collector = EvidenceCollector()
    diff = collector.collect_git_diffs(repo_path=tmp_path)
    assert "[INFO] Not a git repository" in diff


def test_collect_saturation_metrics():
    collector = EvidenceCollector()
    metrics = collector.collect_saturation_metrics()

    assert "load_avg_1m" in metrics
    assert "cpu_count" in metrics
    assert "disk_total_gb" in metrics
    assert "disk_percent_used" in metrics
    assert isinstance(metrics["cpu_count"], int)
    assert metrics["cpu_count"] >= 1


def test_collect_saturation_metrics_mocked_proc():
    collector = EvidenceCollector(sanitize=False)
    fake_meminfo = "MemTotal:       16384000 kB\nMemFree:         4096000 kB\nMemAvailable:    8192000 kB\n"

    with patch("pathlib.Path.is_file", return_value=True), \
         patch("pathlib.Path.open", mock_open(read_data=fake_meminfo)):
        metrics = collector.collect_saturation_metrics()
        assert "memory_total_mb" in metrics
        assert metrics["memory_total_mb"] > 0
        assert metrics["memory_percent_used"] == 50.0


def test_collect_all_bundle(tmp_path):
    collector = EvidenceCollector(sanitize=True)
    with patch.object(collector, "collect_system_logs", return_value=["log line 1"]), \
         patch.object(collector, "collect_git_commits", return_value=[{"hash": "abc"}]), \
         patch.object(collector, "collect_git_diffs", return_value="diff text"), \
         patch.object(collector, "collect_saturation_metrics", return_value={"load_avg_1m": 0.5}):
        bundle = collector.collect_all(repo_path=tmp_path)

    assert "system_logs" in bundle
    assert "git_commits" in bundle
    assert "git_diffs" in bundle
    assert "saturation_metrics" in bundle
    assert bundle["system_logs"] == ["log line 1"]


def test_collect_system_logs_file_io_error(tmp_path):
    collector = EvidenceCollector()
    test_file = tmp_path / "protected.log"
    test_file.touch()

    with patch("pathlib.Path.open", side_effect=OSError("Permission denied")):
        logs = collector.collect_system_logs(log_file=test_file)
    assert any("Failed to read log file" in l for l in logs)


def test_collect_git_commits_exception(tmp_path):
    repo_dir = tmp_path / "test_repo"
    repo_dir.mkdir()
    (repo_dir / ".git").mkdir()

    collector = EvidenceCollector()
    with patch("shutil.which", return_value="/usr/bin/git"), \
         patch("subprocess.run", side_effect=subprocess.SubprocessError("Git crashed")):
        commits = collector.collect_git_commits(repo_path=repo_dir)
    assert commits == []


def test_collect_saturation_metrics_errors():
    collector = EvidenceCollector()
    with patch("os.getloadavg", side_effect=OSError("Loadavg unsupported")), \
         patch("shutil.disk_usage", side_effect=OSError("Disk unsupported")):
        metrics = collector.collect_saturation_metrics()
        assert metrics["load_avg_1m"] == 0.0
        assert metrics["disk_total_gb"] == 0.0
