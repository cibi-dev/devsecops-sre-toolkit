import json
from pathlib import Path
from unittest.mock import patch
import pytest
from postmortem.cli import main


def test_cli_help(capsys):
    ret = main([])
    assert ret == 0
    captured = capsys.readouterr()
    assert "Automated Blameless Post-Mortem" in captured.out


def test_cli_list_empty(tmp_path, capsys):
    db_file = str(tmp_path / "empty.db")
    ret = main(["list", "--db-path", db_file])
    assert ret == 0
    captured = capsys.readouterr()
    assert "No incident post-mortems found" in captured.out


def test_cli_record_and_list(tmp_path, capsys):
    db_file = str(tmp_path / "cli_test.db")

    # 1. Record incident with evidence collection flag
    ret = main([
        "record",
        "--id", "INC-CLI-01",
        "--title", "Auth Service 503 Spike",
        "--severity", "SEV-1",
        "--summary", "Service unavailable due to replica drift",
        "--collect-evidence",
        "--db-path", db_file,
    ])
    assert ret == 0
    captured = capsys.readouterr()
    assert "Incident recorded successfully" in captured.out

    # 2. List incidents
    ret = main(["list", "--db-path", db_file])
    assert ret == 0
    captured = capsys.readouterr()
    assert "INC-CLI-01" in captured.out
    assert "SEV-1" in captured.out


def test_cli_timeline_and_add_event(tmp_path, capsys):
    db_file = str(tmp_path / "cli_test.db")

    main([
        "record",
        "--id", "INC-CLI-02",
        "--title", "Cache Eviction Flap",
        "--summary", "Redis memory max exceeded",
        "--db-path", db_file,
    ])

    # View initial timeline
    ret = main(["timeline", "--incident-id", "INC-CLI-02", "--db-path", db_file])
    assert ret == 0
    captured = capsys.readouterr()
    assert "Timeline for Incident: INC-CLI-02" in captured.out

    # Add milestone event
    ret = main([
        "timeline",
        "--incident-id", "INC-CLI-02",
        "--add-event",
        "--timestamp", "2026-08-27T11:00:00Z",
        "--event-type", "MITIGATION_ATTEMPT",
        "--desc", "Flushed stale session keys",
        "--db-path", db_file,
    ])
    assert ret == 0
    captured = capsys.readouterr()
    assert "Event added to timeline" in captured.out


def test_cli_metrics(tmp_path, capsys):
    db_file = str(tmp_path / "cli_test.db")

    main([
        "record",
        "--id", "INC-CLI-03",
        "--title", "Database Deadlock",
        "--summary", "Deadlock under high write pressure",
        "--db-path", db_file,
    ])

    ret = main(["metrics", "--incident-id", "INC-CLI-03", "--db-path", db_file])
    assert ret == 0
    captured = capsys.readouterr()
    assert "SRE Metrics for Incident: INC-CLI-03" in captured.out
    assert "Time to Detect (TTD)" in captured.out
    assert "Time to Resolve (MTTR)" in captured.out


def test_cli_generate_markdown_and_json(tmp_path, capsys):
    db_file = str(tmp_path / "cli_test.db")
    out_md = tmp_path / "report.md"
    out_json = tmp_path / "report.json"

    main([
        "record",
        "--id", "INC-CLI-04",
        "--title", "Kafka Consumer Lag Surge",
        "--summary", "Partition rebalance triggered lag spike",
        "--db-path", db_file,
    ])

    # Generate Markdown to file
    ret = main(["generate", "--incident-id", "INC-CLI-04", "--output", str(out_md), "--db-path", db_file])
    assert ret == 0
    assert out_md.is_file()
    assert "# 📋 Post-Mortem Report:" in out_md.read_text(encoding="utf-8")

    # Generate Markdown to stdout
    ret_stdout = main(["generate", "--incident-id", "INC-CLI-04", "--db-path", db_file])
    assert ret_stdout == 0
    captured = capsys.readouterr()
    assert "# 📋 Post-Mortem Report:" in captured.out

    # Generate JSON to file
    ret = main(["generate", "--incident-id", "INC-CLI-04", "--format", "json", "--output", str(out_json), "--db-path", db_file])
    assert ret == 0
    assert out_json.is_file()
    data = json.loads(out_json.read_text(encoding="utf-8"))
    assert data["incident_id"] == "INC-CLI-04"

    # Generate from input file
    ret_from_file = main(["generate", "--input-file", str(out_json), "--output", str(tmp_path / "gen_file.md")])
    assert ret_from_file == 0


def test_cli_generate_input_file_missing(tmp_path):
    ret = main(["generate", "--input-file", str(tmp_path / "missing.json")])
    assert ret == 1


def test_cli_collect(tmp_path, capsys):
    # Output to file
    out_file = tmp_path / "evidence.json"
    ret = main(["collect", "--repo", ".", "--lines", "10", "--output", str(out_file)])
    assert ret == 0
    assert out_file.is_file()
    evidence_data = json.loads(out_file.read_text(encoding="utf-8"))
    assert "saturation_metrics" in evidence_data
    assert "system_logs" in evidence_data

    # Output to stdout
    ret2 = main(["collect", "--repo", ".", "--lines", "5"])
    assert ret2 == 0
    captured = capsys.readouterr()
    assert "saturation_metrics" in captured.out


def test_cli_sanitize(tmp_path, capsys):
    # 1. Text flag to stdout
    ret = main(["sanitize", "--text", "Bearer secret_test_token_123456"])
    assert ret == 0
    captured = capsys.readouterr()
    assert "[REDACTED]" in captured.out
    assert "secret_test_token_123456" not in captured.out

    # 2. File input & output
    in_file = tmp_path / "raw.log"
    out_file = tmp_path / "sanitized.log"
    in_file.write_text("aws_key: AKIA9988776655443322", encoding="utf-8")

    ret = main(["sanitize", "--file", str(in_file), "--output", str(out_file)])
    assert ret == 0
    assert out_file.is_file()
    assert "AKIA9988776655443322" not in out_file.read_text(encoding="utf-8")
    assert "[REDACTED]" in out_file.read_text(encoding="utf-8")


def test_cli_sanitize_stdin(capsys):
    with patch("sys.stdin.isatty", return_value=False), \
         patch("sys.stdin.read", return_value="api_key='sk_live_123456789'"):
        ret = main(["sanitize"])
        assert ret == 0
        captured = capsys.readouterr()
        assert "[REDACTED]" in captured.out


def test_cli_sanitize_missing_file_or_input(tmp_path):
    ret1 = main(["sanitize", "--file", str(tmp_path / "missing.log")])
    assert ret1 == 1

    with patch("sys.stdin.isatty", return_value=True):
        ret2 = main(["sanitize"])
        assert ret2 == 1


def test_cli_missing_incident_errors(tmp_path, capsys):
    db_file = str(tmp_path / "cli_test.db")

    ret_tl = main(["timeline", "--incident-id", "NON-EXISTENT", "--db-path", db_file])
    assert ret_tl == 1

    ret_m = main(["metrics", "--incident-id", "NON-EXISTENT", "--db-path", db_file])
    assert ret_m == 1

    ret_gen = main(["generate", "--incident-id", "NON-EXISTENT", "--db-path", db_file])
    assert ret_gen == 1

    ret_gen_no_args = main(["generate"])
    assert ret_gen_no_args == 1
