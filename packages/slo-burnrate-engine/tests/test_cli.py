"""Tests for CLI interface."""

import json
import pytest
from slo.cli import main


def test_cli_help(capsys):
    with pytest.raises(SystemExit) as exc_info:
        main(["--help"])
    assert exc_info.value.code == 0
    captured = capsys.readouterr()
    assert "usage: slo-engine" in captured.out


def test_cli_calculate_events(capsys):
    ret = main(["calculate", "--slo", "0.999", "--good", "99900", "--total", "100000"])
    assert ret == 0
    captured = capsys.readouterr()
    assert "SLO & SLI Calculation" in captured.out
    assert "99.900%" in captured.out
    assert "Budget Consumed:     100.00%" in captured.out


def test_cli_calculate_json(capsys):
    ret = main(["calculate", "--slo", "0.999", "--good", "99950", "--total", "100000", "--format", "json"])
    assert ret == 0
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert data["sli"]["good_events"] == 99950
    assert data["error_budget"]["consumed_budget_percent"] == 50.0


def test_cli_calculate_file(tmp_path, capsys):
    csv_file = tmp_path / "events.csv"
    csv_file.write_text("timestamp,good_events,total_events\n2026-08-27 10:00:00,999,1000\n2026-08-27 11:00:00,999,1000\n")

    ret = main(["calculate", "--slo", "0.999", "--file", str(csv_file)])
    assert ret == 0
    captured = capsys.readouterr()
    assert "Total Events:        2,000" in captured.out
    assert "Good Events:         1,998" in captured.out


def test_cli_calculate_json_file(tmp_path, capsys):
    json_file = tmp_path / "events.json"
    json_file.write_text('[{"timestamp": "2026-08-27 10:00:00", "good_events": 999, "total_events": 1000}]')

    ret = main(["calculate", "--slo", "0.999", "--file", str(json_file), "--format", "json"])
    assert ret == 0
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert data["sli"]["good_events"] == 999


def test_cli_evaluate_burnrate(capsys):
    ret = main(["evaluate-burnrate", "--slo", "0.999", "--good", "9856", "--total", "10000", "--window", "1h"])
    assert ret == 0
    captured = capsys.readouterr()
    assert "Burn Rate:             14.40x" in captured.out
    assert "50.00 hours" in captured.out


def test_cli_evaluate_burnrate_json(capsys):
    ret = main(["evaluate-burnrate", "--slo", "0.999", "--good", "9940", "--total", "10000", "--window", "6h", "--format", "json"])
    assert ret == 0
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert data["burn_rate"] == 6.0
    assert data["budget_consumed_in_window_percent"] == 5.0


def test_cli_evaluate_burnrate_to_file(tmp_path):
    out_file = tmp_path / "br.txt"
    ret = main(["evaluate-burnrate", "--slo", "0.999", "--good", "9856", "--total", "10000", "--output", str(out_file)])
    assert ret == 0
    assert out_file.exists()
    assert "14.40x" in out_file.read_text()


def test_cli_budget_status(capsys):
    ret = main(["budget-status", "--slo", "0.999", "--service", "payment", "--good", "99500", "--total", "100000"])
    assert ret == 0
    captured = capsys.readouterr()
    assert "30-Day Error Budget Status" in captured.out
    assert "payment" in captured.out


def test_cli_budget_status_file(tmp_path, capsys):
    csv_file = tmp_path / "events.csv"
    csv_file.write_text("timestamp,good_events,total_events\n2026-08-27 10:00:00,999,1000\n")

    ret = main(["budget-status", "--slo", "0.999", "--file", str(csv_file), "--format", "json"])
    assert ret == 0
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert "error_budget" in data


def test_cli_budget_status_missing_args(capsys):
    ret = main(["budget-status", "--slo", "0.999"])
    assert ret == 1
    captured = capsys.readouterr()
    assert "Error:" in captured.err


def test_cli_report_markdown(capsys):
    ret = main(["report", "--slo", "0.999", "--service", "checkout", "--good", "99900", "--total", "100000", "--format", "markdown"])
    assert ret == 0
    captured = capsys.readouterr()
    assert "# 📊 SRE Reliability & SLO Report: `checkout`" in captured.out
    assert "Multi-Window Multi-Burn-Rate Alerts" in captured.out


def test_cli_report_openmetrics(capsys):
    ret = main(["report", "--slo", "0.999", "--service", "checkout", "--good", "99900", "--total", "100000", "--format", "openmetrics"])
    assert ret == 0
    captured = capsys.readouterr()
    assert "# HELP slo_target_ratio" in captured.out
    assert 'slo_target_ratio{service="checkout",slo="checkout-availability"} 0.999000' in captured.out


def test_cli_report_json(capsys):
    ret = main(["report", "--slo", "0.999", "--service", "checkout", "--good", "99900", "--total", "100000", "--format", "json"])
    assert ret == 0
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert "error_budget" in data
    assert "burn_rates" in data


def test_cli_report_file(tmp_path, capsys):
    csv_file = tmp_path / "events.csv"
    csv_file.write_text("timestamp,good_events,total_events\n2026-08-27 10:00:00,999,1000\n")

    ret = main(["report", "--slo", "0.999", "--file", str(csv_file), "--format", "markdown"])
    assert ret == 0
    captured = capsys.readouterr()
    assert "SRE Reliability & SLO Report" in captured.out


def test_cli_report_to_file(tmp_path):
    out_file = tmp_path / "report.md"
    ret = main(["report", "--slo", "0.999", "--service", "auth", "--good", "99900", "--total", "100000", "--output", str(out_file)])
    assert ret == 0
    assert out_file.exists()
    content = out_file.read_text()
    assert "auth" in content


def test_cli_report_invalid_format(capsys):
    with pytest.raises(SystemExit):
        main(["report", "--slo", "0.999", "--good", "100", "--total", "100", "--format", "invalid_fmt"])


def test_cli_missing_args(capsys):
    ret = main(["calculate", "--slo", "0.999"])
    assert ret == 1
    captured = capsys.readouterr()
    assert "Error:" in captured.err

    ret_no_subcmd = main([])
    assert ret_no_subcmd == 1
