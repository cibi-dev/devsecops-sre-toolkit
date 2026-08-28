"""Tests for Reporting module (Markdown, OpenMetrics, and JSON formats)."""

import json
import pytest

from slo.burn_rate import calculate_burn_rate
from slo.error_budget import ErrorBudgetManager, SLODefinition
from slo.multi_window import MultiWindowAlertEngine
from slo.reporter import (
    SLOReporter,
    generate_json_report,
    generate_markdown_report,
    generate_openmetrics_metrics,
    redact_data_structures,
    redact_sensitive_text,
)


@pytest.fixture
def sample_report_data():
    slo = SLODefinition(name="billing-api", service="billing-service", target=0.999, window_days=30)
    mgr = ErrorBudgetManager(slo)
    eb_res = mgr.calculate_from_events(good_events=999000, total_events=1000000)

    br1 = calculate_burn_rate(good_events=9856, total_events=10000, target_slo=0.999, window="1h")
    br2 = calculate_burn_rate(good_events=9990, total_events=10000, target_slo=0.999, window="6h")

    engine = MultiWindowAlertEngine(slo)
    alerts = engine.evaluate_from_burn_rates({"1h": br1.burn_rate, "5m": br1.burn_rate})

    return eb_res, [br1, br2], alerts


def test_markdown_report_generation(sample_report_data):
    eb_res, burn_rates, alerts = sample_report_data
    reporter = SLOReporter(eb_res, burn_rates, alerts)
    md = reporter.to_markdown()

    assert "# 📊 SRE Reliability & SLO Report: `billing-service`" in md
    assert "99.9000%" in md
    assert "Quantitative Error Budget Health" in md
    assert "Burn Rate & Time-to-Exhaustion Projections" in md
    assert "Google SRE Multi-Window Multi-Burn-Rate Alerts" in md
    assert "Google SRE Recommendation" in md
    assert "1h-5m-14.4x-page" in md


def test_openmetrics_export(sample_report_data):
    eb_res, burn_rates, alerts = sample_report_data
    reporter = SLOReporter(eb_res, burn_rates, alerts)
    metrics = reporter.to_openmetrics()

    assert "# HELP slo_target_ratio" in metrics
    assert "# TYPE slo_target_ratio gauge"
    assert 'slo_target_ratio{service="billing-service",slo="billing-api"} 0.999000' in metrics
    assert "# HELP sli_current_ratio" in metrics
    assert "# HELP slo_error_budget_consumed_events" in metrics
    assert "# HELP slo_burn_rate" in metrics
    assert "# HELP slo_alert_firing" in metrics
    assert metrics.endswith("# EOF\n") or "# EOF" in metrics


def test_json_report_generation(sample_report_data):
    eb_res, burn_rates, alerts = sample_report_data
    reporter = SLOReporter(eb_res, burn_rates, alerts)
    json_str = reporter.to_json()

    data = json.loads(json_str)
    assert "error_budget" in data
    assert "burn_rates" in data
    assert "alerts" in data
    assert data["error_budget"]["service"] == "billing-service"
    assert len(data["burn_rates"]) == 2


def test_redact_sensitive_text():
    raw_text = "API error connecting to service with api_key=secret_123456789 and Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
    sanitized = redact_sensitive_text(raw_text)
    assert "secret_123456789" not in sanitized
    assert "Bearer [REDACTED]" in sanitized

    gh_text = "token: ghp_1234567890abcdefghijklmnopqrstuvwxyz"
    sanitized_gh = redact_sensitive_text(gh_text)
    assert "ghp_1234567890" not in sanitized_gh
    assert "[REDACTED_GH_TOKEN]" in sanitized_gh

    aws_text = "AWS key: AKIAIOSFODNN7EXAMPLE"
    sanitized_aws = redact_sensitive_text(aws_text)
    assert "AKIAIOSFODNN7EXAMPLE" not in sanitized_aws
    assert "[REDACTED_AWS_KEY]" in sanitized_aws


def test_redact_data_structures():
    data = {
        "service": "auth-service",
        "api_token": "super_secret_token_123",
        "config": {
            "db_password": "mypassword123",
            "host": "localhost",
        },
        "tags": ["env=prod", "secret_key=xyz987"],
    }
    redacted = redact_data_structures(data)
    assert redacted["api_token"] == "[REDACTED]"
    assert redacted["config"]["db_password"] == "[REDACTED]"
    assert redacted["config"]["host"] == "localhost"
    assert "xyz987" not in str(redacted["tags"])
    assert "[REDACTED]" in str(redacted["tags"])


def test_helper_functions(sample_report_data):
    eb_res, burn_rates, alerts = sample_report_data
    md = generate_markdown_report(eb_res, burn_rates, alerts)
    assert "billing-service" in md

    om = generate_openmetrics_metrics(eb_res, burn_rates, alerts)
    assert "slo_target_ratio" in om

    js = generate_json_report(eb_res, burn_rates, alerts)
    assert "billing-service" in js
