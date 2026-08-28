"""Unit tests for AlertEvaluator, rule parsing, debounce, and state transitions."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from exporter.alert_evaluator import (
    AlertEvaluator,
    AlertInstance,
    AlertRuleModel,
    AlertSeverity,
    AlertState,
    parse_duration_seconds,
)


def test_parse_duration_units():
    assert parse_duration_seconds("500ms") == 0.5
    assert parse_duration_seconds("30s") == 30.0
    assert parse_duration_seconds("5m") == 300.0
    assert parse_duration_seconds("2h") == 7200.0
    assert parse_duration_seconds("1d") == 86400.0
    assert parse_duration_seconds(45) == 45.0
    assert parse_duration_seconds(12.5) == 12.5
    assert parse_duration_seconds("") == 0.0

    with pytest.raises(ValueError):
        parse_duration_seconds("invalid_duration")


def test_alert_rule_validation():
    rule = AlertRuleModel(
        alert="HighMemory",
        expr="node_memory_used_percent > 85",
        for_duration="1m",
        severity="critical",
        labels={"tier": "backend"},
        annotations={"summary": "Memory is high at {{ $value }}%"},
    )
    assert rule.alert == "HighMemory"
    assert rule.for_duration == "1m"
    assert rule.severity == "critical"

    # Missing operator raises error
    with pytest.raises(ValidationError):
        AlertRuleModel(alert="BadRule", expr="node_memory_used_percent")


def test_comparison_operators():
    rules_and_metrics = [
        ("node_cpu > 80", 85.0, True),
        ("node_cpu > 80", 75.0, False),
        ("node_cpu < 20", 15.0, True),
        ("node_cpu < 20", 25.0, False),
        ("node_cpu >= 80", 80.0, True),
        ("node_cpu >= 80", 79.9, False),
        ("node_cpu <= 50", 50.0, True),
        ("node_cpu <= 50", 50.1, False),
        ("node_cpu == 100", 100.0, True),
        ("node_cpu == 100", 99.0, False),
        ("node_cpu != 0", 10.0, True),
        ("node_cpu != 0", 0.0, False),
    ]

    for expr, val, expected in rules_and_metrics:
        rule = AlertRuleModel(alert="TestOp", expr=expr)
        instance = AlertInstance(rule=rule)
        assert instance.evaluate_condition(val) == expected, f"Failed on {expr} with val {val}"


def test_debounce_and_state_lifecycle():
    yaml_config = """
    groups:
      - name: host_alerts
        rules:
          - alert: HighCPU
            expr: "node_cpu_usage_percent > 90"
            for: "30s"
            severity: "critical"
            labels:
              team: sre
            annotations:
              description: "CPU breached limit at {{ $value }}% for team {{ $labels.team }}"
    """

    evaluator = AlertEvaluator(yaml_config)
    assert len(evaluator.alert_instances) == 1

    t0 = 1000.0

    # Cycle 1 (t=0): Breaching -> becomes PENDING
    alerts = evaluator.evaluate({"node_cpu_usage_percent": 95.0}, current_time=t0)
    assert alerts[0].state == AlertState.PENDING
    assert len(evaluator.get_firing_alerts()) == 0
    assert len(evaluator.get_pending_alerts()) == 1

    # Cycle 2 (t=15): Breaching -> still PENDING (15s < 30s)
    alerts = evaluator.evaluate({"node_cpu_usage_percent": 95.0}, current_time=t0 + 15.0)
    assert alerts[0].state == AlertState.PENDING

    # Cycle 3 (t=30): Breaching for >= 30s -> transitions to FIRING
    alerts = evaluator.evaluate({"node_cpu_usage_percent": 95.0}, current_time=t0 + 30.0)
    assert alerts[0].state == AlertState.FIRING
    assert len(evaluator.get_firing_alerts()) == 1
    assert alerts[0].firing_since == t0 + 30.0

    # Test annotation rendering
    rendered = alerts[0].render_annotations()
    assert "CPU breached limit at 95% for team sre" in rendered["description"]

    # Cycle 4 (t=45): Recovery -> transitions to RESOLVED
    alerts = evaluator.evaluate({"node_cpu_usage_percent": 50.0}, current_time=t0 + 45.0)
    assert alerts[0].state == AlertState.RESOLVED
    assert len(evaluator.get_resolved_alerts()) == 1
    assert alerts[0].resolved_at == t0 + 45.0

    # Cycle 5 (t=60): Still recovered -> transitions to INACTIVE
    alerts = evaluator.evaluate({"node_cpu_usage_percent": 50.0}, current_time=t0 + 60.0)
    assert alerts[0].state == AlertState.INACTIVE


def test_immediate_alert_zero_for_duration():
    rule = AlertRuleModel(alert="InstantAlert", expr="node_load > 10.0", for_duration="0s")
    evaluator = AlertEvaluator()
    evaluator.add_rule(rule)

    # Immediately transitions to FIRING when for_duration = 0
    alerts = evaluator.evaluate({"node_load": 15.0}, current_time=100.0)
    assert alerts[0].state == AlertState.FIRING


def test_load_config_from_dict_and_invalid_type():
    cfg_dict = {
        "groups": [
            {
                "name": "direct_dict_group",
                "rules": [
                    {
                        "alert": "DirectDictAlert",
                        "expr": "node_load1 > 1.0",
                        "for": "5s",
                        "severity": "warning",
                    }
                ],
            }
        ]
    }
    evaluator = AlertEvaluator(cfg_dict)
    assert len(evaluator.alert_instances) == 1
    assert evaluator.alert_instances[0].rule.alert == "DirectDictAlert"

    with pytest.raises(TypeError, match="Unsupported config type"):
        AlertEvaluator(12345)  # type: ignore[arg-type]


def test_missing_metric_handled_gracefully():
    rule = AlertRuleModel(alert="MissingMetricRule", expr="non_existent_metric > 100")
    evaluator = AlertEvaluator()
    evaluator.add_rule(rule)

    alerts = evaluator.evaluate({"node_cpu": 50.0}, current_time=100.0)
    assert alerts[0].state == AlertState.INACTIVE
    assert alerts[0].current_value is None
