"""Unit tests for OpenMetrics and Prometheus formatters and parsers."""

from __future__ import annotations

import json
import math

import pytest

from exporter.formatter import OpenMetricsFormatter
from exporter.metrics_collector import MetricFamily, MetricSample, MetricType


def test_format_help_and_type():
    fam = MetricFamily(
        name="http_requests_total",
        help_text='Total HTTP requests received with "special" chars and\nnewlines.',
        metric_type=MetricType.COUNTER,
    )
    fam.add_sample("http_requests_total", 42.0, {"method": "GET", "handler": "/api"})

    output = OpenMetricsFormatter.format_openmetrics([fam])
    assert '# HELP http_requests_total Total HTTP requests received with "special" chars and\\nnewlines.' in output
    assert "# TYPE http_requests_total counter" in output
    assert 'http_requests_total{handler="/api",method="GET"} 42' in output
    assert output.endswith("# EOF\n")


def test_label_escaping():
    fam = MetricFamily(
        name="test_labels",
        help_text="Testing label escaping",
        metric_type=MetricType.GAUGE,
    )
    fam.add_sample(
        "test_labels",
        1.0,
        {"quote": 'a"b', "slash": "a\\b", "newline": "a\nb"},
    )
    output = OpenMetricsFormatter.format_openmetrics([fam])
    assert 'newline="a\\nb"' in output
    assert 'quote="a\\"b"' in output
    assert 'slash="a\\\\b"' in output


def test_special_float_values():
    fam = MetricFamily(
        name="float_extremes",
        help_text="Testing special float values",
        metric_type=MetricType.GAUGE,
    )
    fam.add_sample("float_extremes", float("nan"), {"type": "nan"})
    fam.add_sample("float_extremes", float("inf"), {"type": "pos_inf"})
    fam.add_sample("float_extremes", float("-inf"), {"type": "neg_inf"})
    fam.add_sample("float_extremes", 3.14159, {"type": "pi"})

    output = OpenMetricsFormatter.format_openmetrics([fam])
    assert 'float_extremes{type="nan"} nan' in output
    assert 'float_extremes{type="pos_inf"} +Inf' in output
    assert 'float_extremes{type="neg_inf"} -Inf' in output
    assert 'float_extremes{type="pi"} 3.14159' in output


def test_timestamp_formatting():
    sample_om = MetricSample("test_ts", 100.0, timestamp=1700000000.5)
    formatted_om = OpenMetricsFormatter.format_sample(sample_om, openmetrics=True)
    assert formatted_om == "test_ts 100 1700000000.500"

    sample_prom = MetricSample("test_ts", 100.0, timestamp=1700000000.5)
    formatted_prom = OpenMetricsFormatter.format_sample(sample_prom, openmetrics=False)
    assert formatted_prom == "test_ts 100 1700000000500"


def test_format_prometheus_vs_openmetrics():
    fam = MetricFamily(
        name="node_memory_bytes",
        help_text="Memory size in bytes",
        metric_type=MetricType.GAUGE,
        unit="bytes",
    )
    fam.add_sample("node_memory_bytes", 1024.0)

    om_output = OpenMetricsFormatter.format_openmetrics([fam])
    prom_output = OpenMetricsFormatter.format_prometheus([fam])

    # OpenMetrics includes UNIT and # EOF
    assert "# UNIT node_memory_bytes bytes" in om_output
    assert om_output.endswith("# EOF\n")

    # Prometheus 0.0.4 omits UNIT and # EOF
    assert "# UNIT" not in prom_output
    assert "# EOF" not in prom_output


def test_format_json():
    fam = MetricFamily(
        name="test_metric",
        help_text="Test help",
        metric_type=MetricType.GAUGE,
    )
    fam.add_sample("test_metric", 123.45, {"env": "prod"})

    json_str = OpenMetricsFormatter.format_json([fam])
    parsed = json.loads(json_str)
    assert len(parsed) == 1
    assert parsed[0]["name"] == "test_metric"
    assert parsed[0]["samples"][0]["value"] == 123.45
    assert parsed[0]["samples"][0]["labels"] == {"env": "prod"}


def test_empty_families():
    assert OpenMetricsFormatter.format_openmetrics([]) == "# EOF\n"
    assert OpenMetricsFormatter.format_prometheus([]) == ""
    assert OpenMetricsFormatter.format_json([]) == "[]"


def test_parse_openmetrics_roundtrip():
    original_text = (
        "# HELP node_cpu_usage_percent CPU percentage\n"
        "# TYPE node_cpu_usage_percent gauge\n"
        'node_cpu_usage_percent{cpu="total"} 45.5\n'
        'node_cpu_usage_percent{cpu="0"} 50\n'
        "# HELP node_disk_reads_total Total reads\n"
        "# TYPE node_disk_reads_total counter\n"
        'node_disk_reads_total{device="sda"} 1000\n'
        "# EOF\n"
    )

    parsed_families = OpenMetricsFormatter.parse_openmetrics(original_text)
    assert len(parsed_families) == 2

    cpu_fam = next(f for f in parsed_families if "cpu" in f.name)
    assert cpu_fam.metric_type == MetricType.GAUGE
    assert len(cpu_fam.samples) == 2
    assert cpu_fam.samples[0].value == 45.5
    assert cpu_fam.samples[0].labels == {"cpu": "total"}

def test_parse_openmetrics_with_units_and_extremes():
    raw = """
    # HELP temperature_celsius Ambient temperature in Celsius
    # TYPE temperature_celsius gauge
    # UNIT temperature_celsius celsius
    temperature_celsius 23.5
    # HELP error_ratio Ratio of errors
    # TYPE error_ratio gauge
    error_ratio +Inf
    # HELP invalid_ratio Ratio of invalid
    # TYPE invalid_ratio gauge
    invalid_ratio nan
    # HELP negative_infinity
    # TYPE negative_infinity gauge
    negative_infinity -Inf
    # Invalid line without spaces
    invalidline
    # Comment line
    # EOF
    """
    fams = OpenMetricsFormatter.parse_openmetrics(raw)
    assert len(fams) == 4

    temp_fam = next(f for f in fams if f.name == "temperature_celsius")
    assert temp_fam.unit == "celsius"
    assert temp_fam.samples[0].value == 23.5

    inf_fam = next(f for f in fams if f.name == "error_ratio")
    assert math.isinf(inf_fam.samples[0].value) and inf_fam.samples[0].value > 0

    nan_fam = next(f for f in fams if f.name == "invalid_ratio")
    assert math.isnan(nan_fam.samples[0].value)

    neg_inf_fam = next(f for f in fams if f.name == "negative_infinity")
    assert math.isinf(neg_inf_fam.samples[0].value) and neg_inf_fam.samples[0].value < 0
