"""Tests for GrokTransformer and JSON log normalizer."""

import pytest
from aggregator import LogEvent
from aggregator.transformers import BaseTransformer
from aggregator.transformers.grok import GrokTransformer


class DummyTransformer(BaseTransformer):
    """Test concrete implementation of BaseTransformer."""
    def transform(self, event: LogEvent) -> LogEvent:
        self._processed_count += 1
        self._modified_count += 1
        event.tags.append("dummy")
        return event


class TestGrokTransformer:
    """Test suite for Syslog, HTTP and JSON log parsing."""

    def test_base_transformer_metrics(self):
        """Verify BaseTransformer metrics and properties."""
        tf = DummyTransformer("dummy-tf")
        assert tf.metrics["name"] == "dummy-tf"
        assert tf.metrics["processed"] == 0
        event = LogEvent.create("Hello")
        tf.transform(event)
        assert tf.metrics["processed"] == 1
        assert tf.metrics["modified"] == 1
        assert "dummy" in event.tags

    def test_rfc3164_syslog_parsing_with_pid(self):
        """Verify RFC 3164 Syslog format with application name and PID."""
        transformer = GrokTransformer()
        raw = "<134>Feb 15 14:02:30 db-srv-01 postgres[5432]: database connection established"
        event = LogEvent.create(raw)
        res = transformer.transform(event)

        assert res.message == "database connection established"
        assert res.metadata["hostname"] == "db-srv-01"
        assert res.metadata["app_name"] == "postgres"
        assert res.metadata["pid"] == "5432"
        assert res.metadata["facility_code"] == 16  # 134 >> 3
        assert res.metadata["severity_code"] == 6   # 134 & 7
        assert res.metadata["severity"] == "Informational"
        assert "syslog-rfc3164" in res.tags

    def test_rfc3164_syslog_parsing_without_pid(self):
        """Verify RFC 3164 Syslog format without PID."""
        transformer = GrokTransformer()
        raw = "<34>Oct 11 22:14:15 myhost kernel: System restarted successfully"
        event = LogEvent.create(raw)
        res = transformer.transform(event)

        assert res.message == "System restarted successfully"
        assert res.metadata["hostname"] == "myhost"
        assert res.metadata["app_name"] == "kernel"
        assert res.metadata["pid"] is None
        assert "syslog-rfc3164" in res.tags

    def test_rfc5424_syslog_parsing(self):
        """Verify RFC 5424 Syslog format with structured metadata."""
        transformer = GrokTransformer()
        raw = "<165>1 2026-08-27T20:15:30.123Z host.internal.net authservice 8812 msg-909 [exampleSDID@32473 iut=\"3\"] User authentication successful"
        event = LogEvent.create(raw)
        res = transformer.transform(event)

        assert res.message == "User authentication successful"
        assert res.metadata["hostname"] == "host.internal.net"
        assert res.metadata["app_name"] == "authservice"
        assert res.metadata["procid"] == "8812"
        assert res.metadata["msgid"] == "msg-909"
        assert res.metadata["structured_data"] == 'exampleSDID@32473 iut="3"'
        assert res.metadata["facility_code"] == 20
        assert res.metadata["severity_code"] == 5
        assert "syslog-rfc5424" in res.tags

    def test_combined_apache_http_parsing_with_dash_bytes(self):
        """Verify Apache/Nginx Combined access log parsing with '-' for bytes."""
        transformer = GrokTransformer()
        raw = '192.168.1.10 - admin [27/Aug/2026:20:00:00 +0000] "GET /api/v1/health HTTP/1.1" 200 - "https://example.com" "Mozilla/5.0"'
        event = LogEvent.create(raw)
        res = transformer.transform(event)

        assert res.metadata["client_ip"] == "192.168.1.10"
        assert res.metadata["auth_user"] == "admin"
        assert res.metadata["method"] == "GET"
        assert res.metadata["path"] == "/api/v1/health"
        assert res.metadata["status"] == 200
        assert res.metadata["bytes_sent"] == "-"
        assert res.metadata["referrer"] == "https://example.com"
        assert res.metadata["user_agent"] == "Mozilla/5.0"
        assert "http-access" in res.tags

    def test_json_log_normalization(self):
        """Verify structured JSON log parsing and key normalization."""
        transformer = GrokTransformer()
        raw = '{"service": "checkout", "level": "WARN", "msg": "Payment retry initiated", "attempt": 2, "user_id": "u-99"}'
        event = LogEvent.create(raw)
        res = transformer.transform(event)

        assert res.message == "Payment retry initiated"
        assert res.metadata["service"] == "checkout"
        assert res.metadata["level"] == "WARN"
        assert res.metadata["attempt"] == 2
        assert "json-parsed" in res.tags

    def test_custom_grok_pattern(self):
        """Verify user-defined custom Grok regex patterns."""
        custom_patterns = {
            "custom_app": r"^\[(?P<level>[A-Z]+)\]\s+(?P<module>\w+):\s+(?P<message>.*)$"
        }
        transformer = GrokTransformer(custom_patterns=custom_patterns)
        raw = "[CRITICAL] PaymentGateway: Transaction timeout occurred"
        event = LogEvent.create(raw)
        res = transformer.transform(event)

        assert res.message == "Transaction timeout occurred"
        assert res.metadata["level"] == "CRITICAL"
        assert res.metadata["module"] == "PaymentGateway"
        assert "grok-custom_app" in res.tags

    def test_unmatched_log_fallback(self):
        """Verify that unstructured logs pass through without error."""
        transformer = GrokTransformer()
        raw = "Just a raw unstructured log message that matches nothing."
        event = LogEvent.create(raw)
        res = transformer.transform(event)

        assert res.message == raw
        assert res.tags == []
        assert transformer.metrics["processed"] == 1
        assert transformer.metrics["modified"] == 0

    def test_malformed_json_fallback(self):
        """Verify that malformed JSON strings do not raise exceptions."""
        transformer = GrokTransformer()
        raw = "{'service': invalid json syntax, missing quotes}"
        event = LogEvent.create(raw)
        res = transformer.transform(event)

        assert res.message == raw
        assert "json-parsed" not in res.tags
