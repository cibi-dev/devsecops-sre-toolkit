"""Tests for Stdout, Rotating File, and Webhook outputs with Circuit Breaker."""

import asyncio
import io
import json
import os
import stat
import tempfile
import time
import httpx
import pytest
from aggregator import LogEvent
from aggregator.outputs import BaseOutput
from aggregator.outputs.file import RotatingFileOutput
from aggregator.outputs.stdout import StdoutOutput
from aggregator.outputs.webhook import WebhookOutput


class DummyOutput(BaseOutput):
    """Test concrete implementation of BaseOutput."""
    async def send_batch(self, events):
        self._events_sent += len(events)
        self._batches_sent += 1
        return True


@pytest.mark.asyncio
class TestOutputs:
    """Test suite for output sinks."""

    async def test_base_output_properties(self):
        """Verify BaseOutput lifecycle and metrics."""
        out = DummyOutput("dummy-base")
        assert out.is_running is False
        await out.start()
        assert out.is_running is True
        assert out.metrics["name"] == "dummy-base"
        await out.send_batch([LogEvent.create("msg1")])
        assert out.metrics["events_sent"] == 1
        await out.stop()
        assert out.is_running is False

    async def test_stdout_json_output(self):
        """Verify StdoutOutput writes NDJSON to stream."""
        stream = io.StringIO()
        out = StdoutOutput(format_type="json", stream=stream)
        await out.start()

        event = LogEvent.create("Hello world", source="test-src")
        success = await out.send_batch([event])
        await out.stop()

        assert success is True
        output_str = stream.getvalue().strip()
        data = json.loads(output_str)
        assert data["message"] == "Hello world"
        assert data["source"] == "test-src"
        assert out.metrics["events_sent"] == 1

    async def test_stdout_text_output(self):
        """Verify StdoutOutput text formatting."""
        stream = io.StringIO()
        out = StdoutOutput(format_type="text", stream=stream)
        await out.start()

        event = LogEvent.create("Sample log line", source="auth")
        await out.send_batch([event])
        await out.stop()

        assert stream.getvalue() == "[auth] Sample log line\n"

    async def test_stdout_empty_batch(self):
        """Verify StdoutOutput handles empty batch cleanly."""
        out = StdoutOutput()
        assert await out.send_batch([]) is True

    async def test_rotating_file_output_and_permissions(self):
        """Verify RotatingFileOutput size rotation, backup files, and 0o600 permissions."""
        with tempfile.TemporaryDirectory() as tmpdir:
            file_path = os.path.join(tmpdir, "app.log")
            out = RotatingFileOutput(
                file_path=file_path,
                max_bytes=200,
                backup_count=3,
            )
            await out.start()

            file_mode = stat.S_IMODE(os.stat(file_path).st_mode)
            assert file_mode == 0o600

            for i in range(10):
                ev = LogEvent.create(f"Log line event {i:04d} with some filler content...")
                await out.send_batch([ev])

            await out.stop()

            assert os.path.exists(file_path)
            assert os.path.exists(f"{file_path}.1")
            assert out.metrics["events_sent"] == 10

    async def test_rotating_file_text_format(self):
        """Verify RotatingFileOutput with text formatting."""
        with tempfile.TemporaryDirectory() as tmpdir:
            file_path = os.path.join(tmpdir, "text_app.log")
            out = RotatingFileOutput(
                file_path=file_path,
                format_type="text",
            )
            await out.start()
            assert await out.send_batch([]) is True

            ev = LogEvent.create("Text log line", source="srv")
            await out.send_batch([ev])
            await out.stop()

            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()
            assert "[srv] Text log line" in content

    async def test_webhook_successful_batch_post(self):
        """Verify WebhookOutput delivers batch via HTTP POST."""
        sent_requests = []

        def mock_handler(request: httpx.Request):
            sent_requests.append(json.loads(request.content.decode("utf-8")))
            return httpx.Response(200, json={"status": "ok"})

        transport = httpx.MockTransport(mock_handler)
        async with httpx.AsyncClient(transport=transport) as client:
            webhook = WebhookOutput(
                url="https://api.example.com/logs",
                client=client,
            )
            await webhook.start()
            assert await webhook.send_batch([]) is True

            events = [
                LogEvent.create("Event A"),
                LogEvent.create("Event B"),
            ]
            success = await webhook.send_batch(events)
            await webhook.stop()

            assert success is True
            assert len(sent_requests) == 1
            assert len(sent_requests[0]) == 2
            assert sent_requests[0][0]["message"] == "Event A"
            assert webhook.metrics["events_sent"] == 2
            assert webhook.circuit_state == "CLOSED"

    async def test_webhook_retry_and_circuit_breaker(self):
        """Verify WebhookOutput retries on failure and trips Circuit Breaker."""
        call_count = 0

        def failing_handler(request: httpx.Request):
            nonlocal call_count
            call_count += 1
            return httpx.Response(500, json={"error": "Internal Server Error"})

        transport = httpx.MockTransport(failing_handler)
        async with httpx.AsyncClient(transport=transport) as client:
            webhook = WebhookOutput(
                url="https://api.example.com/logs",
                client=client,
                max_retries=1,
                failure_threshold=2,
                circuit_reset_timeout=0.2,
            )
            await webhook.start()

            # Batch 1 fails
            s1 = await webhook.send_batch([LogEvent.create("E1")])
            assert s1 is False
            assert webhook.circuit_state == "CLOSED"

            # Batch 2 fails -> reaches threshold 2 -> Trips circuit
            s2 = await webhook.send_batch([LogEvent.create("E2")])
            assert s2 is False
            assert webhook.circuit_state == "OPEN"
            assert webhook.metrics["circuit_trips"] == 1

            # Batch 3 rejected immediately while OPEN
            prior_calls = call_count
            s3 = await webhook.send_batch([LogEvent.create("E3")])
            assert s3 is False
            assert call_count == prior_calls

            # Wait for circuit reset timeout -> HALF_OPEN
            await asyncio.sleep(0.25)
            assert webhook.circuit_state == "HALF_OPEN"

            await webhook.stop()

    async def test_webhook_lifecycle_without_custom_client(self):
        """Verify WebhookOutput initializes and closes its internal httpx.AsyncClient."""
        webhook = WebhookOutput(url="https://example.com/endpoint")
        assert webhook._client is None
        await webhook.start()
        assert webhook._client is not None
        await webhook.stop()
        assert webhook._client is None
