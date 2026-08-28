"""Dedicated security test suite covering CWE-400, CWE-209, CWE-377, and CWE-502."""

import asyncio
import os
import stat
import tempfile
import pytest
from pydantic import ValidationError
from aggregator import LogEvent, MAX_EVENT_SIZE_BYTES
from aggregator.buffer import PersistentDiskBuffer
from aggregator.inputs.tcp import SyslogTCPInput
from aggregator.outputs.file import RotatingFileOutput
from aggregator.transformers.sanitizer import PIISanitizer


class TestSecurityGuardrails:
    """Security verification tests for DevSecOps standards."""

    def test_cwe_400_max_event_size_quota(self):
        """Verify CWE-400: Oversized raw log lines (>64KB) are safely truncated."""
        oversized = "X" * (MAX_EVENT_SIZE_BYTES + 5000)
        event = LogEvent.create(oversized)

        assert len(event.raw) <= MAX_EVENT_SIZE_BYTES + 50
        assert "[TRUNCATED_OVER_64KB]" in event.raw
        assert len(event.message) <= MAX_EVENT_SIZE_BYTES + 50

    @pytest.mark.asyncio
    async def test_cwe_400_tcp_connection_concurrency_limit(self):
        """Verify CWE-400 Anti-DoS: TCP server enforces max concurrent connections."""
        queue: asyncio.Queue[LogEvent] = asyncio.Queue()
        tcp_input = SyslogTCPInput(
            host="127.0.0.1",
            port=0,
            max_connections=2,  # Low limit for testing
        )
        await tcp_input.start(queue)
        port = tcp_input._server.sockets[0].getsockname()[1]

        # Connect 2 allowed clients
        r1, w1 = await asyncio.open_connection("127.0.0.1", port)
        r2, w2 = await asyncio.open_connection("127.0.0.1", port)

        # Attempt 3rd connection exceeding quota
        r3, w3 = await asyncio.open_connection("127.0.0.1", port)
        try:
            w3.write(b"Drop me\n")
            await w3.drain()
            data = await r3.read()
        except (ConnectionResetError, BrokenPipeError):
            data = b""

        assert data == b"" or tcp_input.metrics["drops"] >= 1

        w1.close()
        w2.close()
        try:
            w3.close()
        except Exception:
            pass
        await tcp_input.stop()

    def test_cwe_209_no_secrets_leaked_in_dict_or_json(self):
        """Verify CWE-209: Secrets and tokens are never leaked into serialized JSON."""
        sanitizer = PIISanitizer()
        mock_key = "sk_" + "live_" + "1234567890"
        raw = f"Auth failure: user=alice password=MySecretP@ss123 api_key={mock_key}"
        event = LogEvent.create(raw)
        sanitized_event = sanitizer.transform(event)

        exported_dict = sanitized_event.to_dict()
        exported_json = sanitized_event.to_json()

        assert "MySecretP@ss123" not in exported_json
        assert mock_key not in exported_json
        assert "[REDACTED]" in exported_json
        assert "[REDACTED]" in exported_dict["message"]

    @pytest.mark.asyncio
    async def test_cwe_377_spool_buffer_and_file_output_permissions(self):
        """Verify CWE-377: Temporary buffers and log files enforce 0o700/0o600 permissions."""
        with tempfile.TemporaryDirectory() as tmpdir:
            buffer = PersistentDiskBuffer(buffer_dir=tmpdir, max_memory_events=1)
            # Write to force segment creation
            await buffer.push(LogEvent.create("Secured Buffer Entry 1"))
            await buffer.push(LogEvent.create("Secured Buffer Entry 2"))

            # Check buffer directory permissions (0o700)
            assert stat.S_IMODE(os.stat(tmpdir).st_mode) == 0o700

            # Check segment permissions (0o600)
            for seg in buffer._get_segment_files():
                assert stat.S_IMODE(os.stat(seg).st_mode) == 0o600

            buffer.close()

            # Check rotating file output permissions (0o600)
            log_path = os.path.join(tmpdir, "secure_output.log")
            f_out = RotatingFileOutput(file_path=log_path)
            await f_out.start()
            await f_out.send_batch([LogEvent.create("Output Log Line")])
            await f_out.stop()

            assert stat.S_IMODE(os.stat(log_path).st_mode) == 0o600

    def test_cwe_502_safe_deserialization(self):
        """Verify CWE-502: Strict validation against hostile or malformed JSON payloads."""
        # Valid JSON payload
        valid_json = '{"id": "evt-1", "source": "test", "raw": "hello", "message": "hello", "metadata": {}}'
        event = LogEvent.from_json(valid_json)
        assert event.id == "evt-1"

        # Invalid field types or malicious structures rejected
        with pytest.raises(ValidationError):
            LogEvent.from_json('{"id": 12345, "timestamp": "not-a-number", "metadata": "must-be-dict"}')
