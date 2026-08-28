"""Tests for LogPipeline orchestration, backpressure, worker pool, and lifecycle."""

import asyncio
import pytest
from aggregator import LogEvent, MAX_EVENT_SIZE_BYTES
from aggregator.outputs.stdout import StdoutOutput
from aggregator.pipeline import LogPipeline
from aggregator.transformers import BaseTransformer
from aggregator.transformers.grok import GrokTransformer
from aggregator.transformers.sanitizer import PIISanitizer


class DummySink(StdoutOutput):
    """Test sink capturing received events."""
    def __init__(self, name="dummy", should_fail=False):
        super().__init__(name=name)
        self.received = []
        self.should_fail = should_fail

    async def send_batch(self, events):
        if self.should_fail:
            self._errors_count += 1
            return False
        self.received.extend(events)
        self._events_sent += len(events)
        self._batches_sent += 1
        return True


class BrokenTransformer(BaseTransformer):
    """Transformer that raises an unhandled exception."""
    def __init__(self):
        super().__init__(name="broken")

    def transform(self, event: LogEvent) -> LogEvent:
        raise ValueError("Simulated transformer error")


@pytest.mark.asyncio
class TestPipeline:
    """Test suite for pipeline orchestrator."""

    async def test_pipeline_transformation_flow(self):
        """Verify full lifecycle: raw injection -> grok -> sanitizer -> buffer -> sink."""
        pipeline = LogPipeline(worker_count=2, batch_size=10, flush_interval=0.01)
        pipeline.add_transformer(GrokTransformer())
        pipeline.add_transformer(PIISanitizer())

        sink = DummySink()
        pipeline.add_output(sink)

        await pipeline.start()
        assert pipeline.is_running is True
        # Idempotent start
        await pipeline.start()

        raw = "<134>Feb 15 14:02:30 auth-node srv[100]: User admin@internal.corp logged in from 10.0.0.1 password=Pass123!"
        await pipeline.push_raw(raw, source="test-stream")

        for _ in range(50):
            if len(sink.received) >= 1:
                break
            await asyncio.sleep(0.01)

        await pipeline.stop(drain=True)
        assert pipeline.is_running is False

        assert len(sink.received) == 1
        ev = sink.received[0]
        assert ev.metadata["hostname"] == "auth-node"
        assert ev.metadata["app_name"] == "srv"
        assert "admin@internal.corp" not in ev.message
        assert "10.0.0.1" not in ev.message
        assert "Pass123!" not in ev.message
        assert "[REDACTED]" in ev.message

    async def test_pipeline_multi_sink_fanout(self):
        """Verify events are broadcasted to all registered output sinks."""
        pipeline = LogPipeline(worker_count=2, batch_size=5, flush_interval=0.01)
        sink1 = DummySink("sink1")
        sink2 = DummySink("sink2")
        pipeline.add_output(sink1).add_output(sink2)

        await pipeline.start()

        for i in range(5):
            await pipeline.push_raw(f"Fanout message {i}")

        for _ in range(50):
            if len(sink1.received) == 5 and len(sink2.received) == 5:
                break
            await asyncio.sleep(0.01)

        await pipeline.stop(drain=True)

        assert len(sink1.received) == 5
        assert len(sink2.received) == 5

    async def test_pipeline_backpressure_and_bounded_queue(self):
        """Verify bounded queue handles high load without deadlock."""
        pipeline = LogPipeline(
            worker_count=2,
            queue_max_size=50,
            batch_size=50,
            flush_interval=0.01,
        )
        sink = DummySink()
        pipeline.add_output(sink)

        await pipeline.start()

        for i in range(100):
            await pipeline.push_raw(f"Load event {i}")

        for _ in range(100):
            if len(sink.received) == 100:
                break
            await asyncio.sleep(0.01)

        await pipeline.stop(drain=True)

        assert len(sink.received) == 100
        metrics = pipeline.metrics
        assert metrics["events_dispatched"] == 100
        assert metrics["average_latency_ms"] >= 0.0

    async def test_pipeline_broken_transformer_and_failing_sink(self):
        """Verify pipeline handles failing transformer and failing sink gracefully."""
        pipeline = LogPipeline(worker_count=1, batch_size=5, flush_interval=0.01)
        pipeline.add_transformer(BrokenTransformer())
        failing_sink = DummySink(should_fail=True)
        pipeline.add_output(failing_sink)

        await pipeline.start()
        await pipeline.push_raw("Message to fail")

        await asyncio.sleep(0.1)
        await pipeline.stop(drain=True)

        m = pipeline.metrics
        assert m["events_failed"] >= 1

    async def test_pipeline_oversized_push_raw_truncation(self):
        """Verify push_raw truncates oversized payload (>64KB)."""
        pipeline = LogPipeline(worker_count=1)
        sink = DummySink()
        pipeline.add_output(sink)

        await pipeline.start()
        huge_raw = "M" * (MAX_EVENT_SIZE_BYTES + 2000)
        await pipeline.push_raw(huge_raw)

        for _ in range(50):
            if len(sink.received) >= 1:
                break
            await asyncio.sleep(0.01)

        await pipeline.stop(drain=True)
        assert len(sink.received) == 1
        assert "[TRUNCATED_OVER_64KB]" in sink.received[0].raw
        assert pipeline.metrics["events_dropped"] >= 1

    async def test_pipeline_drain_on_stop(self):
        """Verify all queued items are processed when pipeline stops with drain=True."""
        pipeline = LogPipeline(worker_count=2, batch_size=10, flush_interval=0.01)
        sink = DummySink()
        pipeline.add_output(sink)

        await pipeline.start()

        for i in range(20):
            await pipeline.push_raw(f"Drain test {i}")

        await pipeline.stop(drain=True, timeout=2.0)
        assert len(sink.received) == 20
