"""Tests for PersistentDiskBuffer, segment rotation, crash recovery, and security (CWE-377)."""

import os
import stat
import tempfile
import pytest
from aggregator import LogEvent
from aggregator.buffer import PersistentDiskBuffer


@pytest.mark.asyncio
class TestPersistentDiskBuffer:
    """Test suite for persistent disk FIFO buffer."""

    async def test_memory_queue_fast_path(self):
        """Verify standard in-memory enqueue and batch dequeue."""
        buffer = PersistentDiskBuffer(max_memory_events=50)
        try:
            event1 = LogEvent.create("Event 1")
            event2 = LogEvent.create("Event 2")

            await buffer.push(event1)
            await buffer.push(event2)

            batch = await buffer.pop_batch(max_items=10, timeout=0.1)
            assert len(batch) == 2
            assert batch[0].message == "Event 1"
            assert batch[1].message == "Event 2"
        finally:
            buffer.close()

    async def test_empty_buffer_timeout(self):
        """Verify pop_batch on empty buffer returns empty list after timeout."""
        buffer = PersistentDiskBuffer(max_memory_events=10)
        try:
            batch = await buffer.pop_batch(max_items=5, timeout=0.02)
            assert batch == []
            # Zero timeout
            batch2 = await buffer.pop_batch(max_items=5, timeout=0.0)
            assert batch2 == []
        finally:
            buffer.close()

    async def test_spill_to_disk_on_memory_full(self):
        """Verify events spill to persistent disk segments when memory is full."""
        with tempfile.TemporaryDirectory() as tmpdir:
            buffer = PersistentDiskBuffer(
                buffer_dir=tmpdir,
                max_memory_events=5,
                max_segment_bytes=1024,
            )
            try:
                for i in range(15):
                    ev = LogEvent.create(f"Spill Event {i}")
                    pushed = await buffer.push(ev)
                    assert pushed is True

                m = buffer.metrics
                assert m["events_pushed"] == 15
                assert m["spilled_to_disk"] > 0
                assert m["segments_count"] > 0

                popped_events = []
                while len(popped_events) < 15:
                    batch = await buffer.pop_batch(max_items=10, timeout=0.2)
                    if not batch:
                        break
                    popped_events.extend(batch)

                assert len(popped_events) == 15
                for i, ev in enumerate(popped_events):
                    assert f"Spill Event {i}" in ev.message
            finally:
                buffer.close()

    async def test_crash_recovery_from_disk(self):
        """Verify un-consumed spool segments are recovered upon restart."""
        with tempfile.TemporaryDirectory() as tmpdir:
            b1 = PersistentDiskBuffer(
                buffer_dir=tmpdir,
                max_memory_events=2,
            )
            for i in range(10):
                await b1.push(LogEvent.create(f"Recoverable Event {i}"))
            b1.close()

            b2 = PersistentDiskBuffer(
                buffer_dir=tmpdir,
                max_memory_events=2,
            )
            try:
                recovered_count = await b2.recover()
                assert recovered_count > 0

                batch = await b2.pop_batch(max_items=20, timeout=0.2)
                assert len(batch) >= recovered_count
                assert "Recoverable Event" in batch[0].message
            finally:
                b2.close()

    async def test_secure_file_permissions(self):
        """Verify CWE-377 / CWE-732 secure permissions (0o700 directory, 0o600 files)."""
        with tempfile.TemporaryDirectory() as tmpdir:
            buffer = PersistentDiskBuffer(
                buffer_dir=tmpdir,
                max_memory_events=1,
            )
            try:
                for i in range(3):
                    await buffer.push(LogEvent.create(f"Secure Event {i}"))

                dir_mode = stat.S_IMODE(os.stat(tmpdir).st_mode)
                assert dir_mode == 0o700

                segments = buffer._get_segment_files()
                assert len(segments) > 0
                file_mode = stat.S_IMODE(os.stat(segments[0]).st_mode)
                assert file_mode == 0o600
            finally:
                buffer.close()

    async def test_disk_quota_exceeded(self):
        """Verify buffer enforces max disk quota (CWE-400 anti-DoS)."""
        with tempfile.TemporaryDirectory() as tmpdir:
            buffer = PersistentDiskBuffer(
                buffer_dir=tmpdir,
                max_memory_events=1,
                max_disk_bytes=100,
            )
            try:
                await buffer.push(LogEvent.create("E1"))
                await buffer.push(LogEvent.create("E2" * 50))
                pushed = await buffer.push(LogEvent.create("E3" * 50))
                assert pushed is False
                assert buffer.metrics["drops_count"] >= 1
            finally:
                buffer.close()

    async def test_segment_cleanup_on_drain(self):
        """Verify consumed segment files are removed from disk to reclaim space."""
        with tempfile.TemporaryDirectory() as tmpdir:
            buffer = PersistentDiskBuffer(
                buffer_dir=tmpdir,
                max_memory_events=1,
                max_segment_bytes=500,
            )
            try:
                for i in range(10):
                    await buffer.push(LogEvent.create(f"Drain Event {i}"))

                assert len(buffer._get_segment_files()) > 0

                while True:
                    b = await buffer.pop_batch(max_items=10, timeout=0.1)
                    if not b:
                        break

                assert len(buffer._get_segment_files()) == 0
            finally:
                buffer.close()
