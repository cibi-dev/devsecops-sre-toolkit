"""Persistent Disk-Backed FIFO Spool Buffer for Anti-Crash & Sink Tolerance (CWE-377)."""

import asyncio
import glob
import json
import os
import shutil
import tempfile
import time
from typing import Any, Dict, List, Optional
from aggregator import LogEvent, MAX_EVENT_SIZE_BYTES

# Default maximum disk buffer capacity: 500 MB (CWE-400)
DEFAULT_MAX_DISK_BYTES = 500 * 1024 * 1024
DEFAULT_MAX_SEGMENT_BYTES = 5 * 1024 * 1024  # 5 MB per segment


class PersistentDiskBuffer:
    """Persistent FIFO on-disk queue with segment rotation and crash recovery."""

    def __init__(
        self,
        buffer_dir: Optional[str] = None,
        max_memory_events: int = 20000,
        max_disk_bytes: int = DEFAULT_MAX_DISK_BYTES,
        max_segment_bytes: int = DEFAULT_MAX_SEGMENT_BYTES,
    ):
        self._temp_dir_obj: Optional[tempfile.TemporaryDirectory[str]] = None
        if buffer_dir is None:
            self._temp_dir_obj = tempfile.TemporaryDirectory(prefix="aggregator_spool_")
            self.buffer_dir = self._temp_dir_obj.name
        else:
            self.buffer_dir = os.path.abspath(buffer_dir)
            os.makedirs(self.buffer_dir, mode=0o700, exist_ok=True)

        # Enforce secure directory permissions (CWE-377)
        try:
            os.chmod(self.buffer_dir, 0o700)
        except OSError:
            pass

        self.max_memory_events = max_memory_events
        self.max_disk_bytes = max_disk_bytes
        self.max_segment_bytes = max_segment_bytes

        self._memory_queue: asyncio.Queue[LogEvent] = asyncio.Queue(maxsize=max_memory_events)
        self._write_seq: int = 0
        self._active_write_file: Optional[Any] = None
        self._active_write_path: Optional[str] = None
        self._active_segment_bytes: int = 0

        self._lock = asyncio.Lock()
        self._has_disk_segments: bool = False
        self._events_pushed: int = 0
        self._events_popped: int = 0
        self._spilled_to_disk: int = 0
        self._disk_read_count: int = 0
        self._drops_count: int = 0

    @property
    def metrics(self) -> Dict[str, Any]:
        """Return buffer operational and disk usage metrics."""
        disk_bytes = self._calculate_disk_usage()
        segments = len(self._get_segment_files())
        return {
            "buffer_dir": self.buffer_dir,
            "memory_queue_size": self._memory_queue.qsize(),
            "disk_bytes_used": disk_bytes,
            "segments_count": segments,
            "events_pushed": self._events_pushed,
            "events_popped": self._events_popped,
            "spilled_to_disk": self._spilled_to_disk,
            "disk_read_count": self._disk_read_count,
            "drops_count": self._drops_count,
        }

    def _calculate_disk_usage(self) -> int:
        """Calculate total bytes occupied by spool segments in buffer directory."""
        total = 0
        for path in self._get_segment_files():
            try:
                total += os.path.getsize(path)
            except OSError:
                pass
        return total

    def _get_segment_files(self) -> List[str]:
        """Get all sorted segment files in buffer directory."""
        pattern = os.path.join(self.buffer_dir, "segment_*.spool")
        files = glob.glob(pattern)
        return sorted(files)

    def _rotate_write_segment(self) -> None:
        """Close current write file and open a new segment."""
        if self._active_write_file:
            try:
                self._active_write_file.flush()
                self._active_write_file.close()
            except OSError:
                pass
            self._active_write_file = None

        self._write_seq += 1
        filename = f"segment_{self._write_seq:010d}.spool"
        path = os.path.join(self.buffer_dir, filename)

        # Open with safe permissions 0o600 (CWE-377)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        self._active_write_file = os.fdopen(fd, "w", encoding="utf-8")
        self._active_write_path = path
        self._active_segment_bytes = 0
        self._has_disk_segments = True

    def _write_to_disk_sync(self, event: LogEvent) -> bool:
        """Synchronously append event to disk segment with quota check."""
        current_disk_usage = self._calculate_disk_usage()
        if current_disk_usage >= self.max_disk_bytes:
            # Over quota (CWE-400 anti-DoS)
            self._drops_count += 1
            return False

        if (
            self._active_write_file is None
            or self._active_segment_bytes >= self.max_segment_bytes
        ):
            self._rotate_write_segment()

        line = event.to_json() + "\n"
        if self._active_write_file is not None:
            self._active_write_file.write(line)
            self._active_write_file.flush()
        line_bytes = len(line.encode("utf-8"))
        self._active_segment_bytes += line_bytes
        self._spilled_to_disk += 1
        self._has_disk_segments = True
        return True

    async def push(self, event: LogEvent) -> bool:
        """Push an event to memory queue, or spill to disk if memory is full."""
        self._events_pushed += 1

        # If disk segments exist, send to disk to maintain chronological order
        if not self._has_disk_segments:
            try:
                self._memory_queue.put_nowait(event)
                return True
            except asyncio.QueueFull:
                pass

        async with self._lock:
            if not self._has_disk_segments and not self._memory_queue.full():
                try:
                    self._memory_queue.put_nowait(event)
                    return True
                except asyncio.QueueFull:
                    pass

            return self._write_to_disk_sync(event)

    async def pop_batch(self, max_items: int = 100, timeout: float = 0.5) -> List[LogEvent]:
        """Pop up to `max_items` preserving strict FIFO ordering."""
        batch: List[LogEvent] = []

        # 1. Drain memory queue first (older events inserted before disk spill)
        while len(batch) < max_items and not self._memory_queue.empty():
            try:
                item = self._memory_queue.get_nowait()
                batch.append(item)
            except asyncio.QueueEmpty:
                break

        if len(batch) >= max_items:
            self._events_popped += len(batch)
            return batch

        # 2. Drain from disk segments if needed
        needed = max_items - len(batch)
        if self._has_disk_segments:
            async with self._lock:
                segments = self._get_segment_files()
                if segments:
                    disk_events = self._read_from_disk_sync(needed)
                    if disk_events:
                        batch.extend(disk_events)
                else:
                    self._has_disk_segments = False

        if batch:
            self._events_popped += len(batch)
            return batch

        # 3. If nothing was available, wait briefly for new items in memory queue
        if timeout > 0:
            try:
                item = await asyncio.wait_for(self._memory_queue.get(), timeout=timeout)
                batch = [item]
                while len(batch) < max_items and not self._memory_queue.empty():
                    try:
                        batch.append(self._memory_queue.get_nowait())
                    except asyncio.QueueEmpty:
                        break
                self._events_popped += len(batch)
                return batch
            except (asyncio.TimeoutError, asyncio.CancelledError):
                return []

        return []

    def _read_from_disk_sync(self, max_items: int) -> List[LogEvent]:
        """Read items from the oldest disk segment and delete consumed segments."""
        segments = self._get_segment_files()
        if not segments:
            self._has_disk_segments = False
            return []

        oldest_segment = segments[0]
        if oldest_segment == self._active_write_path and self._active_write_file:
            self._active_write_file.flush()

        events: List[LogEvent] = []
        remaining_lines: List[str] = []

        try:
            with open(oldest_segment, "r", encoding="utf-8", errors="replace") as f:
                lines = f.readlines()

            for i, line in enumerate(lines):
                line_str = line.strip()
                if not line_str:
                    continue
                if len(events) < max_items:
                    try:
                        event = LogEvent.from_json(line_str)
                        events.append(event)
                        self._disk_read_count += 1
                    except Exception:
                        pass
                else:
                    remaining_lines.extend(lines[i:])
                    break

            if not remaining_lines:
                if oldest_segment == self._active_write_path:
                    if self._active_write_file:
                        self._active_write_file.close()
                        self._active_write_file = None
                    self._active_write_path = None
                    self._active_segment_bytes = 0
                try:
                    os.remove(oldest_segment)
                except OSError:
                    pass
                if len(segments) <= 1:
                    self._has_disk_segments = False
            else:
                if oldest_segment == self._active_write_path and self._active_write_file:
                    self._active_write_file.close()
                    self._active_write_file = None

                fd = os.open(oldest_segment, os.O_WRONLY | os.O_TRUNC | os.O_CREAT, 0o600)
                with os.fdopen(fd, "w", encoding="utf-8") as f:
                    f.writelines(remaining_lines)

                if oldest_segment == self._active_write_path:
                    fd2 = os.open(oldest_segment, os.O_WRONLY | os.O_APPEND, 0o600)
                    self._active_write_file = os.fdopen(fd2, "w", encoding="utf-8")
                    self._active_segment_bytes = sum(len(l.encode("utf-8")) for l in remaining_lines)

        except Exception:
            pass

        return events

    async def recover(self) -> int:
        """Scan buffer directory on startup and calculate recoverable un-acked events."""
        async with self._lock:
            segments = self._get_segment_files()
            total_recovered = 0
            for seg in segments:
                try:
                    with open(seg, "r", encoding="utf-8", errors="replace") as f:
                        for line in f:
                            if line.strip():
                                total_recovered += 1
                except Exception:
                    pass

            if segments:
                self._has_disk_segments = True
                last_seg = segments[-1]
                base = os.path.basename(last_seg)
                try:
                    seq_num = int(base.replace("segment_", "").replace(".spool", ""))
                    self._write_seq = max(self._write_seq, seq_num)
                except ValueError:
                    pass

            return total_recovered

    def close(self) -> None:
        """Close active write file handles."""
        if self._active_write_file:
            try:
                self._active_write_file.flush()
                self._active_write_file.close()
            except OSError:
                pass
            self._active_write_file = None
            self._active_write_path = None

        if self._temp_dir_obj:
            try:
                self._temp_dir_obj.cleanup()
            except OSError:
                pass
