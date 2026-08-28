"""Log Ingestion Inputs (TCP, UDP, Unix Sockets, File Tail)."""

import abc
import asyncio
from typing import Any, Dict, Optional
from aggregator import LogEvent, MAX_EVENT_SIZE_BYTES


class BaseInput(abc.ABC):
    """Abstract base class for all input adapters."""

    def __init__(self, name: str, source_label: Optional[str] = None):
        self.name = name
        self.source_label = source_label or name
        self._running = False
        self._target_queue: Optional[asyncio.Queue] = None
        self._events_received: int = 0
        self._bytes_received: int = 0
        self._errors_count: int = 0
        self._drops_count: int = 0

    @property
    def is_running(self) -> bool:
        """Return True if input is active."""
        return self._running

    @property
    def metrics(self) -> Dict[str, Any]:
        """Return current operational metrics."""
        return {
            "name": self.name,
            "source_label": self.source_label,
            "running": self._running,
            "events_received": self._events_received,
            "bytes_received": self._bytes_received,
            "errors": self._errors_count,
            "drops": self._drops_count,
        }

    async def emit(self, raw_data: str) -> None:
        """Push raw event into the ingestion queue, applying size limits."""
        if not self._target_queue or not self._running:
            return

        byte_len = len(raw_data.encode("utf-8", errors="replace"))
        self._bytes_received += byte_len

        if byte_len > MAX_EVENT_SIZE_BYTES:
            # Enforce CWE-400 size quota: truncate or count drop
            self._drops_count += 1
            raw_data = raw_data[:MAX_EVENT_SIZE_BYTES] + "...[TRUNCATED_OVER_64KB]"

        event = LogEvent.create(raw=raw_data, source=self.source_label)
        self._events_received += 1
        try:
            await self._target_queue.put(event)
        except Exception:
            self._errors_count += 1

    @abc.abstractmethod
    async def start(self, target_queue: asyncio.Queue) -> None:
        """Start listening/polling and emitting events."""
        pass

    @abc.abstractmethod
    async def stop(self) -> None:
        """Stop listening/polling gracefully."""
        pass
