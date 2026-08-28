"""Log Forwarding Outputs / Sinks (Stdout, Rotating File, Webhook)."""

import abc
from typing import Any, Dict, List
from aggregator import LogEvent

# Max batch size in bytes (10MB) - CWE-400 resource quota
MAX_BATCH_BYTES = 10 * 1024 * 1024


class BaseOutput(abc.ABC):
    """Abstract base class for all output / sink adapters."""

    def __init__(self, name: str):
        self.name = name
        self._running = False
        self._events_sent: int = 0
        self._batches_sent: int = 0
        self._errors_count: int = 0
        self._retries_count: int = 0

    @property
    def is_running(self) -> bool:
        """Return True if output is active."""
        return self._running

    @property
    def metrics(self) -> Dict[str, Any]:
        """Return output sink operational metrics."""
        return {
            "name": self.name,
            "running": self._running,
            "events_sent": self._events_sent,
            "batches_sent": self._batches_sent,
            "errors": self._errors_count,
            "retries": self._retries_count,
        }

    async def start(self) -> None:
        """Initialize sink resources."""
        self._running = True

    async def stop(self) -> None:
        """Flush and release sink resources."""
        self._running = False

    @abc.abstractmethod
    async def send_batch(self, events: List[LogEvent]) -> bool:
        """Send a batch of events to the sink. Return True if successful."""
        pass
