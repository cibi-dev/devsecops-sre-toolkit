"""Standard Output Sink for Structured Log Output."""

import json
import sys
from typing import List
from aggregator import LogEvent
from aggregator.outputs import BaseOutput


class StdoutOutput(BaseOutput):
    """Outputs log events to stdout as NDJSON or formatted strings."""

    def __init__(
        self,
        name: str = "stdout",
        format_type: str = "json",  # "json" or "text"
        stream=None,
    ):
        super().__init__(name=name)
        self.format_type = format_type
        self.stream = stream or sys.stdout

    async def send_batch(self, events: List[LogEvent]) -> bool:
        """Output batch of events to stream."""
        if not events:
            return True

        try:
            for event in events:
                if self.format_type == "json":
                    line = event.to_json()
                else:
                    line = f"[{event.source}] {event.message}"
                self.stream.write(line + "\n")

            self.stream.flush()
            self._events_sent += len(events)
            self._batches_sent += 1
            return True
        except Exception:
            self._errors_count += 1
            return False
