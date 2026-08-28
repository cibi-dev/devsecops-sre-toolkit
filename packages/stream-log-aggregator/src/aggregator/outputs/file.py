"""Rotating File Output Sink."""

import os
from typing import Any, List, Optional
from aggregator import LogEvent
from aggregator.outputs import BaseOutput


class RotatingFileOutput(BaseOutput):
    """Asynchronous file sink with automated size-based rotation and secure permissions (CWE-377)."""

    def __init__(
        self,
        file_path: str,
        name: str = "rotating-file",
        max_bytes: int = 10 * 1024 * 1024,  # 10MB
        backup_count: int = 5,
        format_type: str = "json",
    ):
        super().__init__(name=name)
        self.file_path = os.path.abspath(file_path)
        self.max_bytes = max_bytes
        self.backup_count = backup_count
        self.format_type = format_type
        self._file_handle: Optional[Any] = None

    async def start(self) -> None:
        """Open destination file with 0o600 permissions."""
        await super().start()
        dir_name = os.path.dirname(self.file_path)
        if dir_name:
            os.makedirs(dir_name, mode=0o700, exist_ok=True)
        self._open_file()

    def _open_file(self) -> None:
        """Open or reopen file descriptor with 0o600 permissions."""
        if self._file_handle:
            try:
                self._file_handle.flush()
                self._file_handle.close()
            except OSError:
                pass

        fd = os.open(self.file_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        self._file_handle = os.fdopen(fd, "a", encoding="utf-8")

    def _rotate_if_needed(self, additional_bytes: int) -> None:
        """Rotate files if adding bytes exceeds max_bytes."""
        if not os.path.exists(self.file_path):
            return

        current_size = os.path.getsize(self.file_path)
        if current_size + additional_bytes <= self.max_bytes:
            return

        if self._file_handle:
            self._file_handle.flush()
            self._file_handle.close()
            self._file_handle = None

        if self.backup_count > 0:
            for i in range(self.backup_count - 1, 0, -1):
                sfn = f"{self.file_path}.{i}"
                dfn = f"{self.file_path}.{i + 1}"
                if os.path.exists(sfn):
                    if os.path.exists(dfn):
                        os.remove(dfn)
                    os.rename(sfn, dfn)

            dfn = f"{self.file_path}.1"
            if os.path.exists(dfn):
                os.remove(dfn)
            if os.path.exists(self.file_path):
                os.rename(self.file_path, dfn)

        self._open_file()

    async def send_batch(self, events: List[LogEvent]) -> bool:
        """Write batch of events to rotating file."""
        if not events:
            return True

        try:
            if not self._file_handle:
                self._open_file()

            lines = []
            for event in events:
                if self.format_type == "json":
                    lines.append(event.to_json() + "\n")
                else:
                    lines.append(f"[{event.source}] {event.message}\n")

            content = "".join(lines)
            content_bytes = len(content.encode("utf-8"))

            self._rotate_if_needed(content_bytes)

            if self._file_handle is not None:
                self._file_handle.write(content)
                self._file_handle.flush()

            self._events_sent += len(events)
            self._batches_sent += 1
            return True
        except Exception:
            self._errors_count += 1
            return False

    async def stop(self) -> None:
        """Flush and close file handle."""
        await super().stop()
        if self._file_handle:
            try:
                self._file_handle.flush()
                self._file_handle.close()
            except OSError:
                pass
            self._file_handle = None
