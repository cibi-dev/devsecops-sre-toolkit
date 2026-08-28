"""Asynchronous Log File Tailing Input."""

import asyncio
import os
from typing import Optional
from aggregator.inputs import BaseInput


class FileTailInput(BaseInput):
    """Asynchronously tails a file, following log rotations and truncations."""

    def __init__(
        self,
        file_path: str,
        name: str = "file-tail",
        start_from_beginning: bool = False,
        poll_interval: float = 0.05,
    ):
        super().__init__(name=name, source_label=f"file:{file_path}")
        self.file_path = os.path.abspath(file_path)
        self.start_from_beginning = start_from_beginning
        self.poll_interval = poll_interval
        self._tail_task: Optional[asyncio.Task] = None

    async def start(self, target_queue: asyncio.Queue) -> None:
        """Start background tailing task."""
        if self._running:
            return
        self._target_queue = target_queue
        self._running = True
        self._tail_task = asyncio.create_task(self._tail_loop())

    async def _tail_loop(self) -> None:
        """Main tail loop monitoring file changes."""
        file_obj = None
        last_inode = None
        last_pos = 0

        while self._running:
            try:
                if not os.path.exists(self.file_path):
                    if file_obj:
                        file_obj.close()
                        file_obj = None
                        last_inode = None
                    await asyncio.sleep(self.poll_interval)
                    continue

                stat = os.stat(self.file_path)
                current_inode = (stat.st_ino, stat.st_dev)

                # Check if file rotated (inode change) or first open
                if file_obj is None or current_inode != last_inode:
                    if file_obj:
                        # Drain remaining bytes from previous file
                        try:
                            for line in file_obj:
                                if line.strip():
                                    await self.emit(line.rstrip("\r\n"))
                        except Exception:
                            pass
                        file_obj.close()

                    file_obj = open(self.file_path, "r", encoding="utf-8", errors="replace")
                    last_inode = current_inode

                    if not self.start_from_beginning:
                        file_obj.seek(0, os.SEEK_END)
                        last_pos = file_obj.tell()
                    else:
                        last_pos = 0

                # Check for file truncation (copytruncate logrotate)
                current_size = os.path.getsize(self.file_path)
                if current_size < last_pos:
                    file_obj.seek(0, os.SEEK_SET)
                    last_pos = 0

                # Read available lines
                lines_read = 0
                while self._running:
                    line = file_obj.readline()
                    if not line:
                        break
                    lines_read += 1
                    line = line.rstrip("\r\n")
                    if line:
                        await self.emit(line)

                last_pos = file_obj.tell()

                if lines_read == 0:
                    await asyncio.sleep(self.poll_interval)

            except asyncio.CancelledError:
                break
            except Exception:
                self._errors_count += 1
                await asyncio.sleep(self.poll_interval)

        if file_obj:
            try:
                file_obj.close()
            except Exception:
                pass

    async def stop(self) -> None:
        """Stop tailing task gracefully."""
        self._running = False
        if self._tail_task:
            self._tail_task.cancel()
            try:
                await self._tail_task
            except asyncio.CancelledError:
                pass
            self._tail_task = None
