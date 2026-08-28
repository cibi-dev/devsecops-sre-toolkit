"""Asynchronous TCP and Unix Socket Syslog Log Receivers."""

import asyncio
import os
from typing import Optional
from aggregator import MAX_EVENT_SIZE_BYTES
from aggregator.inputs import BaseInput


class SyslogTCPInput(BaseInput):
    """Asynchronous Syslog TCP Receiver with connection limits and timeouts (CWE-400)."""

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 5140,
        name: str = "syslog-tcp",
        max_connections: int = 100,
        idle_timeout: float = 30.0,
    ):
        super().__init__(name=name, source_label=f"syslog-tcp:{host}:{port}")
        self.host = host
        self.port = port
        self.max_connections = max_connections
        self.idle_timeout = idle_timeout
        self._server: Optional[asyncio.Server] = None
        self._connection_semaphore: Optional[asyncio.Semaphore] = None
        self._active_connections: int = 0
        self._client_tasks: set[asyncio.Task] = set()

    async def start(self, target_queue: asyncio.Queue) -> None:
        """Start TCP listener."""
        if self._running:
            return
        self._target_queue = target_queue
        self._connection_semaphore = asyncio.Semaphore(self.max_connections)
        self._running = True

        self._server = await asyncio.start_server(
            self._handle_client,
            host=self.host,
            port=self.port,
            limit=MAX_EVENT_SIZE_BYTES * 2,
        )

    async def _handle_client(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        """Handle incoming TCP client connection with backpressure and timeout."""
        if not self._connection_semaphore:
            writer.close()
            return

        # Check semaphore without blocking indefinitely
        try:
            acquired = self._connection_semaphore.locked() and (
                self._active_connections >= self.max_connections
            )
            if acquired:
                self._drops_count += 1
                writer.close()
                await writer.wait_closed()
                return
            await self._connection_semaphore.acquire()
        except Exception:
            writer.close()
            return

        self._active_connections += 1
        current_task = asyncio.current_task()
        if current_task:
            self._client_tasks.add(current_task)

        try:
            buffer = ""
            while self._running:
                try:
                    # Read with idle timeout (CWE-400 Anti-DoS)
                    data = await asyncio.wait_for(
                        reader.read(8192), timeout=self.idle_timeout
                    )
                except asyncio.TimeoutError:
                    break
                except (ConnectionResetError, asyncio.CancelledError):
                    break

                if not data:
                    break

                text = data.decode("utf-8", errors="replace")
                buffer += text

                # Prevent unbounded memory growth if no newline received (CWE-400)
                if len(buffer) > MAX_EVENT_SIZE_BYTES * 4:
                    self._drops_count += 1
                    buffer = buffer[-MAX_EVENT_SIZE_BYTES:]

                while "\n" in buffer:
                    line, buffer = buffer.split("\n", 1)
                    line = line.strip("\r")
                    if line:
                        await self.emit(line)

            # Emit remaining buffer if any
            if buffer.strip():
                await self.emit(buffer.strip())

        except Exception:
            self._errors_count += 1
        finally:
            self._active_connections -= 1
            if self._connection_semaphore:
                self._connection_semaphore.release()
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
            if current_task and current_task in self._client_tasks:
                self._client_tasks.remove(current_task)

    async def stop(self) -> None:
        """Gracefully stop TCP server and close existing connections."""
        self._running = False
        if self._server:
            self._server.close()
            await self._server.wait_closed()
            self._server = None

        # Cancel active client connection tasks
        for task in list(self._client_tasks):
            if not task.done():
                task.cancel()
        if self._client_tasks:
            await asyncio.gather(*self._client_tasks, return_exceptions=True)
            self._client_tasks.clear()


class UnixSocketInput(BaseInput):
    """Asynchronous Unix Domain Socket log receiver."""

    def __init__(
        self,
        socket_path: str,
        name: str = "unix-socket",
        max_connections: int = 50,
        idle_timeout: float = 30.0,
    ):
        super().__init__(name=name, source_label=f"unix:{socket_path}")
        self.socket_path = socket_path
        self.max_connections = max_connections
        self.idle_timeout = idle_timeout
        self._server: Optional[asyncio.Server] = None
        self._connection_semaphore: Optional[asyncio.Semaphore] = None
        self._active_connections: int = 0
        self._client_tasks: set[asyncio.Task] = set()

    async def start(self, target_queue: asyncio.Queue) -> None:
        """Start listening on Unix Domain Socket."""
        if self._running:
            return
        self._target_queue = target_queue
        self._connection_semaphore = asyncio.Semaphore(self.max_connections)
        self._running = True

        if os.path.exists(self.socket_path):
            try:
                os.unlink(self.socket_path)
            except OSError:
                pass

        self._server = await asyncio.start_unix_server(
            self._handle_client,
            path=self.socket_path,
            limit=MAX_EVENT_SIZE_BYTES * 2,
        )
        # Secure permissions for socket (CWE-377 / CWE-732)
        try:
            os.chmod(self.socket_path, 0o600)
        except OSError:
            pass

    async def _handle_client(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        """Handle incoming Unix socket client."""
        if not self._connection_semaphore:
            writer.close()
            return

        try:
            if self._active_connections >= self.max_connections:
                self._drops_count += 1
                writer.close()
                await writer.wait_closed()
                return
            await self._connection_semaphore.acquire()
        except Exception:
            writer.close()
            return

        self._active_connections += 1
        current_task = asyncio.current_task()
        if current_task:
            self._client_tasks.add(current_task)

        try:
            buffer = ""
            while self._running:
                try:
                    data = await asyncio.wait_for(
                        reader.read(8192), timeout=self.idle_timeout
                    )
                except asyncio.TimeoutError:
                    break
                except (ConnectionResetError, asyncio.CancelledError):
                    break

                if not data:
                    break

                text = data.decode("utf-8", errors="replace")
                buffer += text

                if len(buffer) > MAX_EVENT_SIZE_BYTES * 4:
                    self._drops_count += 1
                    buffer = buffer[-MAX_EVENT_SIZE_BYTES:]

                while "\n" in buffer:
                    line, buffer = buffer.split("\n", 1)
                    line = line.strip("\r")
                    if line:
                        await self.emit(line)

            if buffer.strip():
                await self.emit(buffer.strip())

        except Exception:
            self._errors_count += 1
        finally:
            self._active_connections -= 1
            if self._connection_semaphore:
                self._connection_semaphore.release()
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
            if current_task and current_task in self._client_tasks:
                self._client_tasks.remove(current_task)

    async def stop(self) -> None:
        """Stop Unix socket server and cleanup socket file."""
        self._running = False
        if self._server:
            self._server.close()
            await self._server.wait_closed()
            self._server = None

        for task in list(self._client_tasks):
            if not task.done():
                task.cancel()
        if self._client_tasks:
            await asyncio.gather(*self._client_tasks, return_exceptions=True)
            self._client_tasks.clear()

        if os.path.exists(self.socket_path):
            try:
                os.unlink(self.socket_path)
            except OSError:
                pass
