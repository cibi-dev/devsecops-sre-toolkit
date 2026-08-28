"""Asynchronous UDP Syslog Log Receiver."""

import asyncio
from typing import Optional, Tuple
from aggregator import MAX_EVENT_SIZE_BYTES
from aggregator.inputs import BaseInput


class _SyslogUDPProtocol(asyncio.DatagramProtocol):
    """Internal Datagram Protocol handling incoming UDP packets."""

    def __init__(self, parent_input: "SyslogUDPInput"):
        self.parent = parent_input

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self.parent._transport = transport

    def datagram_received(self, data: bytes, addr: Tuple[str, int]) -> None:
        if not self.parent.is_running:
            return

        if len(data) > MAX_EVENT_SIZE_BYTES:
            self.parent._drops_count += 1
            data = data[:MAX_EVENT_SIZE_BYTES]

        text = data.decode("utf-8", errors="replace")
        # Syslog UDP messages may contain multiple lines or single line
        lines = [line.strip("\r") for line in text.split("\n") if line.strip("\r")]
        if not lines:
            return

        for line in lines:
            if line:
                asyncio.create_task(self.parent.emit(line))

    def error_received(self, exc: Exception) -> None:
        self.parent._errors_count += 1


class SyslogUDPInput(BaseInput):
    """Asynchronous Syslog UDP Receiver (RFC 3164 / RFC 5424 over UDP)."""

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 5140,
        name: str = "syslog-udp",
    ):
        super().__init__(name=name, source_label=f"syslog-udp:{host}:{port}")
        self.host = host
        self.port = port
        self._transport: Optional[asyncio.BaseTransport] = None

    async def start(self, target_queue: asyncio.Queue) -> None:
        """Bind and start UDP listener."""
        if self._running:
            return
        self._target_queue = target_queue
        self._running = True

        loop = asyncio.get_running_loop()
        transport, _ = await loop.create_datagram_endpoint(
            lambda: _SyslogUDPProtocol(self),
            local_addr=(self.host, self.port),
        )
        self._transport = transport

    async def stop(self) -> None:
        """Stop UDP listener and close transport."""
        self._running = False
        if self._transport:
            self._transport.close()
            self._transport = None
