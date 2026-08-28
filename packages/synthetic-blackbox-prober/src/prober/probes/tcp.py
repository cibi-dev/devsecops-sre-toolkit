"""TCP Ping and Port Connectivity synthetic probe module."""

from __future__ import annotations

import asyncio
import socket
import time
from datetime import datetime, timezone
from typing import Optional

from pydantic import BaseModel, Field


class TCPProbeResult(BaseModel):
    """Result model for TCP ping probing."""

    host: str
    port: int
    connected: bool = False
    latency_ms: float = 0.0
    resolved_ip: Optional[str] = None
    status: str = "SUCCESS"  # SUCCESS, CONNECTION_REFUSED, TIMEOUT, ERROR
    error: Optional[str] = None
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def is_success(self) -> bool:
        """Check if TCP connection succeeded."""
        return self.connected and self.status == "SUCCESS"


class TCPProbe:
    """Asynchronous TCP connectivity probe measuring round-trip connection latency."""

    def __init__(self, default_timeout: float = 5.0) -> None:
        self.default_timeout = default_timeout

    async def probe(
        self,
        host: str,
        port: int,
        timeout: Optional[float] = None,
    ) -> TCPProbeResult:
        """Execute an asynchronous TCP ping probe against target:port.

        Args:
            host: Target hostname or IP address.
            port: Target TCP port.
            timeout: Connection timeout in seconds (default: 5.0).

        Returns:
            TCPProbeResult with connection state, latency and status.
        """
        eff_timeout = timeout if timeout is not None else self.default_timeout
        clean_host = host.strip()
        start_time = time.perf_counter()
        writer: Optional[asyncio.StreamWriter] = None

        try:
            async with asyncio.timeout(eff_timeout):
                reader, writer = await asyncio.open_connection(
                    host=clean_host,
                    port=port,
                )

            latency_ms = (time.perf_counter() - start_time) * 1000.0

            # Extract resolved remote IP address if available
            peer_info = writer.get_extra_info("peername")
            resolved_ip = peer_info[0] if peer_info and isinstance(peer_info, tuple) else None

            # Gracefully close socket
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

            return TCPProbeResult(
                host=clean_host,
                port=port,
                connected=True,
                latency_ms=round(latency_ms, 3),
                resolved_ip=resolved_ip,
                status="SUCCESS",
                error=None,
            )

        except TimeoutError:
            latency_ms = (time.perf_counter() - start_time) * 1000.0
            return TCPProbeResult(
                host=clean_host,
                port=port,
                connected=False,
                latency_ms=round(latency_ms, 3),
                status="TIMEOUT",
                error=f"TCP connection timed out after {eff_timeout}s",
            )
        except ConnectionRefusedError as e:
            latency_ms = (time.perf_counter() - start_time) * 1000.0
            return TCPProbeResult(
                host=clean_host,
                port=port,
                connected=False,
                latency_ms=round(latency_ms, 3),
                status="CONNECTION_REFUSED",
                error=f"Connection refused on port {port}: {e}",
            )
        except socket.gaierror as e:
            latency_ms = (time.perf_counter() - start_time) * 1000.0
            return TCPProbeResult(
                host=clean_host,
                port=port,
                connected=False,
                latency_ms=round(latency_ms, 3),
                status="ERROR",
                error=f"Host resolution failed: {e}",
            )
        except Exception as e:
            latency_ms = (time.perf_counter() - start_time) * 1000.0
            return TCPProbeResult(
                host=clean_host,
                port=port,
                connected=False,
                latency_ms=round(latency_ms, 3),
                status="ERROR",
                error=f"TCP connection error: {e}",
            )
        finally:
            if writer is not None:
                try:
                    writer.close()
                except Exception:
                    pass
