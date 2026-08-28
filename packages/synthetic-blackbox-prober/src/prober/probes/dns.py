"""DNS Resolution synthetic probe module."""

from __future__ import annotations

import asyncio
import socket
import time
from datetime import datetime, timezone
from typing import List, Optional

from pydantic import BaseModel, Field


class DNSProbeResult(BaseModel):
    """Result model for DNS synthetic probing."""

    target: str
    record_type: str = "A"
    resolved_records: List[str] = Field(default_factory=list)
    canonical_name: Optional[str] = None
    latency_ms: float = 0.0
    status: str = "SUCCESS"  # SUCCESS, NXDOMAIN, TIMEOUT, ERROR
    error: Optional[str] = None
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def is_success(self) -> bool:
        """Check if DNS resolution succeeded."""
        return self.status == "SUCCESS" and len(self.resolved_records) > 0


class DNSProbe:
    """Asynchronous DNS probe measuring resolution latency and record consistency."""

    def __init__(self, default_timeout: float = 5.0) -> None:
        self.default_timeout = default_timeout

    async def probe(
        self,
        target: str,
        record_type: str = "A",
        timeout: Optional[float] = None,
    ) -> DNSProbeResult:
        """Execute an asynchronous DNS lookup probe.

        Args:
            target: Hostname to resolve.
            record_type: Record family ("A", "AAAA", "CNAME", "ANY").
            timeout: Query timeout in seconds.

        Returns:
            DNSProbeResult containing resolved IP addresses and latency in ms.
        """
        eff_timeout = timeout if timeout is not None else self.default_timeout
        record_type_upper = record_type.upper()
        clean_target = target.strip()

        family = socket.AF_UNSPEC
        if record_type_upper == "A":
            family = socket.AF_INET
        elif record_type_upper == "AAAA":
            family = socket.AF_INET6

        loop = asyncio.get_running_loop()
        start_time = time.perf_counter()

        try:
            # We use AI_CANONNAME to retrieve canonical name if available
            flags = socket.AI_CANONNAME if record_type_upper == "CNAME" else 0
            
            # Non-blocking getaddrinfo wrapped in strict timeout
            async with asyncio.timeout(eff_timeout):
                addrinfo = await loop.getaddrinfo(
                    clean_target,
                    None,
                    family=family,
                    type=socket.SOCK_STREAM,
                    flags=flags,
                )

            latency_ms = (time.perf_counter() - start_time) * 1000.0
            
            resolved_ips: list[str] = []
            canonical_name: Optional[str] = None

            for entry in addrinfo:
                sockaddr = entry[4]
                ip = str(sockaddr[0])
                if ip not in resolved_ips:
                    resolved_ips.append(ip)
                if entry[3] and not canonical_name:
                    canonical_name = entry[3]

            if not resolved_ips:
                return DNSProbeResult(
                    target=clean_target,
                    record_type=record_type_upper,
                    latency_ms=latency_ms,
                    status="NXDOMAIN",
                    error="No records found",
                )

            return DNSProbeResult(
                target=clean_target,
                record_type=record_type_upper,
                resolved_records=resolved_ips,
                canonical_name=canonical_name,
                latency_ms=round(latency_ms, 3),
                status="SUCCESS",
                error=None,
            )

        except TimeoutError:
            latency_ms = (time.perf_counter() - start_time) * 1000.0
            return DNSProbeResult(
                target=clean_target,
                record_type=record_type_upper,
                latency_ms=round(latency_ms, 3),
                status="TIMEOUT",
                error=f"DNS resolution timed out after {eff_timeout}s",
            )
        except socket.gaierror as e:
            latency_ms = (time.perf_counter() - start_time) * 1000.0
            # Common gaierror codes for NXDOMAIN / host not found
            err_str = str(e)
            status = "NXDOMAIN" if e.errno in (-2, -3, -5, 11001) or "Name or service not known" in err_str or "nodename nor servname provided" in err_str else "ERROR"
            return DNSProbeResult(
                target=clean_target,
                record_type=record_type_upper,
                latency_ms=round(latency_ms, 3),
                status=status,
                error=f"DNS resolution failed: {e}",
            )
        except Exception as e:
            latency_ms = (time.perf_counter() - start_time) * 1000.0
            return DNSProbeResult(
                target=clean_target,
                record_type=record_type_upper,
                latency_ms=round(latency_ms, 3),
                status="ERROR",
                error=f"Unexpected DNS error: {e}",
            )
