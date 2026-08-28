"""Asynchronous probe scheduler with concurrency limits and timeout guardrails."""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Awaitable, Callable, Dict, List, Optional, Union

from pydantic import BaseModel, Field

from prober.probes.dns import DNSProbe, DNSProbeResult
from prober.probes.http import HTTPProbe, HTTPProbeResult
from prober.probes.ssl_cert import SSLCertProbe, SSLCertProbeResult
from prober.probes.tcp import TCPProbe, TCPProbeResult

logger = logging.getLogger(__name__)

AnyProbeResult = Union[HTTPProbeResult, TCPProbeResult, SSLCertProbeResult, DNSProbeResult]


class ProbeTarget(BaseModel):
    """Configuration specification for a synthetic probe target."""

    name: str
    probe_type: str = "http"  # http, tcp, ssl, dns
    target: str  # URL or Hostname
    port: int = 443
    record_type: str = "A"  # For DNS
    method: str = "GET"  # For HTTP
    headers: Dict[str, str] = Field(default_factory=dict)
    interval_seconds: float = 30.0
    timeout_seconds: float = 5.0
    verify_ssl: bool = True


class ProbeScheduler:
    """Asynchronous orchestrator executing synthetic probes under strict concurrency control (CWE-400)."""

    def __init__(
        self,
        concurrency_limit: int = 50,
        default_timeout: float = 10.0,
    ) -> None:
        self.concurrency_limit = concurrency_limit
        self.default_timeout = default_timeout
        self._semaphore = asyncio.Semaphore(concurrency_limit)
        self.http_prober = HTTPProbe(default_timeout=default_timeout)
        self.tcp_prober = TCPProbe(default_timeout=default_timeout)
        self.ssl_prober = SSLCertProbe(default_timeout=default_timeout)
        self.dns_prober = DNSProbe(default_timeout=default_timeout)
        self._running = False

    async def execute_target(self, target: ProbeTarget) -> AnyProbeResult:
        """Execute a single probe target bound by concurrency semaphore and timeout constraints."""
        probe_type = target.probe_type.lower()
        timeout = target.timeout_seconds or self.default_timeout

        async with self._semaphore:
            try:
                if probe_type == "http" or probe_type == "https":
                    url = target.target
                    if not (url.startswith("http://") or url.startswith("https://")):
                        url = f"https://{target.target}"
                    return await self.http_prober.probe(
                        url=url,
                        method=target.method,
                        headers=target.headers,
                        timeout=timeout,
                        verify_ssl=target.verify_ssl,
                    )
                elif probe_type == "tcp":
                    return await self.tcp_prober.probe(
                        host=target.target,
                        port=target.port,
                        timeout=timeout,
                    )
                elif probe_type == "ssl" or probe_type == "tls":
                    return await self.ssl_prober.probe(
                        host=target.target,
                        port=target.port,
                        timeout=timeout,
                        verify_ssl=target.verify_ssl,
                    )
                elif probe_type == "dns":
                    return await self.dns_prober.probe(
                        target=target.target,
                        record_type=target.record_type,
                        timeout=timeout,
                    )
                else:
                    return HTTPProbeResult(
                        url=target.target,
                        target_host=target.target,
                        status="ERROR",
                        error=f"Unknown probe_type: {target.probe_type}",
                    )
            except Exception as e:
                logger.error("Error probing %s (%s): %s", target.name, target.target, e)
                return HTTPProbeResult(
                    url=target.target,
                    target_host=target.target,
                    status="ERROR",
                    error=f"Unhandled probe failure: {e}",
                )

    async def run_batch(self, targets: List[ProbeTarget]) -> List[AnyProbeResult]:
        """Run a batch of probe targets concurrently bounded by the semaphore."""
        tasks = [self.execute_target(target) for target in targets]
        return await asyncio.gather(*tasks, return_exceptions=False)

    async def run_loop(
        self,
        targets: List[ProbeTarget],
        callback: Optional[Callable[[ProbeTarget, AnyProbeResult], Union[None, Awaitable[None]]]] = None,
        max_iterations: Optional[int] = None,
    ) -> None:
        """Run continuous periodic probing across all specified targets."""
        self._running = True
        iterations = 0

        async def _schedule_worker(target: ProbeTarget) -> None:
            while self._running:
                result = await self.execute_target(target)
                if callback:
                    try:
                        res = callback(target, result)
                        if asyncio.iscoroutine(res):
                            await res
                    except Exception as cb_err:
                        logger.error("Callback error for %s: %s", target.name, cb_err)
                await asyncio.sleep(target.interval_seconds)

        workers = [asyncio.create_task(_schedule_worker(t)) for t in targets]
        try:
            while self._running:
                if max_iterations is not None and iterations >= max_iterations:
                    break
                iterations += 1
                await asyncio.sleep(1.0)
        finally:
            self._running = False
            for w in workers:
                w.cancel()
            await asyncio.gather(*workers, return_exceptions=True)

    def stop(self) -> None:
        """Stop the running periodic loop."""
        self._running = False
