"""Asynchronous HTTP Webhook Batch Forwarder with Circuit Breaker and Backoff."""

import asyncio
import time
from typing import Any, Dict, List, Optional
import httpx
from aggregator import LogEvent
from aggregator.outputs import BaseOutput, MAX_BATCH_BYTES


class WebhookOutput(BaseOutput):
    """Batched HTTP POST sink with exponential backoff, timeout, and Circuit Breaker (CWE-400)."""

    def __init__(
        self,
        url: str,
        name: str = "webhook",
        headers: Optional[Dict[str, str]] = None,
        timeout: float = 5.0,
        max_retries: int = 3,
        failure_threshold: int = 5,
        circuit_reset_timeout: float = 10.0,
        client: Optional[httpx.AsyncClient] = None,
    ):
        super().__init__(name=name)
        self.url = url
        self.headers = headers or {"Content-Type": "application/json"}
        self.timeout = timeout
        self.max_retries = max_retries
        self.failure_threshold = failure_threshold
        self.circuit_reset_timeout = circuit_reset_timeout

        self._custom_client = client is not None
        self._client = client

        # Circuit breaker state: "CLOSED", "OPEN", "HALF_OPEN"
        self._circuit_state = "CLOSED"
        self._consecutive_failures = 0
        self._circuit_tripped_time = 0.0
        self._circuit_trips_count = 0

    @property
    def circuit_state(self) -> str:
        """Return current circuit breaker state."""
        if self._circuit_state == "OPEN":
            if time.time() - self._circuit_tripped_time > self.circuit_reset_timeout:
                self._circuit_state = "HALF_OPEN"
        return self._circuit_state

    @property
    def metrics(self) -> Dict[str, Any]:
        """Return output sink operational and circuit breaker metrics."""
        m = super().metrics
        m.update({
            "url": self.url,
            "circuit_state": self.circuit_state,
            "consecutive_failures": self._consecutive_failures,
            "circuit_trips": self._circuit_trips_count,
        })
        return m

    async def start(self) -> None:
        """Initialize HTTP client."""
        await super().start()
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=self.timeout)

    async def stop(self) -> None:
        """Close HTTP client."""
        await super().stop()
        if self._client and not self._custom_client:
            await self._client.aclose()
            self._client = None

    def _trip_circuit(self) -> None:
        """Trip circuit breaker to OPEN."""
        self._circuit_state = "OPEN"
        self._circuit_tripped_time = time.time()
        self._circuit_trips_count += 1

    def _reset_circuit(self) -> None:
        """Reset circuit breaker to CLOSED."""
        self._circuit_state = "CLOSED"
        self._consecutive_failures = 0

    async def send_batch(self, events: List[LogEvent]) -> bool:
        """Forward batch of events as HTTP POST payload with retry and circuit breaker."""
        if not events:
            return True

        if self.circuit_state == "OPEN":
            # Circuit is OPEN, drop or let buffer retain without HTTP overhead
            self._errors_count += 1
            return False

        if self._client is None:
            self._client = httpx.AsyncClient(timeout=self.timeout)

        payload = [e.to_dict() for e in events]

        # Retry loop with exponential backoff
        for attempt in range(self.max_retries + 1):
            try:
                response = await self._client.post(
                    self.url,
                    json=payload,
                    headers=self.headers,
                    timeout=self.timeout,
                )

                if response.status_code in (200, 201, 202, 204):
                    self._events_sent += len(events)
                    self._batches_sent += 1
                    self._reset_circuit()
                    return True
                else:
                    self._errors_count += 1
                    if attempt < self.max_retries:
                        self._retries_count += 1
                        await asyncio.sleep(0.05 * (2 ** attempt))

            except Exception:
                self._errors_count += 1
                if attempt < self.max_retries:
                    self._retries_count += 1
                    await asyncio.sleep(0.05 * (2 ** attempt))

        # All retries failed
        self._consecutive_failures += 1
        if self._consecutive_failures >= self.failure_threshold:
            self._trip_circuit()

        return False
