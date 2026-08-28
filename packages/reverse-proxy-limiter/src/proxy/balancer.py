"""
High-Performance Load Balancer with Active & Passive Health Checks.

Supports Round-Robin, Least-Connections, Random, and IP-Hash strategies with
dynamic failover and integrated per-node Circuit Breaker protection.
"""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from enum import Enum
import hashlib
import logging
import secrets
import time
from typing import AsyncIterator, Dict, List, Optional, Union
from pydantic import BaseModel, Field

from proxy.circuit_breaker import CircuitBreaker, CircuitBreakerConfig, CircuitState

logger = logging.getLogger("proxy.balancer")


class BalancerStrategy(str, Enum):
    ROUND_ROBIN = "round_robin"
    LEAST_CONNECTIONS = "least_connections"
    RANDOM = "random"
    IP_HASH = "ip_hash"


class NoHealthyUpstreamError(Exception):
    """Raised when no healthy upstream node is available in the pool."""
    pass


class UpstreamNodeConfig(BaseModel):
    """Configuration for an individual upstream target."""
    url: str = Field(description="Base URL of upstream node (e.g. http://127.0.0.1:8080)")
    weight: int = Field(default=1, ge=1, description="Traffic weight")
    health_endpoint: str = Field(default="/health", description="Health check path")
    failure_threshold: int = Field(default=3, ge=1, description="Consecutive failures to mark dead")
    success_threshold: int = Field(default=2, ge=1, description="Consecutive successes to recover")

    model_config = {"extra": "forbid"}


class UpstreamNode:
    """Represents an active upstream node in the load balancer pool."""

    def __init__(
        self,
        url: str,
        weight: int = 1,
        health_endpoint: str = "/health",
        failure_threshold: int = 3,
        success_threshold: int = 2,
        circuit_config: Optional[CircuitBreakerConfig] = None,
    ) -> None:
        self.url = url.rstrip("/")
        self.weight = max(1, weight)
        self.health_endpoint = health_endpoint if health_endpoint.startswith("/") else f"/{health_endpoint}"
        self.failure_threshold = failure_threshold
        self.success_threshold = success_threshold

        self.is_healthy: bool = True
        self.active_connections: int = 0
        self.consecutive_failures: int = 0
        self.consecutive_successes: int = 0
        self.last_checked: float = 0.0
        self.last_latency_ms: float = 0.0
        self.total_requests: int = 0
        self.total_errors: int = 0

        self.circuit_breaker = CircuitBreaker(
            name=f"cb_{self.url}",
            config=circuit_config or CircuitBreakerConfig(),
        )

    def is_available(self) -> bool:
        """Node is available if actively marked healthy and circuit is not OPEN."""
        return self.is_healthy and self.circuit_breaker.current_state != CircuitState.OPEN

    def record_success(self, latency_ms: float = 0.0) -> None:
        """Record successful transaction."""
        self.total_requests += 1
        self.consecutive_failures = 0
        self.consecutive_successes += 1
        self.last_latency_ms = latency_ms
        if not self.is_healthy and self.consecutive_successes >= self.success_threshold:
            self.is_healthy = True
            logger.info("Upstream node recovered to healthy: %s", self.url)
        self.circuit_breaker.record_success()

    def record_failure(self, exc: Optional[Exception] = None) -> None:
        """Record failed transaction."""
        self.total_requests += 1
        self.total_errors += 1
        self.consecutive_successes = 0
        self.consecutive_failures += 1
        if self.is_healthy and self.consecutive_failures >= self.failure_threshold:
            self.is_healthy = False
            logger.warning("Upstream node marked unhealthy: %s (failures=%d)", self.url, self.consecutive_failures)
        self.circuit_breaker.record_failure(exc)

    def to_dict(self) -> Dict[str, Union[str, int, float, bool, dict]]:
        """Diagnostic state serialization."""
        return {
            "url": self.url,
            "weight": self.weight,
            "is_healthy": self.is_healthy,
            "is_available": self.is_available(),
            "active_connections": self.active_connections,
            "consecutive_failures": self.consecutive_failures,
            "consecutive_successes": self.consecutive_successes,
            "last_latency_ms": round(self.last_latency_ms, 2),
            "total_requests": self.total_requests,
            "total_errors": self.total_errors,
            "circuit_breaker": self.circuit_breaker.get_status(),
        }


class LoadBalancer:
    """
    High-Performance Async Load Balancer supporting multiple balancing algorithms.
    """

    def __init__(
        self,
        strategy: Union[BalancerStrategy, str] = BalancerStrategy.ROUND_ROBIN,
        circuit_config: Optional[CircuitBreakerConfig] = None,
    ) -> None:
        if isinstance(strategy, str):
            strategy = BalancerStrategy(strategy.lower())
        self.strategy = strategy
        self.circuit_config = circuit_config or CircuitBreakerConfig()
        self.nodes: List[UpstreamNode] = []
        self._rr_index: int = 0
        self._lock = asyncio.Lock()
        self._health_check_task: Optional[asyncio.Task] = None
        self._running_health_checks: bool = False

    def add_node(
        self,
        node_or_url: Union[UpstreamNode, str],
        weight: int = 1,
        health_endpoint: str = "/health",
    ) -> UpstreamNode:
        """Add an upstream node to the pool."""
        if isinstance(node_or_url, UpstreamNode):
            node = node_or_url
        else:
            node = UpstreamNode(
                url=node_or_url,
                weight=weight,
                health_endpoint=health_endpoint,
                circuit_config=self.circuit_config,
            )
        # Avoid duplicate URLs
        self.remove_node(node.url)
        self.nodes.append(node)
        return node

    def remove_node(self, url: str) -> bool:
        """Remove an upstream node by URL."""
        clean_url = url.rstrip("/")
        initial_len = len(self.nodes)
        self.nodes = [n for n in self.nodes if n.url != clean_url]
        return len(self.nodes) < initial_len

    def get_healthy_nodes(self) -> List[UpstreamNode]:
        """Return list of currently available upstream nodes."""
        return [n for n in self.nodes if n.is_available()]

    def select_node(self, client_key: Optional[str] = None) -> UpstreamNode:
        """
        Select an upstream node according to configured strategy.
        Raises NoHealthyUpstreamError if no node is configured in the pool.
        """
        if not self.nodes:
            raise NoHealthyUpstreamError("No upstream nodes configured in pool")

        available = [n for n in self.nodes if n.is_available()]
        if not available:
            available = self.nodes

        if self.strategy == BalancerStrategy.ROUND_ROBIN:
            idx = self._rr_index % len(available)
            self._rr_index = (self._rr_index + 1) % 1_000_000
            return available[idx]

        elif self.strategy == BalancerStrategy.LEAST_CONNECTIONS:
            return min(available, key=lambda n: (n.active_connections, n.total_requests))

        elif self.strategy == BalancerStrategy.RANDOM:
            idx = secrets.randbelow(len(available))
            return available[idx]

        elif self.strategy == BalancerStrategy.IP_HASH:
            key = client_key or "127.0.0.1"
            hash_val = int(hashlib.sha256(key.encode("utf-8")).hexdigest(), 16)
            return available[hash_val % len(available)]

        return available[0]

    @asynccontextmanager
    async def connection_scope(self, node: UpstreamNode) -> AsyncIterator[UpstreamNode]:
        """Async context manager to safely track active connections per node."""
        node.active_connections += 1
        start_time = time.monotonic()
        try:
            yield node
        finally:
            node.active_connections = max(0, node.active_connections - 1)

    async def check_node_health(self, node: UpstreamNode, timeout: float = 2.0) -> bool:
        """Perform an active HTTP health probe against upstream node."""
        import httpx

        target_url = f"{node.url}{node.health_endpoint}"
        start_time = time.monotonic()
        node.last_checked = start_time

        try:
            async with httpx.AsyncClient(timeout=timeout) as client:
                resp = await client.get(target_url)
                latency_ms = (time.monotonic() - start_time) * 1000.0
                if 200 <= resp.status_code < 400:
                    node.record_success(latency_ms)
                    return True
                else:
                    node.record_failure()
                    return False
        except Exception as exc:
            node.record_failure(exc)
            return False

    async def run_health_checks(self, timeout: float = 2.0) -> Dict[str, bool]:
        """Run a single cycle of health checks across all upstream nodes."""
        results = {}
        for node in list(self.nodes):
            res = await self.check_node_health(node, timeout=timeout)
            results[node.url] = res
        return results

    async def start_health_checks_loop(self, interval: float = 10.0, timeout: float = 2.0) -> None:
        """Background health check loop."""
        self._running_health_checks = True
        try:
            while self._running_health_checks:
                await self.run_health_checks(timeout=timeout)
                await asyncio.sleep(interval)
        except asyncio.CancelledError:
            self._running_health_checks = False

    def start_background_health_checks(self, interval: float = 10.0, timeout: float = 2.0) -> None:
        """Launch background health checking task."""
        if self._health_check_task is None or self._health_check_task.done():
            self._health_check_task = asyncio.create_task(
                self.start_health_checks_loop(interval=interval, timeout=timeout)
            )

    def stop_background_health_checks(self) -> None:
        """Cancel background health checking task."""
        self._running_health_checks = False
        if self._health_check_task is not None and not self._health_check_task.done():
            self._health_check_task.cancel()
            self._health_check_task = None
