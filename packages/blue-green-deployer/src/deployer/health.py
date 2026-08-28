"""Active HTTP health check probing module with retries, timeouts, and payload verification."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional

import httpx

from deployer.config import DeployerConfig, EnvironmentSlot, HealthCheckConfig, TargetEnvironmentConfig


@dataclass
class HealthProbeResult:
    """Outcome of a single individual HTTP probe attempt."""

    success: bool
    status_code: Optional[int] = None
    latency_ms: float = 0.0
    body_preview: Optional[str] = None
    error_message: Optional[str] = None
    timestamp: float = field(default_factory=time.time)


@dataclass
class HealthCheckResult:
    """Aggregated result of multi-attempt health check verification."""

    slot: EnvironmentSlot
    target_url: str
    healthy: bool
    consecutive_successes: int
    required_successes: int
    total_attempts: int
    total_duration_ms: float
    history: List[HealthProbeResult] = field(default_factory=list)
    message: str = ""

    def to_dict(self) -> Dict[str, object]:
        """Convert result to serializable dictionary."""
        return {
            "slot": self.slot.value,
            "target_url": self.target_url,
            "healthy": self.healthy,
            "consecutive_successes": self.consecutive_successes,
            "required_successes": self.required_successes,
            "total_attempts": self.total_attempts,
            "total_duration_ms": round(self.total_duration_ms, 2),
            "message": self.message,
            "attempts": [
                {
                    "success": p.success,
                    "status_code": p.status_code,
                    "latency_ms": round(p.latency_ms, 2),
                    "error": p.error_message,
                }
                for p in self.history
            ],
        }


class HealthChecker:
    """Active HTTP health check client for validating Blue/Green endpoints."""

    def __init__(self, config: Optional[HealthCheckConfig] = None) -> None:
        self.config = config or HealthCheckConfig()

    def probe_once(
        self,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        client: Optional[httpx.Client] = None,
    ) -> HealthProbeResult:
        """Perform a single HTTP probe against the specified URL.

        Args:
            url: Full HTTP URL to probe.
            headers: Optional request headers.
            client: Optional reusable httpx.Client instance.

        Returns:
            HealthProbeResult detailing success, status code, latency, and errors.
        """
        start = time.perf_counter()
        req_headers = headers or {}

        def _do_request(c: httpx.Client) -> HealthProbeResult:
            try:
                resp = c.get(url, headers=req_headers, timeout=self.config.timeout_seconds)
                elapsed_ms = (time.perf_counter() - start) * 1000.0

                is_status_ok = resp.status_code == self.config.expected_status
                body_text = resp.text[:500] if resp.text else ""

                if not is_status_ok:
                    return HealthProbeResult(
                        success=False,
                        status_code=resp.status_code,
                        latency_ms=elapsed_ms,
                        body_preview=body_text,
                        error_message=f"Status code {resp.status_code} != expected {self.config.expected_status}",
                    )

                if self.config.expected_body_contains:
                    if self.config.expected_body_contains not in body_text:
                        return HealthProbeResult(
                            success=False,
                            status_code=resp.status_code,
                            latency_ms=elapsed_ms,
                            body_preview=body_text,
                            error_message=(
                                f"Body did not contain expected substring: '{self.config.expected_body_contains}'"
                            ),
                        )

                return HealthProbeResult(
                    success=True,
                    status_code=resp.status_code,
                    latency_ms=elapsed_ms,
                    body_preview=body_text,
                )

            except httpx.TimeoutException as exc:
                elapsed_ms = (time.perf_counter() - start) * 1000.0
                return HealthProbeResult(
                    success=False,
                    latency_ms=elapsed_ms,
                    error_message=f"Request timeout after {self.config.timeout_seconds}s: {exc}",
                )
            except httpx.RequestError as exc:
                elapsed_ms = (time.perf_counter() - start) * 1000.0
                return HealthProbeResult(
                    success=False,
                    latency_ms=elapsed_ms,
                    error_message=f"HTTP request error: {exc}",
                )
            except Exception as exc:
                elapsed_ms = (time.perf_counter() - start) * 1000.0
                return HealthProbeResult(
                    success=False,
                    latency_ms=elapsed_ms,
                    error_message=f"Unexpected health probe error: {exc}",
                )

        if client is not None:
            return _do_request(client)
        else:
            with httpx.Client(verify=self.config.verify_ssl) as default_client:
                return _do_request(default_client)

    def check_target(
        self,
        target: TargetEnvironmentConfig,
        custom_retries: Optional[int] = None,
        custom_interval: Optional[float] = None,
        custom_required_consecutive: Optional[int] = None,
    ) -> HealthCheckResult:
        """Probe a target environment repeatedly until consecutive success criteria are met or retries exhausted.

        Args:
            target: Target environment configuration (Blue or Green).
            custom_retries: Optional override for max retries.
            custom_interval: Optional override for sleep interval between retries.
            custom_required_consecutive: Optional override for required consecutive successes.

        Returns:
            HealthCheckResult with comprehensive metrics and history.
        """
        max_retries = custom_retries if custom_retries is not None else self.config.max_retries
        interval = custom_interval if custom_interval is not None else self.config.retry_interval_seconds
        required_success = (
            custom_required_consecutive
            if custom_required_consecutive is not None
            else self.config.consecutive_successes_required
        )

        history: List[HealthProbeResult] = []
        consecutive_successes = 0
        start_time = time.perf_counter()

        with httpx.Client(verify=self.config.verify_ssl) as client:
            for attempt in range(1, max_retries + 1):
                probe = self.probe_once(url=target.url, headers=target.headers, client=client)
                history.append(probe)

                if probe.success:
                    consecutive_successes += 1
                    if consecutive_successes >= required_success:
                        total_duration_ms = (time.perf_counter() - start_time) * 1000.0
                        return HealthCheckResult(
                            slot=target.name,
                            target_url=target.url,
                            healthy=True,
                            consecutive_successes=consecutive_successes,
                            required_successes=required_success,
                            total_attempts=attempt,
                            total_duration_ms=total_duration_ms,
                            history=history,
                            message=f"Environment {target.name.value.upper()} is healthy ({consecutive_successes}/{required_success} consecutive passes).",
                        )
                else:
                    consecutive_successes = 0

                if attempt < max_retries:
                    time.sleep(interval)

        total_duration_ms = (time.perf_counter() - start_time) * 1000.0
        last_error = history[-1].error_message if history else "Unknown error"
        return HealthCheckResult(
            slot=target.name,
            target_url=target.url,
            healthy=False,
            consecutive_successes=consecutive_successes,
            required_successes=required_success,
            total_attempts=len(history),
            total_duration_ms=total_duration_ms,
            history=history,
            message=(
                f"Health check failed for {target.name.value.upper()} after {len(history)} attempts. "
                f"Consecutive passes: {consecutive_successes}/{required_success}. Last error: {last_error}"
            ),
        )

    def check_slot(self, slot: EnvironmentSlot, deployer_config: DeployerConfig) -> HealthCheckResult:
        """Check the health of a specific slot from a DeployerConfig."""
        target_cfg = deployer_config.get_slot_config(slot)
        return self.check_target(target_cfg)
