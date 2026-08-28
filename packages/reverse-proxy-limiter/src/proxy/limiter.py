"""
High-Performance Rate Limiter (Token Bucket & Sliding Window).

Provides per-IP and per-API-Key rate limiting with standard Retry-After
and X-RateLimit headers.
"""

from __future__ import annotations

import math
import re
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple, Union
from pydantic import BaseModel, Field


@dataclass
class RateLimitResult:
    """Outcome of a rate limit check."""
    allowed: bool
    key: str
    limit: int
    remaining: int
    reset_seconds: float
    retry_after: float
    key_type: str = "ip"

    @property
    def headers(self) -> Dict[str, str]:
        """Generate standard HTTP rate limiting headers."""
        hdrs = {
            "X-RateLimit-Limit": str(self.limit),
            "X-RateLimit-Remaining": str(max(0, self.remaining)),
            "X-RateLimit-Reset": str(math.ceil(self.reset_seconds)),
        }
        if not self.allowed:
            hdrs["Retry-After"] = str(math.ceil(self.retry_after))
        return hdrs


class RateLimiterConfig(BaseModel):
    """Configuration for RateLimiter."""
    rate: float = Field(default=100.0, gt=0.0, description="Tokens per second or requests per window")
    capacity: float = Field(default=200.0, gt=0.0, description="Burst capacity for Token Bucket")
    window_seconds: float = Field(default=1.0, gt=0.0, description="Window duration for Sliding Window")
    strategy: str = Field(default="token_bucket", description="'token_bucket' or 'sliding_window'")

    model_config = {"extra": "forbid"}


class TokenBucketLimiter:
    """
    Token Bucket rate limiter supporting smooth continuous refill and burst capacity.
    """

    def __init__(self, rate: float = 100.0, capacity: float = 200.0) -> None:
        self.rate = float(rate)
        self.capacity = float(capacity)
        self._buckets: Dict[str, Tuple[float, float]] = {}  # key -> (tokens, last_refill_timestamp)
        self._lock = threading.Lock()

    def acquire(self, key: str, cost: float = 1.0) -> RateLimitResult:
        """Attempt to consume tokens from the bucket for given key."""
        now = time.monotonic()
        with self._lock:
            if key not in self._buckets:
                tokens = self.capacity
                last_refill = now
            else:
                tokens, last_refill = self._buckets[key]
                elapsed = now - last_refill
                tokens = min(self.capacity, tokens + elapsed * self.rate)
                last_refill = now

            if tokens >= cost:
                tokens -= cost
                self._buckets[key] = (tokens, last_refill)
                remaining = int(tokens)
                reset_secs = (self.capacity - tokens) / self.rate if self.rate > 0 else 0.0
                return RateLimitResult(
                    allowed=True,
                    key=key,
                    limit=int(self.capacity),
                    remaining=remaining,
                    reset_seconds=reset_secs,
                    retry_after=0.0,
                )
            else:
                self._buckets[key] = (tokens, last_refill)
                deficit = cost - tokens
                retry_after = deficit / self.rate if self.rate > 0 else 1.0
                reset_secs = (self.capacity - tokens) / self.rate if self.rate > 0 else 1.0
                return RateLimitResult(
                    allowed=False,
                    key=key,
                    limit=int(self.capacity),
                    remaining=0,
                    reset_seconds=reset_secs,
                    retry_after=max(0.1, retry_after),
                )

    def reset(self, key: Optional[str] = None) -> None:
        """Reset rate limit state for a key or all keys."""
        with self._lock:
            if key is not None:
                self._buckets.pop(key, None)
            else:
                self._buckets.clear()


class SlidingWindowLimiter:
    """
    Sliding Window Log rate limiter tracking exact timestamp windows.
    """

    def __init__(self, window_seconds: float = 60.0, max_requests: int = 100) -> None:
        self.window_seconds = float(window_seconds)
        self.max_requests = int(max_requests)
        self._windows: Dict[str, deque] = defaultdict(deque)
        self._lock = threading.Lock()

    def acquire(self, key: str, cost: int = 1) -> RateLimitResult:
        """Attempt to record request in sliding window."""
        now = time.monotonic()
        cutoff = now - self.window_seconds

        with self._lock:
            dq = self._windows[key]
            # Prune timestamps outside window
            while dq and dq[0] <= cutoff:
                dq.popleft()

            current_count = len(dq)
            if current_count + cost <= self.max_requests:
                for _ in range(cost):
                    dq.append(now)
                remaining = self.max_requests - len(dq)
                reset_secs = (dq[0] + self.window_seconds - now) if dq else 0.0
                return RateLimitResult(
                    allowed=True,
                    key=key,
                    limit=self.max_requests,
                    remaining=remaining,
                    reset_seconds=max(0.0, reset_secs),
                    retry_after=0.0,
                )
            else:
                earliest = dq[0] if dq else now
                retry_after = max(0.1, earliest + self.window_seconds - now)
                return RateLimitResult(
                    allowed=False,
                    key=key,
                    limit=self.max_requests,
                    remaining=0,
                    reset_seconds=retry_after,
                    retry_after=retry_after,
                )

    def reset(self, key: Optional[str] = None) -> None:
        """Reset window state for a key or all keys."""
        with self._lock:
            if key is not None:
                self._windows.pop(key, None)
            else:
                self._windows.clear()


class RateLimiterManager:
    """
    Unified Rate Limiting Manager with IP and API-Key identification,
    custom tiers, and safe key masking (CWE-209).
    """

    def __init__(
        self,
        default_rate: float = 100.0,
        default_capacity: float = 200.0,
        strategy: str = "token_bucket",
        window_seconds: float = 1.0,
        api_key_tiers: Optional[Dict[str, RateLimiterConfig]] = None,
    ) -> None:
        self.strategy = strategy
        self.default_rate = default_rate
        self.default_capacity = default_capacity
        self.window_seconds = window_seconds
        self.api_key_tiers = api_key_tiers or {}

        # Default limiter
        if strategy == "sliding_window":
            self.limiter: Union[TokenBucketLimiter, SlidingWindowLimiter] = SlidingWindowLimiter(
                window_seconds=window_seconds,
                max_requests=int(default_capacity),
            )
        else:
            self.limiter = TokenBucketLimiter(
                rate=default_rate,
                capacity=default_capacity,
            )

        # Tiered limiters for API Keys
        self._tier_limiters: Dict[str, Union[TokenBucketLimiter, SlidingWindowLimiter]] = {}
        for tier_name, config in self.api_key_tiers.items():
            if config.strategy == "sliding_window":
                self._tier_limiters[tier_name] = SlidingWindowLimiter(
                    window_seconds=config.window_seconds,
                    max_requests=int(config.capacity),
                )
            else:
                self._tier_limiters[tier_name] = TokenBucketLimiter(
                    rate=config.rate,
                    capacity=config.capacity,
                )

    @staticmethod
    def mask_key(key: str) -> str:
        """Mask sensitive keys for logging (CWE-209)."""
        if not key:
            return "unknown"
        if len(key) <= 8:
            return "[REDACTED]"
        return f"{key[:4]}...{key[-4:]}"

    def extract_client_key(self, headers: Dict[str, str], client_host: str) -> Tuple[str, str, Optional[str]]:
        """
        Extract identification key from request headers or client host.
        Returns (key, key_type, tier).
        """
        # Look for API Key in X-API-Key header
        api_key = headers.get("x-api-key") or headers.get("api-key")
        if api_key:
            return api_key, "api_key", self._resolve_tier(api_key)

        # Look for Bearer Token in Authorization header
        auth_hdr = headers.get("authorization", "")
        if auth_hdr.lower().startswith("bearer "):
            token = auth_hdr[7:].strip()
            if token:
                return token, "api_key", self._resolve_tier(token)

        # Look for X-Forwarded-For or client host
        xff = headers.get("x-forwarded-for")
        if xff:
            client_ip = xff.split(",")[0].strip()
            if client_ip:
                return client_ip, "ip", None

        ip = client_host or "127.0.0.1"
        return ip, "ip", None

    def _resolve_tier(self, api_key: str) -> Optional[str]:
        """Map API Key to tier prefix if applicable (e.g., 'tier_pro_...')."""
        for tier in self.api_key_tiers:
            if api_key.startswith(f"{tier}_") or f"_{tier}_" in api_key:
                return tier
        return None

    def check(self, headers: Dict[str, str], client_host: str) -> RateLimitResult:
        """Check rate limit for the incoming request."""
        key, key_type, tier = self.extract_client_key(headers, client_host)

        if tier and tier in self._tier_limiters:
            limiter = self._tier_limiters[tier]
        else:
            limiter = self.limiter

        result = limiter.acquire(key)
        result.key_type = key_type
        return result

    def reset(self, key: Optional[str] = None) -> None:
        """Reset rate limiter state."""
        self.limiter.reset(key)
        for t_lim in self._tier_limiters.values():
            t_lim.reset(key)
