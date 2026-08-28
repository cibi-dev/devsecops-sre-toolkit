"""Unit tests for Token Bucket and Sliding Window rate limiting."""

import secrets
import time
import pytest
from pydantic import ValidationError

from proxy.limiter import (
    RateLimiterConfig,
    RateLimiterManager,
    RateLimitResult,
    SlidingWindowLimiter,
    TokenBucketLimiter,
)


def test_token_bucket_initial_capacity():
    limiter = TokenBucketLimiter(rate=10.0, capacity=20.0)
    res = limiter.acquire("user1", cost=5.0)
    assert res.allowed is True
    assert res.remaining == 15
    assert res.limit == 20
    assert res.retry_after == 0.0


def test_token_bucket_exhaustion_and_refill():
    limiter = TokenBucketLimiter(rate=5.0, capacity=5.0)
    res1 = limiter.acquire("ip1", cost=5.0)
    assert res1.allowed is True
    assert res1.remaining == 0

    # Exhausted -> reject
    res2 = limiter.acquire("ip1", cost=1.0)
    assert res2.allowed is False
    assert res2.retry_after > 0
    assert "Retry-After" in res2.headers

    # Wait for refill
    time.sleep(0.25)
    res3 = limiter.acquire("ip1", cost=1.0)
    assert res3.allowed is True


def test_token_bucket_reset():
    limiter = TokenBucketLimiter(rate=1.0, capacity=2.0)
    limiter.acquire("ip1", cost=2.0)
    res = limiter.acquire("ip1", cost=1.0)
    assert res.allowed is False

    limiter.reset("ip1")
    res_after = limiter.acquire("ip1", cost=1.0)
    assert res_after.allowed is True


def test_sliding_window_limiter():
    limiter = SlidingWindowLimiter(window_seconds=0.2, max_requests=3)
    assert limiter.acquire("key1").allowed is True
    assert limiter.acquire("key1").allowed is True
    assert limiter.acquire("key1").allowed is True
    # 4th request in window rejected
    res = limiter.acquire("key1")
    assert res.allowed is False
    assert res.retry_after > 0

    # Sleep past window
    time.sleep(0.22)
    assert limiter.acquire("key1").allowed is True


def test_sliding_window_reset():
    limiter = SlidingWindowLimiter(window_seconds=1.0, max_requests=1)
    assert limiter.acquire("key1").allowed is True
    assert limiter.acquire("key1").allowed is False
    limiter.reset("key1")
    assert limiter.acquire("key1").allowed is True


def test_rate_limiter_manager_ip_extraction():
    mgr = RateLimiterManager(default_rate=10.0, default_capacity=10.0)

    # Standard client host
    key, k_type, tier = mgr.extract_client_key({}, "192.168.1.100")
    assert key == "192.168.1.100"
    assert k_type == "ip"
    assert tier is None

    # X-Forwarded-For precedence
    key, k_type, _ = mgr.extract_client_key({"x-forwarded-for": "10.0.0.1, 10.0.0.2"}, "192.168.1.1")
    assert key == "10.0.0.1"
    assert k_type == "ip"


def test_rate_limiter_manager_api_key_extraction():
    mgr = RateLimiterManager()

    # Dynamic test key
    test_key = f"demo_{secrets.token_hex(8)}"
    key, k_type, _ = mgr.extract_client_key({"x-api-key": test_key}, "127.0.0.1")
    assert key == test_key
    assert k_type == "api_key"

    # Authorization Bearer
    test_token = f"demo_jwt_{secrets.token_hex(8)}"
    key, k_type, _ = mgr.extract_client_key({"authorization": f"Bearer {test_token}"}, "127.0.0.1")
    assert key == test_token
    assert k_type == "api_key"


def test_rate_limiter_manager_tiered_limits():
    tiers = {
        "premium": RateLimiterConfig(rate=100.0, capacity=100.0, strategy="token_bucket"),
        "free": RateLimiterConfig(rate=2.0, capacity=2.0, strategy="token_bucket"),
    }
    mgr = RateLimiterManager(default_rate=5.0, default_capacity=5.0, api_key_tiers=tiers)

    # Free tier key
    res_free = mgr.check({"x-api-key": "free_user_key_999"}, "127.0.0.1")
    assert res_free.allowed is True
    assert res_free.limit == 2

    # Premium tier key
    res_prem = mgr.check({"x-api-key": "premium_user_key_777"}, "127.0.0.1")
    assert res_prem.allowed is True
    assert res_prem.limit == 100


def test_rate_limiter_manager_mask_key():
    assert RateLimiterManager.mask_key("") == "unknown"
    assert RateLimiterManager.mask_key("short") == "[REDACTED]"
    sample = "user_" + secrets.token_hex(8)
    masked = RateLimiterManager.mask_key(sample)
    assert masked.startswith(sample[:4])
    assert masked.endswith(sample[-4:])


def test_rate_limiter_config_validation():
    with pytest.raises(ValidationError):
        RateLimiterConfig(rate=-5.0)

    with pytest.raises(ValidationError):
        RateLimiterConfig(invalid_option="bad")
