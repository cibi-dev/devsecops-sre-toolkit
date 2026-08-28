"""Unit tests for Load Balancer and health check mechanism."""

import asyncio
import pytest
from pydantic import ValidationError

from proxy.balancer import (
    BalancerStrategy,
    LoadBalancer,
    NoHealthyUpstreamError,
    UpstreamNode,
    UpstreamNodeConfig,
)
from proxy.circuit_breaker import CircuitState


def test_upstream_node_config_validation():
    cfg = UpstreamNodeConfig(url="http://127.0.0.1:8080", weight=2)
    assert cfg.url == "http://127.0.0.1:8080"
    assert cfg.weight == 2

    with pytest.raises(ValidationError):
        UpstreamNodeConfig(url="http://127.0.0.1:8080", weight=0)


def test_round_robin_balancer():
    lb = LoadBalancer(strategy=BalancerStrategy.ROUND_ROBIN)
    n1 = lb.add_node("http://10.0.0.1:8080")
    n2 = lb.add_node("http://10.0.0.2:8080")
    n3 = lb.add_node("http://10.0.0.3:8080")

    selected = [lb.select_node().url for _ in range(6)]
    assert selected == [
        "http://10.0.0.1:8080",
        "http://10.0.0.2:8080",
        "http://10.0.0.3:8080",
        "http://10.0.0.1:8080",
        "http://10.0.0.2:8080",
        "http://10.0.0.3:8080",
    ]


def test_least_connections_balancer():
    lb = LoadBalancer(strategy=BalancerStrategy.LEAST_CONNECTIONS)
    n1 = lb.add_node("http://10.0.0.1:8080")
    n2 = lb.add_node("http://10.0.0.2:8080")

    n1.active_connections = 5
    n2.active_connections = 1

    selected = lb.select_node()
    assert selected.url == "http://10.0.0.2:8080"

    n2.active_connections = 10
    selected2 = lb.select_node()
    assert selected2.url == "http://10.0.0.1:8080"


def test_random_balancer():
    lb = LoadBalancer(strategy=BalancerStrategy.RANDOM)
    lb.add_node("http://10.0.0.1:8080")
    lb.add_node("http://10.0.0.2:8080")
    selected = lb.select_node()
    assert selected.url in ["http://10.0.0.1:8080", "http://10.0.0.2:8080"]


def test_ip_hash_balancer():
    lb = LoadBalancer(strategy=BalancerStrategy.IP_HASH)
    lb.add_node("http://10.0.0.1:8080")
    lb.add_node("http://10.0.0.2:8080")

    # Consistent hashing: same IP always maps to same node
    node_ip1_a = lb.select_node(client_key="192.168.1.50")
    node_ip1_b = lb.select_node(client_key="192.168.1.50")
    assert node_ip1_a.url == node_ip1_b.url


def test_balancer_node_add_remove():
    lb = LoadBalancer()
    lb.add_node("http://10.0.0.1:8080")
    assert len(lb.nodes) == 1

    # Adding same URL replaces existing
    lb.add_node("http://10.0.0.1:8080")
    assert len(lb.nodes) == 1

    assert lb.remove_node("http://10.0.0.1:8080") is True
    assert len(lb.nodes) == 0
    assert lb.remove_node("http://10.0.0.1:8080") is False


def test_balancer_empty_pool_raises():
    lb = LoadBalancer()
    with pytest.raises(NoHealthyUpstreamError):
        lb.select_node()


def test_upstream_node_passive_health():
    node = UpstreamNode(url="http://10.0.0.1:8080", failure_threshold=2, success_threshold=2)
    assert node.is_healthy is True

    node.record_failure()
    assert node.is_healthy is True

    node.record_failure()
    assert node.is_healthy is False
    assert node.is_available() is False

    # Recovery
    node.record_success()
    assert node.is_healthy is False
    node.record_success()
    assert node.is_healthy is True
    assert node.is_available() is True


def test_upstream_node_circuit_breaker_isolation():
    node = UpstreamNode(url="http://10.0.0.1:8080")
    assert node.is_available() is True
    node.circuit_breaker.trip()
    assert node.is_available() is False


@pytest.mark.asyncio
async def test_connection_scope_tracking():
    lb = LoadBalancer()
    node = lb.add_node("http://10.0.0.1:8080")
    assert node.active_connections == 0

    async with lb.connection_scope(node):
        assert node.active_connections == 1

    assert node.active_connections == 0


@pytest.mark.asyncio
async def test_background_health_checks_start_stop():
    lb = LoadBalancer()
    lb.add_node("http://127.0.0.1:9999")
    lb.start_background_health_checks(interval=0.1, timeout=0.05)
    assert lb._health_check_task is not None
    await asyncio.sleep(0.05)
    lb.stop_background_health_checks()
    assert lb._health_check_task is None
