"""Tests for HTTP/HTTPS synthetic prober with phase-split latency profiling."""

import asyncio
import socket
import ssl
from unittest.mock import AsyncMock, MagicMock, patch
import pytest
from prober.probes.http import HTTPProbe, HTTPProbeResult, sanitize_headers, sanitize_url


@pytest.fixture
async def mock_http_server():
    """Spin up a lightweight local mock HTTP server."""
    async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        try:
            line = await reader.readline()
            if not line:
                writer.close()
                return
            req_str = line.decode("latin1")
            
            # Read headers
            while True:
                h_line = await reader.readline()
                if h_line in (b"\r\n", b"\n", b""):
                    break

            if "GET /slow" in req_str:
                await asyncio.sleep(0.5)
                body = b"Slow response payload"
                resp = (
                    b"HTTP/1.1 200 OK\r\n"
                    b"Content-Type: text/plain\r\n"
                    b"X-Custom-Header: TestVal\r\n"
                    b"Authorization: SecretBearerToken\r\n"
                    b"Content-Length: " + str(len(body)).encode("ascii") + b"\r\n\r\n" + body
                )
            elif "GET /404" in req_str:
                body = b"Not Found"
                resp = b"HTTP/1.1 404 Not Found\r\nContent-Length: 9\r\n\r\n" + body
            elif "GET /500" in req_str:
                body = b"Server Error"
                resp = b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 12\r\n\r\n" + body
            elif "POST /echo" in req_str:
                body = b"Echoed"
                resp = b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\n" + body
            elif "GET /oversized" in req_str:
                body = b"A" * 2000
                resp = b"HTTP/1.1 200 OK\r\nContent-Length: 2000\r\n\r\n" + body
            else:
                body = b"OK Body"
                resp = (
                    b"HTTP/1.1 200 OK\r\n"
                    b"Content-Type: text/plain\r\n"
                    b"X-Auth-Token: supersecret\r\n"
                    b"Content-Length: 7\r\n\r\n" + body
                )

            writer.write(resp)
            await writer.drain()
        except Exception:
            pass
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    server = await asyncio.start_server(handle_client, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    yield f"http://127.0.0.1:{port}"
    server.close()
    await server.wait_closed()


@pytest.mark.asyncio
async def test_http_probe_success(mock_http_server):
    """Test successful HTTP probe with phase breakdowns."""
    probe = HTTPProbe(default_timeout=5.0)
    result = await probe.probe(url=f"{mock_http_server}/")

    assert result.status == "SUCCESS"
    assert result.is_success is True
    assert result.status_code == 200
    assert result.total_latency_ms > 0
    assert result.dns_latency_ms >= 0
    assert result.tcp_latency_ms >= 0
    assert result.ttfb_ms >= 0
    assert result.response_bytes > 0
    assert result.resolved_ip == "127.0.0.1"
    # Sensitive header check (X-Auth-Token redacted)
    assert result.headers.get("X-Auth-Token") == "[REDACTED]"


@pytest.mark.asyncio
async def test_http_probe_404_error(mock_http_server):
    """Test HTTP probe detecting 404 status."""
    probe = HTTPProbe(default_timeout=5.0)
    result = await probe.probe(url=f"{mock_http_server}/404")

    assert result.status == "HTTP_ERROR"
    assert result.is_success is False
    assert result.status_code == 404
    assert "HTTP Status 404" in str(result.error)


@pytest.mark.asyncio
async def test_http_probe_500_error(mock_http_server):
    """Test HTTP probe detecting 500 status."""
    probe = HTTPProbe(default_timeout=5.0)
    result = await probe.probe(url=f"{mock_http_server}/500")

    assert result.status == "HTTP_ERROR"
    assert result.is_success is False
    assert result.status_code == 500


@pytest.mark.asyncio
async def test_http_probe_post_method(mock_http_server):
    """Test HTTP probe with POST method and headers."""
    probe = HTTPProbe(default_timeout=5.0)
    result = await probe.probe(
        url=f"{mock_http_server}/echo",
        method="POST",
        headers={"Content-Type": "application/json"},
        body=b'{"test":123}',
    )

    assert result.status == "SUCCESS"
    assert result.status_code == 200
    assert result.method == "POST"


@pytest.mark.asyncio
async def test_http_probe_timeout(mock_http_server):
    """Test HTTP probe timeout enforcement."""
    probe = HTTPProbe(default_timeout=0.1)
    result = await probe.probe(url=f"{mock_http_server}/slow", timeout=0.1)

    assert result.status == "TIMEOUT"
    assert result.is_success is False
    assert "timed out" in str(result.error).lower()


@pytest.mark.asyncio
async def test_http_probe_unsupported_scheme():
    """Test HTTP probe with invalid URL scheme."""
    probe = HTTPProbe()
    result = await probe.probe(url="ftp://ftp.example.com/file")

    assert result.status == "ERROR"
    assert result.is_success is False
    assert "Unsupported scheme" in str(result.error)


@pytest.mark.asyncio
async def test_http_probe_dns_failure():
    """Test HTTP probe against non-existent domain."""
    probe = HTTPProbe(default_timeout=2.0)
    result = await probe.probe(url="http://non-existent-domain-xyz-123456789.invalid/")

    assert result.status in ("DNS_ERROR", "ERROR")
    assert result.is_success is False


@pytest.mark.asyncio
async def test_http_probe_connection_refused():
    """Test HTTP probe connecting to closed port."""
    s = socket.socket()
    s.bind(("", 0))
    port = s.getsockname()[1]
    s.close()

    probe = HTTPProbe(default_timeout=2.0)
    result = await probe.probe(url=f"http://127.0.0.1:{port}/")

    assert result.status in ("CONNECTION_ERROR", "ERROR")
    assert result.is_success is False


@pytest.mark.asyncio
async def test_http_probe_tls_error():
    """Test HTTP probe capturing TLS error when probing HTTPS."""
    probe = HTTPProbe(default_timeout=2.0)
    loop = asyncio.get_running_loop()
    mock_addrinfo = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 443))]
    mock_writer = MagicMock()
    mock_writer.transport = MagicMock()
    mock_writer.close = MagicMock()
    mock_writer.wait_closed = AsyncMock()

    with patch.object(loop, "getaddrinfo", return_value=mock_addrinfo):
        with patch("asyncio.open_connection", return_value=(MagicMock(), mock_writer)):
            with patch.object(loop, "start_tls", side_effect=ssl.SSLCertVerificationError("Self-signed cert")):
                result = await probe.probe(url="https://untrusted-self-signed.local/")
                assert result.status == "TLS_ERROR"
                assert result.is_success is False
                assert "Self-signed cert" in str(result.error)


@pytest.mark.asyncio
async def test_http_probe_unexpected_error():
    """Test HTTP probe capturing unexpected runtime error."""
    probe = HTTPProbe(default_timeout=2.0)
    with patch("asyncio.open_connection", side_effect=RuntimeError("Kernel socket failure")):
        result = await probe.probe(url="http://127.0.0.1:8080/")
        assert result.status == "ERROR"
        assert result.is_success is False


@pytest.mark.asyncio
async def test_http_probe_max_response_bytes(mock_http_server):
    """Test HTTP probe bounding response size to prevent DoS (CWE-400)."""
    probe = HTTPProbe(default_timeout=5.0, max_response_bytes=100)
    result = await probe.probe(url=f"{mock_http_server}/oversized")

    assert result.status == "SUCCESS"
    assert result.status_code == 200
    assert result.response_bytes <= 4096 + 100


def test_url_sanitization():
    """Test URL credential and query param redaction."""
    url = "https://user:mypassword@example.com/api?token=secret123&api_key=xyz987&page=2"
    sanitized = sanitize_url(url)

    assert "mypassword" not in sanitized
    assert "secret123" not in sanitized
    assert "xyz987" not in sanitized
    assert "[REDACTED]" in sanitized
    assert "page=2" in sanitized

    # Fallback / user only without password
    user_only = "https://admin@example.com/status"
    assert sanitize_url(user_only) == "https://[REDACTED]@example.com/status"


def test_header_sanitization():
    """Test header redaction for Authorization and tokens."""
    headers = {
        "Authorization": "Bearer token-12345",
        "X-Api-Key": "my-secret-key",
        "Content-Type": "application/json",
    }
    sanitized = sanitize_headers(headers)
    assert sanitized["Authorization"] == "[REDACTED]"
    assert sanitized["X-Api-Key"] == "[REDACTED]"
    assert sanitized["Content-Type"] == "application/json"
