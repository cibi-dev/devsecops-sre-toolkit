"""Asynchronous HTTP/HTTPS Synthetic Prober with phase-split latency profiling."""

from __future__ import annotations

import asyncio
import re
import socket
import ssl
import time
from datetime import datetime, timezone
from typing import Dict, Optional
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from pydantic import BaseModel, Field


SENSITIVE_PARAM_NAMES = {
    "key",
    "apikey",
    "api_key",
    "token",
    "auth",
    "secret",
    "password",
    "pass",
    "access_token",
    "refresh_token",
    "session",
}

SENSITIVE_HEADER_NAMES = {
    "authorization",
    "proxy-authorization",
    "x-api-key",
    "api-key",
    "cookie",
    "set-cookie",
    "x-auth-token",
}


def sanitize_url(url: str) -> str:
    """Sanitize URL query parameters and credentials to prevent sensitive leakage (CWE-209)."""
    try:
        parsed = urlparse(url)
        # Redact credentials if present (user:pass@host)
        netloc = parsed.netloc
        if "@" in netloc:
            credentials, host_part = netloc.split("@", 1)
            if ":" in credentials:
                user, _ = credentials.split(":", 1)
                netloc = f"{user}:[REDACTED]@{host_part}"
            else:
                netloc = f"[REDACTED]@{host_part}"

        # Redact sensitive query parameters
        if parsed.query:
            query_pairs = parse_qsl(parsed.query, keep_blank_values=True)
            sanitized_pairs = []
            for k, v in query_pairs:
                if k.lower() in SENSITIVE_PARAM_NAMES or any(s in k.lower() for s in ("secret", "token", "key", "pass")):
                    sanitized_pairs.append((k, "[REDACTED]"))
                else:
                    sanitized_pairs.append((k, v))
            query = urlencode(sanitized_pairs)
        else:
            query = ""

        return urlunparse((
            parsed.scheme,
            netloc,
            parsed.path,
            parsed.params,
            query,
            parsed.fragment,
        ))
    except Exception:
        # Fallback regex redaction if parsing fails
        return re.sub(r"(token|key|secret|password|api_key)=[^&]+", r"\1=[REDACTED]", url, flags=re.IGNORECASE)


def sanitize_headers(headers: Dict[str, str]) -> Dict[str, str]:
    """Sanitize sensitive HTTP headers (CWE-209)."""
    sanitized: Dict[str, str] = {}
    for k, v in headers.items():
        if k.lower() in SENSITIVE_HEADER_NAMES or "token" in k.lower() or "auth" in k.lower():
            sanitized[k] = "[REDACTED]"
        else:
            sanitized[k] = v
    return sanitized


class HTTPProbeResult(BaseModel):
    """Result model for HTTP/HTTPS synthetic probe with granular latency phases."""

    url: str
    target_host: str
    method: str = "GET"
    status_code: Optional[int] = None
    dns_latency_ms: float = 0.0
    tcp_latency_ms: float = 0.0
    tls_latency_ms: float = 0.0
    ttfb_ms: float = 0.0
    content_transfer_ms: float = 0.0
    total_latency_ms: float = 0.0
    response_bytes: int = 0
    resolved_ip: Optional[str] = None
    headers: Dict[str, str] = Field(default_factory=dict)
    ssl_verified: bool = True
    status: str = "SUCCESS"  # SUCCESS, HTTP_ERROR, TIMEOUT, DNS_ERROR, TLS_ERROR, CONNECTION_ERROR, ERROR
    error: Optional[str] = None
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def is_success(self) -> bool:
        """Check if HTTP status code is 2xx or 3xx and no network errors occurred."""
        return self.status == "SUCCESS" and self.status_code is not None and 200 <= self.status_code < 400


class HTTPProbe:
    """High-precision asynchronous Blackbox HTTP prober with phase-split telemetry."""

    def __init__(
        self,
        default_timeout: float = 10.0,
        max_response_bytes: int = 10 * 1024 * 1024,  # CWE-400 guardrail: 10MB limit
    ) -> None:
        self.default_timeout = default_timeout
        self.max_response_bytes = max_response_bytes

    async def probe(
        self,
        url: str,
        method: str = "GET",
        headers: Optional[Dict[str, str]] = None,
        body: Optional[bytes] = None,
        timeout: Optional[float] = None,
        verify_ssl: bool = True,
    ) -> HTTPProbeResult:
        """Execute synthetic probe with microsecond phase profiling (DNS, TCP, TLS, TTFB, Total).

        Args:
            url: Target URL to probe.
            method: HTTP method (GET, POST, HEAD, etc.).
            headers: Optional HTTP headers.
            body: Optional request payload.
            timeout: Timeout in seconds (default 10.0).
            verify_ssl: Strict CA verification flag (CWE-295).

        Returns:
            HTTPProbeResult with detailed phase-split metrics and sanitized metadata.
        """
        eff_timeout = timeout if timeout is not None else self.default_timeout
        sanitized_target_url = sanitize_url(url)
        parsed_url = urlparse(url)
        scheme = parsed_url.scheme.lower()
        if scheme not in ("http", "https"):
            return HTTPProbeResult(
                url=sanitized_target_url,
                target_host=parsed_url.netloc or "unknown",
                method=method.upper(),
                status="ERROR",
                error=f"Unsupported scheme: {scheme}. Expected 'http' or 'https'.",
            )

        host = parsed_url.hostname or ""
        port = parsed_url.port or (443 if scheme == "https" else 80)
        path = parsed_url.path or "/"
        if parsed_url.query:
            path = f"{path}?{parsed_url.query}"

        loop = asyncio.get_running_loop()
        start_probe_time = time.perf_counter()

        dns_latency_ms = 0.0
        tcp_latency_ms = 0.0
        tls_latency_ms = 0.0
        ttfb_ms = 0.0
        content_transfer_ms = 0.0
        resolved_ip: Optional[str] = None
        writer: Optional[asyncio.StreamWriter] = None

        try:
            async with asyncio.timeout(eff_timeout):
                # Phase 1: DNS Lookup
                dns_t0 = time.perf_counter()
                addrinfo = await loop.getaddrinfo(
                    host,
                    port,
                    family=socket.AF_INET,
                    type=socket.SOCK_STREAM,
                )
                dns_latency_ms = (time.perf_counter() - dns_t0) * 1000.0
                if not addrinfo:
                    raise socket.gaierror("No DNS records returned")
                resolved_ip = str(addrinfo[0][4][0])

                # Phase 2: TCP Connection
                tcp_t0 = time.perf_counter()
                reader, writer = await asyncio.open_connection(
                    host=resolved_ip,
                    port=port,
                )
                tcp_latency_ms = (time.perf_counter() - tcp_t0) * 1000.0

                # Phase 3: TLS Handshake (if HTTPS)
                if scheme == "https":
                    tls_t0 = time.perf_counter()
                    ssl_ctx = ssl.create_default_context()
                    if not verify_ssl:
                        ssl_ctx.check_hostname = False
                        ssl_ctx.verify_mode = ssl.CERT_NONE

                    # Upgrade connection to TLS using loop.start_tls
                    transport = writer.transport
                    protocol = getattr(transport, "_protocol", None)
                    new_transport = await loop.start_tls(  # type: ignore[arg-type]
                        transport=transport,
                        protocol=protocol,  # type: ignore[arg-type]
                        sslcontext=ssl_ctx,
                        server_hostname=host,
                    )
                    # Bind updated transport back to streams
                    setattr(writer, "_transport", new_transport)
                    setattr(reader, "_transport", new_transport)
                    tls_latency_ms = (time.perf_counter() - tls_t0) * 1000.0

                # Prepare HTTP/1.1 Request
                req_headers = {
                    "Host": host,
                    "User-Agent": "SyntheticBlackboxProber/0.1.0",
                    "Accept": "*/*",
                    "Connection": "close",
                }
                if headers:
                    req_headers.update(headers)
                if body:
                    req_headers["Content-Length"] = str(len(body))

                req_lines = [f"{method.upper()} {path} HTTP/1.1"]
                for hk, hv in req_headers.items():
                    req_lines.append(f"{hk}: {hv}")
                req_payload = "\r\n".join(req_lines).encode("latin1") + b"\r\n\r\n"
                if body:
                    req_payload += body

                # Send Request and Measure TTFB
                ttfb_t0 = time.perf_counter()
                writer.write(req_payload)
                await writer.drain()

                # Read first chunk of response (TTFB)
                initial_chunk = await reader.read(4096)
                ttfb_ms = (time.perf_counter() - ttfb_t0) * 1000.0

                # Phase 5: Read Response Content
                content_t0 = time.perf_counter()
                response_chunks = [initial_chunk]
                total_bytes = len(initial_chunk)

                while True:
                    chunk = await reader.read(8192)
                    if not chunk:
                        break
                    total_bytes += len(chunk)
                    if total_bytes > self.max_response_bytes:
                        # CWE-400 Guardrail: Stop downloading oversized payloads
                        break
                    response_chunks.append(chunk)

                content_transfer_ms = (time.perf_counter() - content_t0) * 1000.0
                total_latency_ms = (time.perf_counter() - start_probe_time) * 1000.0

                # Parse HTTP Status and Headers
                full_raw_response = b"".join(response_chunks)
                status_code: Optional[int] = None
                resp_headers: Dict[str, str] = {}

                header_end_idx = full_raw_response.find(b"\r\n\r\n")
                if header_end_idx != -1:
                    header_bytes = full_raw_response[:header_end_idx]
                    header_lines = header_bytes.decode("latin1", errors="replace").split("\r\n")
                    if header_lines:
                        status_line = header_lines[0]
                        parts = status_line.split(" ", 2)
                        if len(parts) >= 2 and parts[1].isdigit():
                            status_code = int(parts[1])
                        for line in header_lines[1:]:
                            if ":" in line:
                                hk, hv = line.split(":", 1)
                                resp_headers[hk.strip()] = hv.strip()

                is_http_ok = status_code is not None and 200 <= status_code < 400
                status_label = "SUCCESS" if is_http_ok else "HTTP_ERROR"

                return HTTPProbeResult(
                    url=sanitized_target_url,
                    target_host=host,
                    method=method.upper(),
                    status_code=status_code,
                    dns_latency_ms=round(dns_latency_ms, 3),
                    tcp_latency_ms=round(tcp_latency_ms, 3),
                    tls_latency_ms=round(tls_latency_ms, 3),
                    ttfb_ms=round(ttfb_ms, 3),
                    content_transfer_ms=round(content_transfer_ms, 3),
                    total_latency_ms=round(total_latency_ms, 3),
                    response_bytes=total_bytes,
                    resolved_ip=resolved_ip,
                    headers=sanitize_headers(resp_headers),
                    ssl_verified=verify_ssl,
                    status=status_label,
                    error=None if is_http_ok else f"HTTP Status {status_code}",
                )

        except TimeoutError:
            total_latency_ms = (time.perf_counter() - start_probe_time) * 1000.0
            return HTTPProbeResult(
                url=sanitized_target_url,
                target_host=host,
                method=method.upper(),
                dns_latency_ms=round(dns_latency_ms, 3),
                tcp_latency_ms=round(tcp_latency_ms, 3),
                tls_latency_ms=round(tls_latency_ms, 3),
                total_latency_ms=round(total_latency_ms, 3),
                resolved_ip=resolved_ip,
                status="TIMEOUT",
                error=f"Probe timed out after {eff_timeout}s",
            )
        except socket.gaierror as e:
            total_latency_ms = (time.perf_counter() - start_probe_time) * 1000.0
            return HTTPProbeResult(
                url=sanitized_target_url,
                target_host=host,
                method=method.upper(),
                dns_latency_ms=round(dns_latency_ms, 3),
                total_latency_ms=round(total_latency_ms, 3),
                status="DNS_ERROR",
                error=f"DNS resolution failure: {e}",
            )
        except (ssl.SSLCertVerificationError, ssl.SSLError) as e:
            total_latency_ms = (time.perf_counter() - start_probe_time) * 1000.0
            return HTTPProbeResult(
                url=sanitized_target_url,
                target_host=host,
                method=method.upper(),
                dns_latency_ms=round(dns_latency_ms, 3),
                tcp_latency_ms=round(tcp_latency_ms, 3),
                tls_latency_ms=round(tls_latency_ms, 3),
                total_latency_ms=round(total_latency_ms, 3),
                resolved_ip=resolved_ip,
                ssl_verified=verify_ssl,
                status="TLS_ERROR",
                error=f"TLS verification failure: {e}",
            )
        except (ConnectionRefusedError, ConnectionResetError, OSError) as e:
            total_latency_ms = (time.perf_counter() - start_probe_time) * 1000.0
            return HTTPProbeResult(
                url=sanitized_target_url,
                target_host=host,
                method=method.upper(),
                dns_latency_ms=round(dns_latency_ms, 3),
                tcp_latency_ms=round(tcp_latency_ms, 3),
                total_latency_ms=round(total_latency_ms, 3),
                resolved_ip=resolved_ip,
                status="CONNECTION_ERROR",
                error=f"Connection failure: {e}",
            )
        except Exception as e:
            total_latency_ms = (time.perf_counter() - start_probe_time) * 1000.0
            return HTTPProbeResult(
                url=sanitized_target_url,
                target_host=host,
                method=method.upper(),
                dns_latency_ms=round(dns_latency_ms, 3),
                tcp_latency_ms=round(tcp_latency_ms, 3),
                tls_latency_ms=round(tls_latency_ms, 3),
                total_latency_ms=round(total_latency_ms, 3),
                status="ERROR",
                error=f"Unexpected error: {e}",
            )
        finally:
            if writer is not None:
                try:
                    writer.close()
                    await writer.wait_closed()
                except Exception:
                    pass
