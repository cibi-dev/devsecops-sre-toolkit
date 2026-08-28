"""Prometheus and OpenMetrics format exporter for Blackbox probing telemetry."""

from __future__ import annotations

import asyncio
import logging
from typing import Dict, List, Optional, Union

from prober.probes.dns import DNSProbeResult
from prober.probes.http import HTTPProbeResult
from prober.probes.ssl_cert import SSLCertProbeResult
from prober.probes.tcp import TCPProbeResult

logger = logging.getLogger(__name__)

AnyProbeResult = Union[HTTPProbeResult, TCPProbeResult, SSLCertProbeResult, DNSProbeResult]


def format_labels(labels: Dict[str, str]) -> str:
    """Format dictionary into Prometheus label syntax."""
    if not labels:
        return ""
    items = [f'{k}="{v}"' for k, v in sorted(labels.items())]
    return "{" + ",".join(items) + "}"


class MetricsCollector:
    """In-memory thread-safe telemetry store generating standard OpenMetrics outputs."""

    def __init__(self) -> None:
        self._results: Dict[str, AnyProbeResult] = {}
        self._lock = asyncio.Lock()

    async def record_result(self, target_id: str, result: AnyProbeResult) -> None:
        """Store the latest probe result for a given target."""
        async with self._lock:
            self._results[target_id] = result

    def get_results(self) -> Dict[str, AnyProbeResult]:
        """Retrieve a copy of recorded probe results."""
        return dict(self._results)

    def generate_openmetrics(self) -> str:
        """Generate valid Prometheus/OpenMetrics exposition text format."""
        lines: List[str] = []

        # Headers & Help
        lines.append("# HELP probe_success Indicates if the probe succeeded (1 for success, 0 for failure)")
        lines.append("# TYPE probe_success gauge")

        lines.append("# HELP probe_duration_seconds Total and phase-split probe durations in seconds")
        lines.append("# TYPE probe_duration_seconds gauge")

        lines.append("# HELP probe_http_status_code Response HTTP status code")
        lines.append("# TYPE probe_http_status_code gauge")

        lines.append("# HELP probe_ssl_earliest_cert_expiry UTC timestamp of SSL certificate expiration")
        lines.append("# TYPE probe_ssl_earliest_cert_expiry gauge")

        lines.append("# HELP probe_ssl_days_remaining Days remaining until certificate expiration")
        lines.append("# TYPE probe_ssl_days_remaining gauge")

        lines.append("# HELP probe_ssl_alert_level_state Expiration alert state indicator (1 active, 0 inactive)")
        lines.append("# TYPE probe_ssl_alert_level_state gauge")

        lines.append("# HELP probe_dns_lookup_time_seconds Latency of DNS resolution in seconds")
        lines.append("# TYPE probe_dns_lookup_time_seconds gauge")

        lines.append("# HELP probe_tcp_connect_time_seconds Latency of TCP connection in seconds")
        lines.append("# TYPE probe_tcp_connect_time_seconds gauge")

        for target_id, result in self._results.items():
            if isinstance(result, HTTPProbeResult):
                lbl_success = {"target": result.url, "probe_type": "http"}
                lines.append(f"probe_success{format_labels(lbl_success)} {1 if result.is_success else 0}")

                # Phase breakdowns
                lbl_dns = {"target": result.url, "phase": "dns"}
                lines.append(f"probe_duration_seconds{format_labels(lbl_dns)} {result.dns_latency_ms / 1000.0:.6f}")

                lbl_tcp = {"target": result.url, "phase": "tcp"}
                lines.append(f"probe_duration_seconds{format_labels(lbl_tcp)} {result.tcp_latency_ms / 1000.0:.6f}")

                lbl_tls = {"target": result.url, "phase": "tls"}
                lines.append(f"probe_duration_seconds{format_labels(lbl_tls)} {result.tls_latency_ms / 1000.0:.6f}")

                lbl_ttfb = {"target": result.url, "phase": "ttfb"}
                lines.append(f"probe_duration_seconds{format_labels(lbl_ttfb)} {result.ttfb_ms / 1000.0:.6f}")

                lbl_transfer = {"target": result.url, "phase": "content_transfer"}
                lines.append(f"probe_duration_seconds{format_labels(lbl_transfer)} {result.content_transfer_ms / 1000.0:.6f}")

                lbl_total = {"target": result.url, "phase": "total"}
                lines.append(f"probe_duration_seconds{format_labels(lbl_total)} {result.total_latency_ms / 1000.0:.6f}")

                if result.status_code is not None:
                    lbl_code = {"target": result.url}
                    lines.append(f"probe_http_status_code{format_labels(lbl_code)} {result.status_code}")

            elif isinstance(result, TCPProbeResult):
                lbl_success = {"target": f"{result.host}:{result.port}", "probe_type": "tcp"}
                lines.append(f"probe_success{format_labels(lbl_success)} {1 if result.is_success else 0}")

                lbl_tcp_dur = {"target": result.host, "port": str(result.port)}
                lines.append(f"probe_tcp_connect_time_seconds{format_labels(lbl_tcp_dur)} {result.latency_ms / 1000.0:.6f}")

                lbl_total = {"target": f"{result.host}:{result.port}", "phase": "total"}
                lines.append(f"probe_duration_seconds{format_labels(lbl_total)} {result.latency_ms / 1000.0:.6f}")

            elif isinstance(result, SSLCertProbeResult):
                lbl_success = {"target": f"{result.host}:{result.port}", "probe_type": "ssl"}
                lines.append(f"probe_success{format_labels(lbl_success)} {1 if result.is_success else 0}")

                lbl_tls_dur = {"target": result.host, "phase": "tls"}
                lines.append(f"probe_duration_seconds{format_labels(lbl_tls_dur)} {result.handshake_latency_ms / 1000.0:.6f}")

                if result.not_after:
                    ts = result.not_after.timestamp()
                    lbl_expiry = {"target": result.host}
                    lines.append(f"probe_ssl_earliest_cert_expiry{format_labels(lbl_expiry)} {ts:.0f}")

                if result.days_until_expiration is not None:
                    lbl_days = {"target": result.host}
                    lines.append(f"probe_ssl_days_remaining{format_labels(lbl_days)} {result.days_until_expiration:.2f}")

                for level in ["OK", "WARNING_30D", "CRITICAL_15D", "EMERGENCY_7D", "EXPIRED"]:
                    active = 1 if result.alert_level == level else 0
                    lbl_level = {"target": result.host, "level": level}
                    lines.append(f"probe_ssl_alert_level_state{format_labels(lbl_level)} {active}")

            elif isinstance(result, DNSProbeResult):
                lbl_success = {"target": result.target, "probe_type": "dns"}
                lines.append(f"probe_success{format_labels(lbl_success)} {1 if result.is_success else 0}")

                lbl_dns_dur = {"target": result.target, "record_type": result.record_type}
                lines.append(f"probe_dns_lookup_time_seconds{format_labels(lbl_dns_dur)} {result.latency_ms / 1000.0:.6f}")

                lbl_total = {"target": result.target, "phase": "total"}
                lines.append(f"probe_duration_seconds{format_labels(lbl_total)} {result.latency_ms / 1000.0:.6f}")

        lines.append("# EOF\n")
        return "\n".join(lines)


class MetricsServer:
    """Lightweight asynchronous HTTP server serving Prometheus metrics on /metrics."""

    def __init__(
        self,
        collector: MetricsCollector,
        host: str = "127.0.0.1",
        port: int = 9115,
    ) -> None:
        self.collector = collector
        self.host = host
        self.port = port
        self._server: Optional[asyncio.Server] = None

    async def _handle_request(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        try:
            line = await reader.readline()
            if not line:
                writer.close()
                return

            req_line = line.decode("latin1").strip()
            parts = req_line.split(" ")
            path = parts[1] if len(parts) >= 2 else "/"

            if path == "/metrics":
                body = self.collector.generate_openmetrics().encode("utf-8")
                response = (
                    b"HTTP/1.1 200 OK\r\n"
                    b"Content-Type: application/openmetrics-text; version=1.0.0; charset=utf-8\r\n"
                    b"Content-Length: " + str(len(body)).encode("ascii") + b"\r\n"
                    b"Connection: close\r\n"
                    b"\r\n" + body
                )
            elif path == "/healthz" or path == "/health":
                body = b'{"status":"ok"}\n'
                response = (
                    b"HTTP/1.1 200 OK\r\n"
                    b"Content-Type: application/json\r\n"
                    b"Content-Length: " + str(len(body)).encode("ascii") + b"\r\n"
                    b"Connection: close\r\n"
                    b"\r\n" + body
                )
            else:
                body = b"Not Found\n"
                response = (
                    b"HTTP/1.1 404 Not Found\r\n"
                    b"Content-Length: " + str(len(body)).encode("ascii") + b"\r\n"
                    b"Connection: close\r\n"
                    b"\r\n" + body
                )

            writer.write(response)
            await writer.drain()
        except Exception as e:
            logger.debug("Metrics server request error: %s", e)
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    async def start(self) -> None:
        """Start listening for incoming scrape requests."""
        self._server = await asyncio.start_server(
            self._handle_request,
            host=self.host,
            port=self.port,
        )
        logger.info("Metrics server listening on http://%s:%d/metrics", self.host, self.port)

    async def stop(self) -> None:
        """Gracefully stop server."""
        if self._server:
            self._server.close()
            await self._server.wait_closed()
