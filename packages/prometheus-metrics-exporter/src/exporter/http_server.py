"""Native HTTP server exposing OpenMetrics / Prometheus metrics and alert evaluation.

Hardened with CWE-400 resource quotas (<10MB payload size limits) and connection timeouts.
"""

from __future__ import annotations

import json
import logging
import socket
import threading
import time
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from .alert_evaluator import AlertEvaluator
from .formatter import OpenMetricsFormatter
from .metrics_collector import MetricsCollector
from .notifiers.webhook import WebhookNotifier

logger = logging.getLogger(__name__)

# Security Quota (CWE-400): 10 MB maximum request payload size
MAX_PAYLOAD_SIZE_BYTES = 10 * 1024 * 1024


class MetricsRequestHandler(BaseHTTPRequestHandler):
    """HTTP request handler for metrics exposition and health checks."""

    # Limit socket read timeout
    timeout = 10.0

    # Avoid noisy default logging during testing
    def log_message(self, format: str, *args: Any) -> None:
        logger.debug("%s - - [%s] %s", self.address_string(), self.log_date_time_string(), format % args)

    @property
    def server_instance(self) -> MetricsHTTPServer:
        return self.server.metrics_server  # type: ignore[attr-defined]

    def _send_response_data(
        self,
        status_code: int,
        content_type: str,
        body: bytes,
        extra_headers: Optional[Dict[str, str]] = None,
    ) -> None:
        self.close_connection = True
        self.send_response(status_code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        if extra_headers:
            for k, v in extra_headers.items():
                self.send_header(k, v)
        self.end_headers()
        try:
            self.wfile.write(body)
        except (OSError, ConnectionError):
            pass

    def _read_body_safe(self) -> Optional[bytes]:
        """Safely reads request body enforcing the 10 MB maximum payload size limit (CWE-400)."""
        content_length_header = self.headers.get("Content-Length")
        if not content_length_header:
            return b""

        try:
            length = int(content_length_header)
        except ValueError:
            self._send_response_data(
                HTTPStatus.BAD_REQUEST,
                "application/json",
                json.dumps({"error": "Invalid Content-Length header"}).encode("utf-8"),
            )
            return None

        if length > MAX_PAYLOAD_SIZE_BYTES:
            logger.warning("Request payload too large (%d bytes > %d limit)", length, MAX_PAYLOAD_SIZE_BYTES)
            self._send_response_data(
                HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
                "application/json",
                json.dumps({
                    "error": "Payload Too Large",
                    "max_allowed_bytes": MAX_PAYLOAD_SIZE_BYTES,
                    "received_bytes": length,
                }).encode("utf-8"),
            )
            return None

        try:
            return self.rfile.read(length)
        except OSError as exc:
            logger.warning("Socket read error: %s", exc)
            return None

    def do_GET(self) -> None:
        parsed_url = urlparse(self.path)
        path = parsed_url.path.rstrip("/")
        if not path:
            path = "/"

        if path == "/metrics":
            accept_header = self.headers.get("Accept", "")
            use_openmetrics = self.server_instance.openmetrics
            if "application/openmetrics-text" in accept_header:
                use_openmetrics = True
            elif "text/plain" in accept_header and "version=0.0.4" in accept_header:
                use_openmetrics = False

            families = self.server_instance.collector.collect_all()

            if use_openmetrics:
                body_str = OpenMetricsFormatter.format_openmetrics(families)
                content_type = "application/openmetrics-text; version=1.0.0; charset=utf-8"
            else:
                body_str = OpenMetricsFormatter.format_prometheus(families)
                content_type = "text/plain; version=0.0.4; charset=utf-8"

            self._send_response_data(HTTPStatus.OK, content_type, body_str.encode("utf-8"))

        elif path in ("/health", "/livez", "/healthz"):
            resp = {
                "status": "healthy",
                "uptime_seconds": round(time.time() - self.server_instance.start_time, 2),
                "timestamp": time.time(),
            }
            self._send_response_data(HTTPStatus.OK, "application/json", json.dumps(resp).encode("utf-8"))

        elif path == "/readyz":
            resp = {"status": "ready"}
            self._send_response_data(HTTPStatus.OK, "application/json", json.dumps(resp).encode("utf-8"))

        elif path in ("/status", "/alerts"):
            evaluator = self.server_instance.evaluator
            alerts_data = [inst.to_dict() for inst in evaluator.alert_instances] if evaluator else []
            resp = {
                "server": "prometheus-metrics-exporter",
                "version": "0.1.0",
                "uptime_seconds": round(time.time() - self.server_instance.start_time, 2),
                "alerts_total": len(alerts_data),
                "alerts_firing": sum(1 for a in alerts_data if a["state"] == "firing"),
                "alerts": alerts_data,
            }
            self._send_response_data(HTTPStatus.OK, "application/json", json.dumps(resp, indent=2).encode("utf-8"))

        elif path == "/":
            welcome_html = (
                "<html><head><title>Prometheus Metrics Exporter</title></head>"
                "<body><h1>Prometheus Metrics Exporter</h1>"
                "<p><a href='/metrics'>/metrics</a></p>"
                "<p><a href='/health'>/health</a></p>"
                "<p><a href='/status'>/status</a></p>"
                "</body></html>"
            )
            self._send_response_data(HTTPStatus.OK, "text/html; charset=utf-8", welcome_html.encode("utf-8"))

        else:
            resp = {"error": "Not Found", "path": path}
            self._send_response_data(HTTPStatus.NOT_FOUND, "application/json", json.dumps(resp).encode("utf-8"))

    def do_POST(self) -> None:
        parsed_url = urlparse(self.path)
        path = parsed_url.path.rstrip("/")

        body = self._read_body_safe()
        if body is None:
            return  # Response already sent (400 or 413)

        if path == "/alerts/eval":
            evaluator = self.server_instance.evaluator
            if not evaluator:
                resp = {"error": "No alert evaluator configured"}
                self._send_response_data(HTTPStatus.BAD_REQUEST, "application/json", json.dumps(resp).encode("utf-8"))
                return

            families = self.server_instance.collector.collect_all()
            updated_alerts = evaluator.evaluate(families)
            firing = evaluator.get_firing_alerts()

            if self.server_instance.notifier and firing:
                self.server_instance.notifier.dispatch(firing)

            resp_eval: dict[str, Any] = {
                "evaluated_rules": len(updated_alerts),
                "firing_rules": len(firing),
                "alerts": [a.to_dict() for a in updated_alerts],
            }
            self._send_response_data(HTTPStatus.OK, "application/json", json.dumps(resp_eval, indent=2).encode("utf-8"))

        else:
            resp = {"error": "Not Found", "path": path}
            self._send_response_data(HTTPStatus.NOT_FOUND, "application/json", json.dumps(resp).encode("utf-8"))

    def do_PUT(self) -> None:
        resp = {"error": "Method Not Allowed"}
        self._send_response_data(HTTPStatus.METHOD_NOT_ALLOWED, "application/json", json.dumps(resp).encode("utf-8"))

    def do_DELETE(self) -> None:
        resp = {"error": "Method Not Allowed"}
        self._send_response_data(HTTPStatus.METHOD_NOT_ALLOWED, "application/json", json.dumps(resp).encode("utf-8"))


class MetricsHTTPServer:
    """Enterprise-grade threaded HTTP server for metrics and alert handling."""

    def __init__(
        self,
        host: str = "0.0.0.0",  # nosec B104
        port: int = 9100,
        collector: Optional[MetricsCollector] = None,
        evaluator: Optional[AlertEvaluator] = None,
        notifier: Optional[WebhookNotifier] = None,
        openmetrics: bool = True,
        eval_interval_seconds: float = 15.0,
    ) -> None:
        self.host = host
        self.port = port
        self.collector = collector or MetricsCollector()
        self.evaluator = evaluator
        self.notifier = notifier
        self.openmetrics = openmetrics
        self.eval_interval = eval_interval_seconds
        self.start_time = time.time()

        self._httpd: Optional[ThreadingHTTPServer] = None
        self._server_thread: Optional[threading.Thread] = None
        self._eval_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()

    @property
    def server_address(self) -> tuple[str, int]:
        if self._httpd:
            return self._httpd.server_address  # type: ignore[return-value]
        return (self.host, self.port)

    def _run_server(self) -> None:
        try:
            assert self._httpd is not None  # nosec B101
            self._httpd.serve_forever(poll_interval=0.2)
        except Exception as exc:
            if not self._stop_event.is_set():
                logger.error("HTTP server encountered unexpected error: %s", exc)

    def _run_eval_loop(self) -> None:
        """Background loop evaluating alerts at configured intervals."""
        while not self._stop_event.is_set():
            if self.evaluator:
                try:
                    families = self.collector.collect_all()
                    self.evaluator.evaluate(families)
                    firing = self.evaluator.get_firing_alerts()
                    if firing and self.notifier:
                        self.notifier.dispatch(firing)
                except Exception as exc:
                    logger.warning("Error in background alert evaluation loop: %s", exc)

            self._stop_event.wait(timeout=self.eval_interval)

    def start(self, background: bool = True) -> None:
        """Starts the HTTP server and optional background evaluator."""
        self._stop_event.clear()
        self._httpd = ThreadingHTTPServer((self.host, self.port), MetricsRequestHandler)
        # Attach reference to this server instance on httpd
        self._httpd.metrics_server = self  # type: ignore[attr-defined]

        if background:
            self._server_thread = threading.Thread(target=self._run_server, daemon=True)
            self._server_thread.start()

            if self.evaluator:
                self._eval_thread = threading.Thread(target=self._run_eval_loop, daemon=True)
                self._eval_thread.start()
        else:
            if self.evaluator:
                self._eval_thread = threading.Thread(target=self._run_eval_loop, daemon=True)
                self._eval_thread.start()
            self._run_server()

    def stop(self) -> None:
        """Stops the server cleanly."""
        self._stop_event.set()
        if self._httpd:
            self._httpd.shutdown()
            self._httpd.server_close()
            self._httpd = None

        if self._server_thread and self._server_thread.is_alive():
            self._server_thread.join(timeout=2.0)
        if self._eval_thread and self._eval_thread.is_alive():
            self._eval_thread.join(timeout=2.0)

    def __enter__(self) -> MetricsHTTPServer:
        self.start(background=True)
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.stop()


def create_server_app(
    host: str = "0.0.0.0",  # nosec B104
    port: int = 9100,
    collector: Optional[MetricsCollector] = None,
    evaluator: Optional[AlertEvaluator] = None,
    notifier: Optional[WebhookNotifier] = None,
    openmetrics: bool = True,
) -> MetricsHTTPServer:
    """Factory helper to build and configure a MetricsHTTPServer instance."""
    return MetricsHTTPServer(
        host=host,
        port=port,
        collector=collector,
        evaluator=evaluator,
        notifier=notifier,
        openmetrics=openmetrics,
    )
