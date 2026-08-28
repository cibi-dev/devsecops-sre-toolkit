"""Enterprise-grade Prometheus / OpenMetrics host metrics exporter and alert evaluator.

Package exports:
- MetricsCollector: Native host metrics collector from Linux /proc
- OpenMetricsFormatter: OpenMetrics 1.0 & Prometheus 0.0.4 serializer
- AlertEvaluator: YAML alert rule evaluator with debounce timing
- WebhookNotifier: Alertmanager-compatible HTTP webhook notifier
- MetricsHTTPServer: Threaded HTTP server exposing /metrics and health endpoints
"""

__version__ = "0.1.0"

from .alert_evaluator import (
    AlertEvaluator,
    AlertGroupModel,
    AlertInstance,
    AlertRuleModel,
    AlertSeverity,
    AlertState,
)
from .formatter import OpenMetricsFormatter
from .http_server import MetricsHTTPServer, create_server_app
from .metrics_collector import (
    MetricFamily,
    MetricsCollector,
    MetricSample,
    MetricType,
)
from .notifiers.webhook import WebhookNotifier, WebhookPayload, sanitize_url

__all__ = [
    "__version__",
    "MetricType",
    "MetricSample",
    "MetricFamily",
    "MetricsCollector",
    "OpenMetricsFormatter",
    "AlertState",
    "AlertSeverity",
    "AlertRuleModel",
    "AlertGroupModel",
    "AlertInstance",
    "AlertEvaluator",
    "WebhookPayload",
    "WebhookNotifier",
    "sanitize_url",
    "MetricsHTTPServer",
    "create_server_app",
]
