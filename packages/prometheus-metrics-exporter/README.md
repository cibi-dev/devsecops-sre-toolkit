# Prometheus Metrics Exporter & Alert Evaluator

[![CI DevSecOps Security Scan](https://github.com/cibi-dev/prometheus-metrics-exporter/actions/workflows/security-scan.yml/badge.svg)](https://github.com/cibi-dev/prometheus-metrics-exporter/actions/workflows/security-scan.yml)
[![SAST Bandit](https://img.shields.io/badge/SAST-Bandit%20Passing-brightgreen.svg)](https://github.com/PyCQA/bandit)
[![Gitleaks Clean](https://img.shields.io/badge/Gitleaks-0%20Secrets-brightgreen.svg)](https://github.com/gitleaks/gitleaks)
[![Coverage](https://img.shields.io/badge/Coverage-93.2%25-brightgreen.svg)](https://pytest.org)
[![SBOM CycloneDX](https://img.shields.io/badge/SBOM-CycloneDX%20JSON-blue.svg)](sbom.json)
[![Python Version](https://img.shields.io/badge/Python-%3E%3D3.10-blue.svg)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

An enterprise-grade native Python HTTP exporter conforming to the **OpenMetrics 1.0.0** and **Prometheus 0.0.4** specifications. It gathers real-time Linux host metrics (per-core CPU, RAM, Disk I/O, Network, File Descriptors, Load, Uptime) and continuously evaluates YAML alert rules with debounce state lifecycles (`PENDING` $\to$ `FIRING` $\to$ `RESOLVED`), dispatching alerts to webhooks with exponential backoff and jitter.

---

## 🚀 Key Features

- 🐧 **Native Linux Host Metrics Collector**: Collects metrics directly from `/proc` (`stat`, `meminfo`, `diskstats`, `net/dev`, `sys/fs/file-nr`, `loadavg`, `uptime`) and `statvfs` with zero external binary dependencies.
- 📐 **Strict OpenMetrics 1.0 & Prometheus 0.0.4 Engine**: Exact formatting for `# HELP`, `# TYPE`, `# UNIT`, sorted label key-value pairs, escaped quotes/newlines/slashes, NaN/$\pm\text{Inf}$ floats, and `# EOF` markers.
- 🚨 **YAML Alert Evaluator with Debounce**: Evaluates PromQL-like comparison conditions (`>`, `<`, `>=`, `<=`, `==`, `!=`) against metrics, enforcing duration thresholds (`for: 30s`, `for: 5m`) before firing.
- 📬 **Resilient Webhook Dispatcher**: Dispatches Alertmanager-compatible payloads with exponential backoff and jitter, retrying on network errors or 5xx responses.
- 🛡️ **Hardened DevSecOps Guardrails**:
  - **CWE-400 Anti-DoS**: Max HTTP payload quota (<10 MB, returns HTTP 413) and YAML config size limits (<1 MB).
  - **CWE-209 Sanitization**: Redacts sensitive auth tokens and credentials in webhook URLs and log streams (`[REDACTED]`).
  - **CWE-502 & CWE-20 Safe Deserialization**: Strict Pydantic v2 schemas and `yaml.safe_load()`.
  - **CWE-798**: Zero hardcoded secrets, verified with Gitleaks.

---

## 📦 Architecture Overview

```text
Host Linux (/proc, statvfs)
          │
          ▼
   [MetricsCollector]  ──> (CPU per-core, RAM, Disk, Net, FDs, Load)
          │
          ├──────────────────────────────┐
          ▼                              ▼
  [OpenMetricsFormatter]         [AlertEvaluator]
          │                              │ (Debounce & State Machine)
          ▼                              ▼
 [MetricsHTTPServer]            [WebhookNotifier]
   ├── GET /metrics               └── HTTP POST with backoff & jitter
   ├── GET /health & /readyz          └── [REDACTED] URL Masking
   ├── GET /status
   └── POST /alerts/eval (Quota <10MB)
```

---

## 🛠️ Quickstart

### 1. Installation

```bash
# Clone and install in virtual environment
git clone https://github.com/cibi-dev/prometheus-metrics-exporter.git
cd prometheus-metrics-exporter
pip install .

# Or install with development and security tools
pip install -e .[dev]
```

### 2. Collect Host Metrics to stdout

```bash
# Print OpenMetrics 1.0 format
prometheus-exporter collect --format openmetrics

# Print Prometheus 0.0.4 text format
prometheus-exporter collect --format prometheus

# Print structured JSON
prometheus-exporter collect --format json
```

### 3. Start Exporter HTTP Server

```bash
# Launch server on port 9100 with alert evaluation and webhook notifications
prometheus-exporter serve \
  --host 0.0.0.0 \
  --port 9100 \
  --alerts-config alerts.yaml \
  --webhook-url "https://hooks.slack.com/services/T00/B00/X?token=secret123" \
  --interval 15.0
```

### 4. Query Health & Status

```bash
# Check exporter health
prometheus-exporter status --url http://localhost:9100

# Scrape metrics with curl
curl -s http://localhost:9100/metrics
```

---

## 📋 OpenMetrics Exposition Format Example

```text
# HELP node_cpu_seconds_total Seconds the CPUs spent in each mode.
# TYPE node_cpu_seconds_total counter
# UNIT node_cpu_seconds_total seconds
node_cpu_seconds_total{cpu="0",mode="idle"} 1006.000
node_cpu_seconds_total{cpu="0",mode="user"} 50.000
# HELP node_cpu_usage_percent Estimated instant or windowed CPU usage percentage (0-100).
# TYPE node_cpu_usage_percent gauge
# UNIT node_cpu_usage_percent percent
node_cpu_usage_percent{cpu="total"} 14.5
# HELP node_memory_bytes Memory statistics in bytes.
# TYPE node_memory_bytes gauge
# UNIT node_memory_bytes bytes
node_memory_bytes{type="used"} 8388608000
node_memory_bytes{type="total"} 16777216000
# HELP node_filesystem_used_percent Filesystem used percentage.
# TYPE node_filesystem_used_percent gauge
# UNIT node_filesystem_used_percent percent
node_filesystem_used_percent{mountpoint="/"} 42.1
# EOF
```

---

## 🚨 Alert Configuration Example (`alerts.yaml`)

```yaml
groups:
  - name: host_resource_alerts
    rules:
      - alert: HostHighCpuUsage
        expr: "node_cpu_usage_percent > 90.0"
        for: "30s"
        severity: "critical"
        labels:
          team: sre
          environment: production
        annotations:
          summary: "Host CPU usage exceeds 90%"
          description: "Current CPU usage is {{ $value }}% on host."

      - alert: HostMemoryLow
        expr: "node_memory_used_percent >= 85.0"
        for: "1m"
        severity: "warning"
        labels:
          team: sre
        annotations:
          summary: "Host RAM is running low ({{ $value }}% used)"

      - alert: RootFilesystemFull
        expr: "node_filesystem_used_percent > 85.0"
        for: "0s"
        severity: "critical"
        labels:
          team: infrastructure
        annotations:
          summary: "Root filesystem is over 85% full"
```

---

## 📊 Performance Benchmarks

Measured on Linux 6.x (`benchmarks/resultados.json`):

| Operation | Mean Latency | p50 | p95 | p99 |
|---|:---:|:---:|:---:|:---:|
| **Metrics Collection (`/proc` parse)** | **0.757 ms** | 0.861 ms | 1.355 ms | 2.096 ms |
| **OpenMetrics Serialization** | **0.576 ms** | 0.523 ms | 1.003 ms | 1.425 ms |
| **Alert Rules Evaluation (20 rules)** | **0.009 ms** | 0.009 ms | 0.010 ms | 0.017 ms |
| **HTTP Scraping Throughput** | **127.0 req/s** | 57.5 ms | 84.4 ms | 102.5 ms |

Run the benchmark suite locally:
```bash
python benchmarks/run.py
```

---

## 🛡️ DevSecOps & Security Compliance

This package adheres to the **cibi-dev DevSecOps & Security Standard**:

| Security Control | CWE Reference | Mitigation / Implementation | Verification |
|---|---|---|:---:|
| **Zero Secrets** | CWE-798 | No credentials stored in source or repo | `gitleaks detect` (0 leaks) |
| **Resource Quotas** | CWE-400 | Max 10 MB payload limits (HTTP 413) & 1 MB YAML limits | `test_security.py` |
| **Log Sanitization** | CWE-209 | Masking URL query tokens and auth headers as `[REDACTED]` | `test_security.py` |
| **Safe Deserialization** | CWE-502 / CWE-20 | Strict `yaml.safe_load()` and Pydantic v2 schemas | `test_security.py` |
| **SAST Analysis** | Bandit | Codebase scanned with 0 high/medium vulnerabilities | `bandit -r . -ll` |
| **Supply Chain Integrity** | CycloneDX | Automated Software Bill of Materials generation | `sbom.json` |

---

## 🧪 Testing & Validation

```bash
# Run pytest with strict coverage gate (>=90%)
pytest -v --cov=exporter --cov-report=term-missing --cov-fail-under=90

# Run Bandit SAST scan
bandit -r . -ll

# Run Gitleaks secret scan
gitleaks detect --no-git --source . -v

# Generate CycloneDX SBOM
cyclonedx-py environment --pyproject pyproject.toml -o sbom.json
```

---

## 📄 License

MIT License. Copyright (c) 2026 cibi-dev.
