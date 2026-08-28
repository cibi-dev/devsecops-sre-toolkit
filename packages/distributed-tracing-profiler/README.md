# Distributed Tracing Profiler

[![CI Security Scan](https://github.com/cibi-dev/distributed-tracing-profiler/actions/workflows/security-scan.yml/badge.svg)](https://github.com/cibi-dev/distributed-tracing-profiler/actions)
[![Bandit SAST](https://img.shields.io/badge/security-bandit%20passed-brightgreen.svg)](https://github.com/PyCQA/bandit)
[![Gitleaks Secret Scan](https://img.shields.io/badge/secrets-gitleaks%20clean-brightgreen.svg)](https://github.com/gitleaks/gitleaks)
[![CycloneDX SBOM](https://img.shields.io/badge/SBOM-CycloneDX%20v1.5-blue.svg)](https://cyclonedx.org)
[![Coverage](https://img.shields.io/badge/coverage-100%25-brightgreen.svg)](https://pytest.org)
[![Python Version](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.13%20%7C%203.14-blue.svg)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Enterprise-grade, pure-Python distributed tracing SDK, W3C TraceContext propagator, and high-precision latency profiler.

Designed for microservices, asynchronous web frameworks (FastAPI, Starlette, Quart, Django Channels, Flask, WSGI), and high-throughput pipelines where observability must come with near-zero CPU overhead ($<15\ \mu\text{s}$ per operation) and strict DevSecOps security guardrails.

---

## 🌟 Key Capabilities

- **W3C TraceContext RFC Conformance:** Full implementation of `traceparent` (version `00`, 16-byte Trace-ID, 8-byte Span-ID, trace-flags) and `tracestate` (max 32 members, 512 bytes).
- **Asynchronous & Thread-Safe Context:** Transparent propagation across coroutines (`asyncio.gather`, `asyncio.create_task`) and threads using native `contextvars.ContextVar`.
- **Latency Profiler & Exact Percentiles:** Real-time calculation of **p50 (median), p90, p95, p99, p99.9**, mean, and standard deviation using standard linear interpolation algorithms.
- **Sampling Strategies:** `AlwaysOnSampler`, `AlwaysOffSampler`, deterministic `RatioBasedSampler` (consistent trace hashing across distributed services), `RateLimitingSampler` (token bucket), and `ParentBasedSampler`.
- **Pluggable Exporters:**
  - **OpenTelemetry OTLP JSON:** Fully schema-compliant JSON format for OTel Collector, Datadog, Grafana Tempo.
  - **Jaeger JSON:** Native format compatible with Jaeger UI and collectors.
  - **ASCII Terminal Waterfall:** Instant, colored tree hierarchy with duration bars.
- **Zero-Dependency Core:** Pure Python standard library + Pydantic v2. Zero heavy C-extensions or external network dependencies.
- **DevSecOps Hardened:** Strict mitigations against CWE-330, CWE-208, CWE-209, CWE-400, CWE-502, and CWE-798.

---

## 📦 Installation

```bash
pip install distributed-tracing-profiler
```

Or for development / testing:

```bash
git clone https://github.com/cibi-dev/distributed-tracing-profiler.git
cd distributed-tracing-profiler
pip install -e ".[dev]"
```

---

## 🚀 Quickstart

### 1. Manual Span Tracing

```python
from tracing import Tracer, SpanKind, SpanStatus, ASCIIWaterfallExporter

tracer = Tracer(name="order-service")

# Start root span
with tracer.start_span("HTTP POST /orders", kind=SpanKind.SERVER) as root:
    root.set_attribute("user.id", "usr_9981")
    root.set_attribute("authorization", "Bearer eyJhbGciOi...")  # Automatically redacted!

    # Start child span (automatically linked via contextvars)
    with tracer.start_span("db.insert_order", kind=SpanKind.CLIENT) as db_span:
        db_span.set_attribute("db.table", "orders")
        db_span.add_event("query_executed", {"rows_affected": 1})
        db_span.set_status(SpanStatus.OK)

# Print ASCII Waterfall
exporter = ASCIIWaterfallExporter()
print(exporter.render_cascade([root, db_span]))
```

### 2. ASGI Middleware (FastAPI / Starlette)

```python
from fastapi import FastAPI
from tracing import TracingASGIMiddleware, SpanProfiler

app = FastAPI()
profiler = SpanProfiler()

# Wrap ASGI application with distributed tracing
app.add_middleware(TracingASGIMiddleware, profiler=profiler, service_name="fastapi-app")

@app.get("/api/v1/items")
async def get_items():
    return {"items": [1, 2, 3]}

# Access real-time p50/p95/p99 latency percentiles
metrics = profiler.get_metrics("HTTP GET /api/v1/items")
print(f"p50: {metrics.p50_ms}ms | p95: {metrics.p95_ms}ms | p99: {metrics.p99_ms}ms")
```

### 3. Decorator `@traced`

```python
from tracing import traced, SpanKind

@traced(name="payment.charge", kind=SpanKind.CLIENT)
async def process_payment(amount: float, card_token: str):
    # Traced automatically: records timing, exceptions, and sets status
    return {"status": "success", "amount": amount}
```

---

## 📐 W3C TraceContext Specification

This package implements the official [W3C TraceContext Recommendation](https://www.w3.org/TR/trace-context/):

### `traceparent` Header

Format: `version-trace_id-parent_id-trace_flags`
Example: `00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01`

- **version (2 hex):** Currently `00`. `ff` is rejected as invalid.
- **trace_id (32 hex):** 16-byte cryptographically secure non-zero random hex.
- **parent_id / span_id (16 hex):** 8-byte cryptographically secure non-zero random hex.
- **trace_flags (2 hex):** Bit `0x01` indicates whether trace is recorded/sampled.

### `tracestate` Header

Format: `vendor1=opaqueValue,vendor2=opaqueValue` (Max 32 members, max 512 characters).

---

## 📊 Latency Profiler & Percentiles

The `SpanProfiler` collects completed spans into a **bounded circular buffer** (`collections.deque(maxlen=10000)`) to ensure zero memory exhaustion (CWE-400).

```python
from tracing import SpanProfiler

profiler = SpanProfiler(max_buffer_size=10_000)
# Finished spans are recorded via callback: tracer = Tracer(on_span_end=profiler.record_span)

metrics = profiler.get_metrics()
print(f"Total Spans: {metrics.count}")
print(f"Min / Max:   {metrics.min_ms} ms / {metrics.max_ms} ms")
print(f"Mean / Std:  {metrics.mean_ms} ms ± {metrics.stddev_ms} ms")
print(f"p50:         {metrics.p50_ms} ms")
print(f"p90:         {metrics.p90_ms} ms")
print(f"p95:         {metrics.p95_ms} ms")
print(f"p99:         {metrics.p99_ms} ms (Tail Latency)")
print(f"p99.9:       {metrics.p99_9_ms} ms")
```

---

## 🛠️ CLI Reference

The package ships with a standalone CLI `distributed-tracing-profiler`:

```bash
# 1. Inspect and validate W3C headers
distributed-tracing-profiler inspect --traceparent "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"

# 2. Simulate multi-tier distributed transaction with ASCII waterfall
distributed-tracing-profiler trace --output-json trace.json

# 3. Run CPU overhead benchmark
distributed-tracing-profiler benchmark --iterations 50000

# 4. Profile latency percentiles from JSON or synthetic distribution
distributed-tracing-profiler profile --samples 10000
```

---

## 🛡️ DevSecOps & Security Hardening

This package follows the **cibi-dev DevSecOps & Security Standard**:

| Security Control | Reference | Mitigations Implemented |
|---|---|---|
| **Cryptographic Entropy** | CWE-330 / CWE-208 | `secrets.token_hex()` for all Trace-IDs & Span-IDs. Zero-byte IDs rejected. `hmac.compare_digest()` for timing attack immunity. |
| **Sensitive Data Redaction** | CWE-209 | Automatic `[REDACTED]` masking for Authorization headers, bearer tokens, API keys, passwords, cookies, and PII. |
| **Bounded Memory (Anti-DoS)** | CWE-400 | Bounded circular buffer (`deque(maxlen=10000)`). Max 128 attributes and 128 events per span. |
| **Safe Deserialization** | CWE-502 | Native JSON serialization only. No `pickle`, `eval`, or dynamic code execution. |
| **Zero Hardcoded Secrets** | CWE-798 | Verified with `gitleaks detect` (0 leaks). |
| **Static Security Analysis** | SAST | Verified with `bandit -r src/ -ll` (0 findings). |
| **Supply Chain Security** | SLSA L2 | Full CycloneDX Software Bill of Materials (`sbom.json`). |

---

## 🧪 Testing & Validation

Execute the continuous validation gate:

```bash
# 1. Pytest suite with strict coverage enforcement (>=90%)
pytest -v --cov=tracing --cov-report=term-missing --cov-fail-under=90

# 2. Bandit SAST scanner
bandit -r src/ -ll

# 3. Gitleaks secret detection
gitleaks detect --verbose

# 4. Performance benchmarks
python benchmarks/run.py
```

---

## 📜 License

MIT License. Copyright (c) 2026 cibi-dev.
