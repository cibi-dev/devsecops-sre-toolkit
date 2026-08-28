# 📊 slo-burnrate-engine

[![DevSecOps Security Scan](https://github.com/cibi-dev/slo-burnrate-engine/actions/workflows/security-scan.yml/badge.svg)](https://github.com/cibi-dev/slo-burnrate-engine/actions/workflows/security-scan.yml)
[![Coverage](https://img.shields.io/badge/Coverage-95.5%25-brightgreen.svg)](https://github.com/cibi-dev/slo-burnrate-engine)
[![Security: Bandit](https://img.shields.io/badge/Security-Bandit%20Passed-brightgreen.svg)](https://github.com/PyCQA/bandit)
[![Secrets: Gitleaks](https://img.shields.io/badge/Secrets-Gitleaks%20Clean-brightgreen.svg)](https://github.com/gitleaks/gitleaks)
[![SBOM: CycloneDX](https://img.shields.io/badge/SBOM-CycloneDX%20v1.6-blue.svg)](sbom.json)
[![Python Version](https://img.shields.io/badge/Python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.13%20%7C%203.14-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

**Enterprise-grade quantitative SRE engine implementing Google SRE Workbook (Chapter 5) Multi-Window Multi-Burn-Rate alerting, 30-day rolling error budgets, and real-time Time-to-Exhaustion forecasting.**

---

## 🎯 Key Features

- **Google SRE Multi-Window Multi-Burn-Rate Alerting (MWMBR):** Exact implementation of Google SRE Workbook Table 5-8 alert matrix (1h/5m @ 14.4x, 6h/30m @ 6.0x, 24h/2h @ 3.0x, 72h/6h @ 1.0x).
- **Near-Zero Alert Reset Delays:** Evaluates both long and short windows simultaneously, instantly clearing alerts when outages recover.
- **False Alarm Suppression:** Filters out transient brief spikes before pages are dispatched to on-call engineers.
- **30-Day Rolling Error Budget Management:** Quantitative calculation of total allowed errors, consumed error percentage, remaining budget ratio, and exhaustion state.
- **Time-to-Exhaustion (TTE) Forecasting:** Real-time projection of remaining time (seconds, hours, days) until budget depletion.
- **OpenMetrics & Prometheus Exposition:** Generates production-ready OpenMetrics metrics for seamless Prometheus/Grafana integration.
- **Executive Reporting:** Generates high-density Markdown status reports and sanitized JSON payloads.
- **DevSecOps Hardened:** Strict CWE-400 memory bounds, Pydantic v2 safe parsing (CWE-20/CWE-502), and automated credential redaction (CWE-209).

---

## 📐 Mathematical Foundations (Google SRE Workbook)

### 1. Service Level Indicator (SLI)
$$\text{SLI} = \frac{\text{Good Events}}{\text{Total Events}} = 1.0 - \text{Error Rate}$$

### 2. Error Budget
For a target reliability $T$ (e.g. $99.9\% = 0.999$) over compliance period $P$ (standard 30 days):
$$\text{Allowed Error Rate} = 1.0 - T = 0.001$$
$$\text{Total Error Budget Events} = \text{Total Events} \times (1.0 - T)$$
$$\text{Consumed Budget } \% = \left( \frac{\text{Bad Events}}{\text{Total Error Budget Events}} \right) \times 100$$
$$\text{Remaining Budget } \% = 100\% - \text{Consumed Budget } \%$$

### 3. Burn Rate Multiplier
Burn rate $BR$ is the speed at which error budget is being consumed relative to the SLO:
$$BR = \frac{\text{Observed Error Rate}}{\text{Allowed Error Rate}} = \frac{\text{Bad Events} / \text{Total Events}}{1.0 - T}$$
- $BR = 1.0x$: 100% of error budget consumed in 30 days.
- $BR = 14.4x$: 2% of budget consumed in 1 hour (100% in 50 hours).
- $BR = 6.0x$: 5% of budget consumed in 6 hours (100% in 120 hours).
- $BR = 3.0x$: 10% of budget consumed in 24 hours (100% in 240 hours).

### 4. Time-to-Exhaustion (TTE)
$$\text{TTE} = \frac{\text{Remaining Budget Ratio} \times P_{\text{seconds}}}{BR}$$

---

## 🚨 Google SRE Multi-Window Alert Matrix (Table 5-8)

| Tier | Long Window ($W_{\text{long}}$) | Short Window ($W_{\text{short}}$) | Burn Rate Threshold | % Budget Consumed | Severity | Action |
|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| **1** | **1 hour** (3600s) | **5 minutes** (300s) | **14.4x** | 2.0% | `PAGE` | Immediate On-Call Page |
| **2** | **6 hours** (21600s) | **30 minutes** (1800s) | **6.0x** | 5.0% | `PAGE` | Immediate On-Call Page |
| **3** | **24 hours** (86400s) | **2 hours** (7200s) | **3.0x** | 10.0% | `TICKET` | Engineering Investigation |
| **4** | **72 hours** (259200s) | **6 hours** (21600s) | **1.0x** | 10.0% | `INFO` | Daily Triage / Slack Notification |

$$\text{Alert Firing Condition} \iff \left( BR(W_{\text{long}}) \ge \text{Threshold} \right) \land \left( BR(W_{\text{short}}) \ge \text{Threshold} \right)$$

---

## 🚀 Quickstart & Installation

```bash
pip install .
```

For development and testing:
```bash
pip install .[dev]
```

---

## 💻 Python API Usage

### 1. Rolling Error Budget & Burn Rate

```python
from slo import SLODefinition, ErrorBudgetManager, calculate_burn_rate

# Define 99.9% availability SLO over 30 days
slo = SLODefinition(name="checkout-avail", service="checkout-service", target=0.999, window_days=30)
mgr = ErrorBudgetManager(slo)

# Evaluate 30-day compliance
eb = mgr.calculate_from_events(good_events=999_400, total_events=1_000_000)
print(f"Consumed Budget: {eb.consumed_budget_percent:.2f}% | Remaining: {eb.remaining_budget_percent:.2f}%")

# Calculate instantaneous 1-hour Burn Rate and TTE
br = calculate_burn_rate(
    good_events=9856,
    total_events=10000,
    target_slo=0.999,
    window="1h",
    remaining_budget_ratio=eb.remaining_budget_ratio,
)
print(f"Burn Rate: {br.burn_rate:.2f}x | TTE: {br.time_to_exhaustion_hours:.1f} hours")
```

### 2. Multi-Window Alerting & OpenMetrics Export

```python
from slo import MultiWindowAlertEngine, SLOReporter

# Initialize Multi-Window Alert Engine
engine = MultiWindowAlertEngine(slo)

# Evaluate current burn rates
burn_rates = {"1h": 15.0, "5m": 16.0, "6h": 1.0, "30m": 1.0}
alert_res = engine.evaluate_from_burn_rates(burn_rates)

# Generate OpenMetrics / Prometheus exporter text
reporter = SLOReporter(error_budget=eb, burn_rates=[br], alerts=alert_res)
metrics_text = reporter.to_openmetrics()
print(metrics_text)
```

---

## 🖥️ Command Line Interface (CLI)

```bash
# 1. Calculate SLI and Error Budget from event counts
slo-engine calculate --slo 0.999 --good 99950 --total 100000

# 2. Evaluate Burn Rate & Time-to-Exhaustion
slo-engine evaluate-burnrate --slo 0.999 --good 9856 --total 10000 --window 1h

# 3. Check 30-Day Budget Status
slo-engine budget-status --slo 0.999 --service payment-service --good 99500 --total 100000

# 4. Generate Executive SRE Markdown Report
slo-engine report --slo 0.999 --service checkout-service --good 99800 --total 100000 --format markdown
```

---

## ⚡ Performance Benchmarks

Measured on synthetic datasets using `benchmarks/run.py`:

| Workload | Dataset Size | Processing Throughput | Execution Time | Peak Memory |
|---|---|---|---|---|
| **Scalar Event SLI** | 100,000 operations | **160,936 ops/sec** | 0.621s | < 0.1 MB |
| **Vectorized TimeSeries** | 100,000 datapoints (54.9M reqs) | **7.64 Billion req/s** | 0.007s | 2.30 MB |
| **Vectorized TimeSeries** | 1,000,000 datapoints (549.2M reqs) | **2.00 Billion req/s** | 0.274s | 22.89 MB |
| **Vectorized TimeSeries** | 5,000,000 datapoints (2.75B reqs) | **3.91 Billion req/s** | 0.704s | 114.45 MB |
| **Multi-Window Alert Engine** | 25,000 tier evaluations | **6,906 evals/sec** | 3.620s | < 1.0 MB |

---

## 🛡️ DevSecOps & Security Compliance

| Security Control | Standard | Applied Mitigation |
|---|---|---|
| **Zero Hardcoded Secrets** | CWE-798 | 0 findings verified with `gitleaks detect`. |
| **Resource Quotas & Anti-DoS** | CWE-400 | Typed numpy vectorization with configurable memory ceiling (`max_memory_mb=512`). |
| **Safe Deserialization** | CWE-502 / CWE-20 | Strict Pydantic v2 schemas with `extra='forbid'` and numerical bounds. |
| **Information Exposure** | CWE-209 | Automated regex masking of API tokens, Bearer headers, and secrets as `[REDACTED]`. |
| **Path Traversal Defense** | CWE-22 | Dataset input paths sanitized with `os.path.realpath`. |
| **Static Security Analysis** | Bandit (`-r . -ll`) | 0 medium / high severity findings. |
| **Supply Chain Integrity** | CycloneDX SBOM | Automated `sbom.json` generation adhering to CycloneDX v1.6. |

---

## 📄 License

MIT License. Copyright (c) 2026 cibi-dev.
