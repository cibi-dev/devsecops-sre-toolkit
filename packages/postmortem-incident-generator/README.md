# 📋 postmortem-incident-generator

[![DevSecOps CI](https://github.com/cibi-dev/postmortem-incident-generator/actions/workflows/security-scan.yml/badge.svg)](https://github.com/cibi-dev/postmortem-incident-generator/actions)
[![Security: Bandit SAST](https://img.shields.io/badge/Security-Bandit%20SAST%20Clean-brightgreen.svg)](https://github.com/PyCQA/bandit)
[![Secrets: Gitleaks](https://img.shields.io/badge/Secrets-Gitleaks%20Verified-blue.svg)](https://github.com/gitleaks/gitleaks)
[![Coverage: >=95%](https://img.shields.io/badge/Coverage-95.67%25-brightgreen.svg)](https://github.com/pytest-dev/pytest)
[![SBOM: CycloneDX](https://img.shields.io/badge/SBOM-CycloneDX%20v1.5-blueviolet.svg)](sbom.json)
[![Python: >=3.10](https://img.shields.io/badge/Python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.13%20%7C%203.14-blue.svg)](pyproject.toml)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

**postmortem-incident-generator** is an enterprise-grade CLI and Python framework for **Blameless SRE Post-Mortem automation**. It safely collects read-only post-incident telemetry, reconstructs minute-by-minute incident timelines, calculates mathematically exact SRE response metrics (**TTD, MTTA, MTTR, TTM**), enforces blameless culture standards, and generates auditable executive Markdown reports conforming to Google SRE, Netflix, and PagerDuty standards.

---

## 🌟 Key Features

- 🛡️ **Zero-Mutation Evidence Collector (CWE-250 / CWE-78):** Captures read-only host saturation metrics, `journalctl` / syslog traces, git commits, and deployment diffs with closed argument lists (`shell=False`) and timeout protections.
- 🔒 **Deterministic Evidence Sanitizer (CWE-209 / CWE-532):** Linear-time regex engine redacts Bearer tokens, private keys (`BEGIN RSA PRIVATE KEY`), JWTs, AWS credentials (`AKIA...`), URLs with basic auth, and PII to `[REDACTED]`.
- ⏱️ **Timeline Reconstruction & SRE Metrics:** Computes Time to Detect (**TTD**), Time to Acknowledge (**MTTA / TTA**), Time to Mitigate (**TTM**), and Time to Resolve (**MTTR / TTR**).
- 🧠 **Structured 5-Whys & Blameless RCA Engine:** Generates structured 5-Whys causal chains, categorizes systemic contributing factors, prioritizes Action Items (`P0`–`P3`), and audits post-mortem text against blame-oriented language.
- 💾 **100% Parameterized SQLite Storage (CWE-89):** Persistent ACID incident repository using native parameterized bindings (`?`, `?`) preventing SQL injection.
- 📄 **Deterministic Executive Markdown Generator:** Renders auditable SRE post-mortem reports with metrics tables, timeline diagrams, RCA summaries, and sanitized technical evidence.

---

## 🚀 Quickstart & Installation

```bash
# Clone the repository
git clone https://github.com/cibi-dev/postmortem-incident-generator.git
cd postmortem-incident-generator

# Install in development mode
pip install -e ".[dev]"
```

---

## 💻 CLI Usage Guide

### 1. Record an Incident
```bash
postmortem record \
  --id INC-2026-0827-01 \
  --title "Payment Gateway 504 Timeout Spike" \
  --severity SEV-1 \
  --status RESOLVED \
  --summary "Stalled database connection pool caused payment gateway timeout." \
  --user-impact "240 users experienced checkout delays." \
  --trigger "Concurrent batch settlement run" \
  --root-cause "Global table locking without partition pruning" \
  --collect-evidence
```

### 2. Append Timeline Milestones
```bash
postmortem timeline \
  --incident-id INC-2026-0827-01 \
  --add-event \
  --timestamp "2026-08-27T10:04:00Z" \
  --event-type DETECTION \
  --desc "Prometheus alert 5xx rate > 5%" \
  --source "Prometheus" \
  --impact CRITICAL
```

### 3. Display Calculated SRE Metrics
```bash
postmortem metrics --incident-id INC-2026-0827-01
```
*Output:*
```text
⏱️ SRE Metrics for Incident: INC-2026-0827-01
--------------------------------------------------
Time to Detect (TTD):       4m           (240.0s)
Time to Ack (MTTA):         2m           (120.0s)
Time to Mitigate (TTM):     20m          (1200.0s)
Time to Resolve (MTTR):     25m          (1500.0s)
Total Outage Duration:      25m          (1500.0s)
--------------------------------------------------
```

### 4. Generate Executive Markdown Report
```bash
# Generate to Markdown file
postmortem generate --incident-id INC-2026-0827-01 --output postmortem-report.md

# Or export structured JSON
postmortem generate --incident-id INC-2026-0827-01 --format json --output report.json
```

### 5. Collect System Telemetry & Sanitize Secrets
```bash
# Capture local evidence bundle
postmortem collect --service nginx --lines 100 --output evidences.json

# Sanitize arbitrary logs / tokens
postmortem sanitize --file /path/to/raw.log --output /path/to/sanitized.log
```

---

## 🧱 Architecture Overview

```text
postmortem/
├── collector.py        # Read-only evidence gathering (journalctl, git, saturation)
├── sanitizer.py        # Multi-stage deterministic credential & PII mask engine ([REDACTED])
├── timeline_builder.py # Minute-by-minute timeline builder & SRE metrics (TTD/MTTA/MTTR)
├── rca_engine.py       # 5-Whys, contributing factors, action items & blameless checker
├── generator.py        # Jinja2 SRE Markdown & JSON report generator
├── storage.py          # 100% Parameterized SQLite repository
└── cli.py              # Unified CLI dispatcher
```

---

## 🛡️ DevSecOps & Security Hardening

| Control | Reference | Implementation & Mitigation |
|---|---|---|
| **Credential Sanitization** | CWE-209 / CWE-532 | Auto-redaction of Bearer tokens, private keys, JWTs, AWS keys to `[REDACTED]` |
| **SQL Injection Defense** | CWE-89 | 100% Parameterized queries (`?`, `?`) across all SQLite statements |
| **Safe Subprocess Execution** | CWE-78 | Arguments passed as closed lists with `shell=False` and strict timeouts |
| **Least Privilege / Read-Only** | CWE-250 | Zero mutation of system state or git histories |
| **ReDoS & Resource Quotas** | CWE-400 | Linear-time bounded regexes, 64KB log line limits, bounded buffer caps |
| **SAST Verification** | Bandit | 0 issues identified at `-ll` high-confidence level |
| **Supply Chain Security** | CycloneDX | Automated `sbom.json` generation and dependency vulnerability audits |

---

## ⚡ Performance Benchmarks

Real-world metrics generated on local CPU (`benchmarks/resultados.json`):

| Component | Benchmark Metric | Measured Performance |
|---|---|:---:|
| **Evidence Sanitizer** | Throughput | **5.16 MB/s** |
| **Evidence Collector** | Collection Latency | **14.38 ms** |
| **Timeline Reconstruction** | 100 Events Calculation | **0.235 ms** |
| **Markdown Generator** | Report Rendering | **0.324 ms** (3,085 reports/sec) |
| **SQLite Storage** | Roundtrip Save & Retrieve | **0.837 ms** (1,195 ops/sec) |

---

## 🧪 Quality Gates Execution

```bash
# 1. Run unit & integration test suite with coverage
pytest -v --cov=src/postmortem --cov-report=term-missing --cov-fail-under=90

# 2. Run static security analysis
bandit -r src/ -ll

# 3. Verify zero secrets
gitleaks detect --source . --no-git -v

# 4. Type checking
mypy src/

# 5. Run performance benchmarks
python benchmarks/run.py

# 6. Generate CycloneDX SBOM
cyclonedx-py environment --pyproject pyproject.toml -o sbom.json
```

---

## 📄 License
MIT License. Created by [cibi-dev](https://github.com/cibi-dev).
