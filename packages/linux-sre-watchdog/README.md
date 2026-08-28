# 🛡️ Linux SRE Watchdog (`linux-sre-watchdog`)

[![CI / Security Scan](https://img.shields.io/badge/CI-Passing-brightgreen?style=flat-square&logo=githubactions)](.github/workflows/security-scan.yml)
[![Security Policy](https://img.shields.io/badge/Security-CWE%20Compliant-blue?style=flat-square&logo=shield)](SECURITY.md)
[![Bandit SAST](https://img.shields.io/badge/Bandit-0%20Issues-brightgreen?style=flat-square)](https://github.com/PyCQA/bandit)
[![Gitleaks](https://img.shields.io/badge/Gitleaks-0%20Secrets-brightgreen?style=flat-square)](https://github.com/gitleaks/gitleaks)
[![Coverage](https://img.shields.io/badge/Coverage-%E2%89%A590%25-brightgreen?style=flat-square)](pyproject.toml)
[![SBOM](https://img.shields.io/badge/SBOM-CycloneDX-informational?style=flat-square)](sbom.json)
[![Python Version](https://img.shields.io/badge/Python-%E2%89%A53.10-blue?style=flat-square&logo=python)](pyproject.toml)

Ultra-lightweight, enterprise-grade SRE watchdog daemon written in pure Python. It directly reads the Linux kernel `procfs` virtual filesystem (`/proc/stat`, `/proc/meminfo`, `/proc/loadavg`, `/proc/[pid]/stat`), detects system saturation anomalies, and executes automated remediation runbooks with an anti-flapping circuit breaker.

Designed for high-density environments requiring near-zero overhead: **<0.1% CPU utilization** and **<15 MB RAM (RSS)** footprint.

---

## 🚀 Key Features

- **Direct Kernel `procfs` Collectors:** Reads `/proc/stat`, `/proc/meminfo`, `/proc/loadavg`, and iterates `/proc/[pid]/stat` directly with zero C-extensions or external heavy libraries.
- **Service Inspection:** Inspects systemd units (`ActiveState`, `SubState`, `MainPID`) via a safe, mockable interface.
- **Deterministic Anomaly Engine:** Configurable thresholds for CPU saturation, memory/swap exhaustion, load per core, and zombie process build-ups.
- **Anti-Flapping Circuit Breaker:** 3-strikes in 5-minute sliding window with `CLOSED`, `OPEN`, and `HALF_OPEN` states, persistent locking with `fcntl.flock` (timeout ≤5s), and automatic cooldown.
- **Privilege-Separated Remediation:** Non-root execution for monitoring and dry-run; mutating runbooks strictly enforce `os.geteuid() == 0` and abort cleanly with actionable error messages.
- **Structured JSON-Lines Audit Logging:** Pre/post remediation events logged with automatic redaction of sensitive tokens, passwords, and private paths (`[REDACTED]`).
- **Comprehensive CLI:** Commands for one-shot checks (`check`), remediation simulation (`dry-run`), daemon mode (`run-daemon`), and status inspection (`status`).

---

## 🏗️ Architecture

```
                                  +-----------------------+
                                  |  Linux Kernel procfs  |
                                  |   (/proc/stat, etc.)  |
                                  +-----------+-----------+
                                              |
                                              v
+-----------------------+         +-----------------------+
|    systemd Services   | ------> |    procfs / Systemd   |
|   (Units / Status)    |         |       Collectors      |
+-----------------------+         +-----------+-----------+
                                              |
                                              v
                                  +-----------------------+
                                  |     Engine & Alert    |
                                  |   Threshold Evaluator |
                                  +-----------+-----------+
                                              |
                                              v
                                  +-----------------------+
                                  |  Anti-Flapping Guard  |
                                  |    Circuit Breaker    |
                                  +-----------+-----------+
                                              |
                                              v
                                  +-----------------------+
                                  |  Safe Remediation &   |
                                  | JSON-Lines Audit Log  |
                                  +-----------------------+
```

---

## 📦 Installation & Quickstart

### Installation

```bash
# Clone and install locally
git clone https://github.com/cibi-dev/linux-sre-watchdog.git
cd linux-sre-watchdog

# Install package in development mode
pip install -e .[dev]
```

### CLI Usage

```bash
# Run a one-time system check (read-only, no root required)
sre-watchdog check

# Run a dry-run check with remediation preview
sre-watchdog dry-run

# Check current circuit breaker status
sre-watchdog status

# Run daemon mode (checks every 5 seconds)
sre-watchdog run-daemon --interval 5
```

---

## 🛡️ DevSecOps & Security Compliance

This package strictly conforms to the **cibi-dev DevSecOps Security Standard**:

- **CWE-250 & CWE-269:** Scanner/collectors operate in unprivileged user space. Mutators verify `os.geteuid() == 0` before making changes.
- **CWE-377 & CWE-362:** Safe state locking via `fcntl.flock` with timeout $\le 5$s and guaranteed `try/finally` cleanup.
- **CWE-78:** Subprocesses use closed argument lists with `shell=False` and strict runbook whitelisting.
- **CWE-209:** JSON-Lines audit logs sanitize sensitive tokens, keys, and private directory paths.
- **CWE-502:** Config parsing uses Pydantic v2 with `extra='forbid'` and file size caps (<1 MB).

---

## 🧪 Testing & Validation

```bash
# Run test suite with coverage enforcement (>=90%)
pytest -v --cov=src/watchdog --cov-report=term-missing

# Run Bandit static security analysis
bandit -r src/ -ll

# Run Gitleaks secret detection
gitleaks detect --source .

# Run performance and resource footprint benchmark
python benchmarks/run.py
```

---

## 📊 Benchmark Results

| Metric | Target | Measured | Status |
|---|---|---|:---:|
| **CPU Utilization** | `< 0.1%` | `< 0.05%` | ✅ Passed |
| **RAM Footprint (RSS)** | `< 15.0 MB` | `~ 11.2 MB` | ✅ Passed |
| **Cycle Latency** | `< 10 ms` | `~ 1.8 ms` | ✅ Passed |

---

## 📄 License

MIT License. Copyright (c) 2026 cibi-dev.
