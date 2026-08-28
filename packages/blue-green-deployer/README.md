# Blue/Green Deployer 🚀

[![CI & Security Scan](https://github.com/cibi-dev/blue-green-deployer/actions/workflows/security-scan.yml/badge.svg)](https://github.com/cibi-dev/blue-green-deployer/actions/workflows/security-scan.yml)
[![Coverage](https://img.shields.io/badge/coverage-93%25-brightgreen.svg)](https://github.com/cibi-dev/blue-green-deployer)
[![Bandit](https://img.shields.io/badge/security-bandit%20passed-green.svg)](https://github.com/cibi-dev/blue-green-deployer)
[![SBOM](https://img.shields.io/badge/SBOM-CycloneDX-blue.svg)](sbom.json)
[![Python](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.13%20%7C%203.14-blue.svg)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

**Enterprise-grade zero-downtime Blue/Green deployment orchestrator for Linux** that manages two identical environments, validates active HTTP health checks on the passive environment, and executes atomic proxy traffic switching via POSIX symlinks and safe proxy reloads (`nginx -t` + `nginx -s reload`), backed by deterministic auto-rollback verified in **< 30 seconds**.

---

## 🏛️ Blue/Green Architecture & Lifecycle

```
                           [ Incoming User Traffic ]
                                      │
                                      ▼
                      ┌───────────────────────────────┐
                      │    Nginx / Reverse Proxy      │
                      │  (Reads: active_upstream.conf)│
                      └───────────────┬───────────────┘
                                      │
                 ┌────────────────────┴────────────────────┐
                 │ (Atomic Symlink Pointer via rename(2))  │
                 ▼                                         ▼
      ┌─────────────────────┐                   ┌─────────────────────┐
      │     BLUE Slot       │                   │     GREEN Slot      │
      │   127.0.0.1:8081    │                   │   127.0.0.1:8082    │
      │   [ ACTIVE 🟢 ]     │                   │   [ PASSIVE ⚪ ]    │
      └─────────────────────┘                   └──────────┬──────────┘
                                                           │
                                             Active HTTP Health Probe
                                             (Pre-Switch Validation)
```

### Orchestration Sequence

1. **Mutex Lock Acquisition (CWE-362)**: Acquires an exclusive `fcntl.flock` with a strict timeout ($\le 5\,\text{s}$) to prevent concurrent double deployments.
2. **Pre-Switch Active Health Probing**: Sends active HTTP probes to the passive environment (e.g. Green). Requires consecutive passing checks before proceeding. If unhealthy, the deployment aborts cleanly with **zero traffic shifted**.
3. **Atomic Symlink Traffic Switch (CWE-377)**: Creates a unique temporary symlink in the same filesystem directory and atomically swaps the active symlink via `os.replace` (`rename(2)`).
4. **Safe Proxy Reload (CWE-78)**: Runs configuration validation (`nginx -t`) followed by non-disruptive worker reload (`nginx -s reload`) without killing active connections.
5. **Post-Switch Health Validation**: Probes the newly active slot under real traffic conditions.
6. **Deterministic Auto-Rollback**: If post-switch health fails, traffic is atomically reverted to the previous healthy slot in **< 30 seconds** (actual benchmark: **~10 ms**).

---

## 🛡️ DevSecOps & Security Hardening (CWE Mitigations)

This package implements the **cibi-dev DevSecOps Security Standard**:

| Security Control | CWE Target | Implementation Mechanism |
|---|---|---|
| **Concurrency Locking** | **CWE-362** | Non-blocking `fcntl.flock` with strict timeout ($\le 5\,\text{s}$) ensuring single-process execution. |
| **Secure Atomic Temporary Files** | **CWE-377** | Unique PID/token symlinks replaced atomically via POSIX `os.replace` (`rename(2)`) with try/finally cleanup. |
| **Privilege Separation** | **CWE-250** | Read-only inspection runs unprivileged; mutation verifies `os.geteuid() == 0` or requires explicit flag. |
| **Safe Subprocess Execution** | **CWE-78** | Fixed list arguments (`shell=False`) for `nginx -t` and `nginx -s reload`, preventing shell injection. |
| **Path Traversal Defense** | **CWE-22** | Strict absolute path canonicalization via `os.path.abspath()` on all symlinks and configurations. |
| **Anti-DoS Resource Quotas** | **CWE-400** | Bounded HTTP connection timeouts (default 2s), retry ceilings, and bounded mutex polling loops. |
| **Zero Hardcoded Secrets** | **CWE-798** | Clean codebase verified continuously by `gitleaks detect` in CI. |

---

## ⚡ Performance Benchmarks

Measured on Linux 7.1 x86_64 with Python 3.14 (see [`benchmarks/resultados.json`](benchmarks/resultados.json)):

| Benchmark Metric | Iterations | Mean Latency | P95 Latency | P99 Latency | SLA Compliance |
|---|:---:|:---:|:---:|:---:|:---:|
| **Atomic Symlink Traffic Switch** | 1,000 | **0.119 ms** | 0.281 ms | 0.492 ms | **8,383 ops/sec** |
| **Concurrency Flock Mutex** | 500 | **0.014 ms** | 0.021 ms | 0.038 ms | Mutex safe |
| **Deterministic Auto-Rollback** | 200 | **10.136 ms** | 18.520 ms | 27.945 ms | **PASSED (<30s SLA)** |
| **Full Deployment Cycle (End-to-End)** | 100 | **21.667 ms** | 32.948 ms | 48.110 ms | Zero downtime |

---

## 📦 Installation

```bash
# Clone and install locally in editable mode
cd /home/cibi/Proyectos/projects/blue-green-deployer
pip install -e ".[dev]"
```

---

## 🚀 Quickstart & Usage

### 1. Configuration (`deployer.json`)

```json
{
  "blue": {
    "name": "blue",
    "host": "127.0.0.1",
    "port": 8081,
    "health_endpoint": "/health",
    "config_path": "/etc/nginx/conf.d/upstream_blue.conf"
  },
  "green": {
    "name": "green",
    "host": "127.0.0.1",
    "port": 8082,
    "health_endpoint": "/health",
    "config_path": "/etc/nginx/conf.d/upstream_green.conf"
  },
  "health": {
    "endpoint": "/health",
    "expected_status": 200,
    "timeout_seconds": 2.0,
    "max_retries": 3,
    "consecutive_successes_required": 2
  },
  "router": {
    "symlink_path": "/etc/nginx/conf.d/active_upstream.conf",
    "backup_dir": "/var/backups/blue-green",
    "enable_proxy_reload": true,
    "test_command": ["nginx", "-t"],
    "reload_command": ["nginx", "-s", "reload"]
  },
  "rollback": {
    "auto_rollback_enabled": true,
    "post_switch_health_checks": 3,
    "max_rollback_timeout_seconds": 30.0
  }
}
```

### 2. CLI Usage

```bash
# Check status and live health of both environments
blue-green-deployer --config deployer.json status

# Probe health of active or specific slot
blue-green-deployer --config deployer.json health --slot both

# Execute zero-downtime Blue/Green deployment
blue-green-deployer --config deployer.json deploy

# Explicitly deploy to a target slot with JSON output
blue-green-deployer --config deployer.json deploy --target green --json

# Manual traffic switch
blue-green-deployer --config deployer.json switch --target blue

# Trigger emergency rollback
blue-green-deployer --config deployer.json rollback --reason "High latency alert on Green"
```

### 3. Python SDK Usage

```python
from deployer import DeployEngine, DeployerConfig, EnvironmentSlot

# Load configuration
config = DeployerConfig.from_file("deployer.json")

# Initialize orchestration engine
engine = DeployEngine(config=config)

# Run full zero-downtime deployment cycle
result = engine.deploy(target_slot=EnvironmentSlot.GREEN)

if result.success:
    print(f"Deployment succeeded! Active slot: {result.new_active_slot}")
else:
    print(f"Deployment failed ({result.status}): {result.message}")
    if result.rollback_result:
        print(f"Auto-rollback executed in {result.rollback_result.rollback_duration_ms} ms")
```

---

## 🧪 Testing & Verification

```bash
# Run pytest with coverage gate (>=90%)
pytest -v --cov=deployer --cov-report=term-missing --cov-fail-under=90

# Static security analysis with Bandit (0 findings required)
bandit -r src/ -ll

# Secret detection with Gitleaks
gitleaks detect

# Generate CycloneDX Software Bill of Materials (SBOM)
cyclonedx-py environment --pyproject pyproject.toml -o sbom.json

# Run benchmarks
python benchmarks/run.py
```

---

## 📄 License

MIT License © 2026 cibi-dev
