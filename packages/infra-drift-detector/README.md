# 🛡️ infra-drift-detector

[![Security Scan & DevSecOps CI](https://github.com/cibi-dev/infra-drift-detector/actions/workflows/security-scan.yml/badge.svg)](https://github.com/cibi-dev/infra-drift-detector/actions/workflows/security-scan.yml)
[![Coverage](https://img.shields.io/badge/Coverage-91%25-brightgreen.svg)](pyproject.toml)
[![Bandit SAST](https://img.shields.io/badge/Bandit-0%20Vulnerabilities-success.svg)](SECURITY.md)
[![Gitleaks](https://img.shields.io/badge/Gitleaks-0%20Secrets-success.svg)](SECURITY.md)
[![CycloneDX SBOM](https://img.shields.io/badge/SBOM-CycloneDX%20v1.6-blue.svg)](sbom.json)
[![Python Version](https://img.shields.io/badge/Python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.13%20%7C%203.14-blue.svg)](pyproject.toml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](pyproject.toml)

**`infra-drift-detector`** is an enterprise-grade, **100% read-only GitOps infrastructure drift detector** for Linux systems. It compares a declarative desired-state YAML manifest (system users, systemd services, kernel sysctl flags, listening ports, critical file permissions, and system packages) against the live host state, reporting missing, unexpected, and modified resources with unified diffs.

---

## 🎯 Key Features

- 🔒 **100% Read-Only Guarantee (CWE-250 & CWE-269)**: Pure read-only inspection; never performs state mutations, writes, or alterations on the host.
- ⚡ **High-Throughput Audit Engine**: Capable of evaluating over **106,000 resources/sec** with sub-2ms latency.
- 🧩 **Multi-Domain Probes**:
  - **Users & Groups**: Live `/etc/passwd` & `/etc/group` verification via [`UserInspector`](src/drift/inspectors/users.py).
  - **Systemd Services**: Active/Loaded/Enabled state verification via [`ServiceInspector`](src/drift/inspectors/services.py).
  - **Kernel Sysctl**: Direct procfs `/proc/sys` flags verification via [`SysctlInspector`](src/drift/inspectors/sysctl.py).
  - **Listening Ports**: Direct `/proc/net/tcp` & `udp` socket decoding via [`PortInspector`](src/drift/inspectors/ports.py).
  - **File Attributes & Checksums**: Permissions, ownership, and streaming SHA-256 integrity via [`FileInspector`](src/drift/inspectors/files.py).
  - **System Packages**: Installation & version tracking via [`PackageInspector`](src/drift/inspectors/packages.py).
- 📊 **Multi-Format Reporting**: Generates visual terminal reports, unified diffs, JSON payloads, and PR-ready GitHub Markdown with severity tags ([`DriftReporter`](src/drift/reporter.py)).
- 🛡️ **DevSecOps Hardened**: Strict Safe YAML parser (1MB DoS limit), regex injection defenses, constant-time secret redaction, and `extra="forbid"` Pydantic v2 schemas.

---

## 🚀 Installation & Quickstart

```bash
# Clone and install with development dependencies
git clone https://github.com/cibi-dev/infra-drift-detector.git
cd infra-drift-detector
pip install -e .[dev]

# Validate your desired state manifest
infra-drift validate examples/hardened-bastion.yaml

# Run a live host audit
infra-drift audit examples/hardened-bastion.yaml --exit-code

# Generate unified diff of detected configuration drift
infra-drift diff examples/hardened-bastion.yaml

# Generate PR-ready Markdown report
infra-drift report examples/hardened-bastion.yaml -o pr-drift-report.md
```

---

## 📋 YAML Manifest Schema

A manifest defines the expected state of the host using strict [Pydantic v2 schemas](src/drift/schema.py):

```yaml
version: "1.0"
name: "hardened-bastion"

users:
  - name: "deploy"
    uid: 1001
    shell: "/bin/bash"
    groups: ["sudo", "docker"]
    state: "present"
  - name: "guest"
    state: "absent"

services:
  - name: "ssh"
    state: "running"
    enabled: true
  - name: "telnet"
    state: "absent"

sysctl:
  - key: "net.ipv4.ip_forward"
    value: 0
  - key: "net.ipv4.tcp_syncookies"
    value: 1

ports:
  - port: 22
    protocol: "tcp"
    address: "0.0.0.0"
    state: "listening"
  - port: 23
    protocol: "tcp"
    state: "closed"

files:
  - path: "/etc/shadow"
    mode: "0600"
    owner: "root"
    group: "root"
    state: "present"
  - path: "/etc/sudoers.d/backdoor"
    state: "absent"

packages:
  - name: "curl"
    state: "present"
  - name: "telnet"
    state: "absent"
```

---

## 🛠️ CLI Subcommands Reference

| Subcommand | Description | Flags |
|---|---|---|
| `audit <manifest>` | Compares live host against manifest | `--format=text\|json\|markdown`, `-o <file>`, `--exit-code` |
| `diff <manifest>` | Emits unified diff of drifted attributes | `-o <file>` |
| `validate <manifest>` | Validates YAML syntax & Pydantic schema | *(none)* |
| `report <manifest>` | Generates GitHub PR-ready Markdown report | `-o <file>` |

---

## 🔒 DevSecOps & Security Hardening

This project complies with the **DevSecOps Security Standard** detailed in [`SECURITY.md`](SECURITY.md):

| Control | Reference | Implementation / Mitigation |
|---|---|---|
| **Zero Hardcoded Secrets** | CWE-798 | Validated with Gitleaks (`gitleaks detect`) in CI |
| **100% Read-Only Immutability** | CWE-250 / CWE-269 | Dedicated pytest immutability suite checking zero filesystem mutations |
| **Command Injection Mitigation** | CWE-78 | Safe `subprocess.run(shell=False)` with strict regex whitelists |
| **Path Traversal Defense** | CWE-22 | Traversal blockers rejecting `..` and validating `commonpath` |
| **Safe Deserialization** | CWE-502 | `yaml.safe_load` with Pydantic v2 `extra="forbid"` models |
| **Resource Quota & Anti-DoS** | CWE-400 | Max 1MB manifest size limit & streaming 64KB block hashing |
| **PII & Secret Masking** | CWE-209 | Dynamic token and password redaction ([`sanitize_secrets`](src/drift/parser.py)) |
| **Static Application Security Testing** | Bandit | Clean execution: `0 findings` (`bandit -r . -ll`) |
| **Supply Chain Integrity** | CycloneDX | Continuous SBOM generation ([`sbom.json`](sbom.json)) |

---

## 📊 Benchmark Metrics

Measured with [`benchmarks/run.py`](benchmarks/run.py) (see [`benchmarks/resultados.json`](benchmarks/resultados.json)):

| Metric | Measured Value |
|---|:---:|
| **Throughput** | **106,248+ resources / sec** |
| **Mean Latency (180 resources)** | **1.69 ms** |
| **p50 Median Latency** | **1.62 ms** |
| **p95 Latency** | **2.74 ms** |
| **p99 Latency** | **3.80 ms** |
| **Full Live Host Audit** | **~33 ms** |

---

## 🧪 Testing & Verification

Run the full validation suite:

```bash
# Run pytest test suite with coverage
pytest -v --cov=src/drift --cov-report=term-missing

# Run Bandit security linter
bandit -r . -ll

# Run Mypy strict type checking
mypy src/

# Run Gitleaks secret detection
gitleaks detect --no-git --source . -v
```
