# 🛡️ Linux CIS Hardener (`linux-cis-hardener`)

[![CI / Security Scan](https://github.com/cibi-dev/linux-cis-hardener/actions/workflows/security-scan.yml/badge.svg)](https://github.com/cibi-dev/linux-cis-hardener/actions/workflows/security-scan.yml)
[![Security Policy](https://img.shields.io/badge/Security-SECURITY.md-blue.svg)](SECURITY.md)
[![SAST Bandit](https://img.shields.io/badge/SAST-Bandit%20Passing-brightgreen.svg)](https://github.com/PyCQA/bandit)
[![Coverage](https://img.shields.io/badge/Coverage-94%25-brightgreen.svg)](#test-coverage)
[![SBOM](https://img.shields.io/badge/SBOM-CycloneDX-informational.svg)](sbom.json)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Enterprise-grade, lightweight Linux security auditing and automated remediation suite based on **Center for Internet Security (CIS) Benchmark Level 1** baseline.

Features non-privileged auditing, **0–100% weighted compliance scoring**, idempotent atomic remediations, **mandatory `--dry-run` simulation mode**, automatic timestamped `.bak` snapshots, and **deterministic rollback**.

---

## 🚀 Key Features

- 🔍 **Non-Privileged Security Auditing (CWE-250):** Read-only scanner evaluates system state without requiring `root` privileges.
- 🎯 **Weighted Scoring Engine:** Evaluates compliance from **0.0% to 100.0%**, weighted by severity (CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1).
- 🔧 **Idempotent Automated Remediation:** Safely configures hardened baselines; consecutive runs make 0 modifications.
- 🛡️ **Mandatory Dry-Run Preview:** Simulate proposed configuration changes prior to any disk mutation via `--dry-run`.
- 💾 **Timestamped Backups & Deterministic Rollback:** Takes SHA-256 verified `.bak` snapshots before any change and supports one-click reversal.
- 📊 **Multi-Format Reporting:** Outputs structured compliance reports in colored Console, Markdown, and JSON.
- 🔒 **DevSecOps Standard Compliance:** 100% pass on Bandit SAST, Gitleaks, pip-audit, and strict path traversal defense (CWE-22).

---

## 📋 CIS Benchmark Level 1 Rule Coverage

| Rule ID | CIS Ref | Section | Title | Severity | Remediation |
|---|:---:|---|---|:---:|:---:|
| `CIS-SSH-001` | 5.2.4 | SSH Server | Disable Direct Root Login (`PermitRootLogin no`) | **CRITICAL** | ✅ Auto |
| `CIS-SSH-002` | 5.2.8 | SSH Server | Disable Password Auth (`PasswordAuthentication no`) | **HIGH** | ✅ Auto |
| `CIS-SSH-003` | 5.2.5 | SSH Server | Limit Max Auth Attempts (`MaxAuthTries <= 4`) | **MEDIUM** | ✅ Auto |
| `CIS-SSH-004` | 5.2.6 | SSH Server | Disable GUI Forwarding (`X11Forwarding no`) | **HIGH** | ✅ Auto |
| `CIS-SSH-005` | 5.2.11 | SSH Server | Set Client Inactivity Timeout (`ClientAliveInterval 300`) | **LOW** | ✅ Auto |
| `CIS-SSH-006` | 5.2.10 | SSH Server | Set Login Grace Timeout (`LoginGraceTime 60`) | **MEDIUM** | ✅ Auto |
| `CIS-SYSCTL-001` | 3.1.1 | Kernel/Sysctl | Disable IP Packet Forwarding (`net.ipv4.ip_forward = 0`) | **HIGH** | ✅ Auto |
| `CIS-SYSCTL-002` | 3.1.2 | Kernel/Sysctl | Disable Packet Redirect Sending (`send_redirects = 0`) | **MEDIUM** | ✅ Auto |
| `CIS-SYSCTL-003` | 3.2.2 | Kernel/Sysctl | Disable ICMP Redirect Acceptance (`accept_redirects = 0`) | **MEDIUM** | ✅ Auto |
| `CIS-SYSCTL-004` | 3.2.8 | Kernel/Sysctl | Enable TCP SYN Cookies (`net.ipv4.tcp_syncookies = 1`) | **HIGH** | ✅ Auto |
| `CIS-SYSCTL-005` | 1.5.3 | Kernel/Sysctl | Enable ASLR Memory Randomization (`kernel.randomize_va_space = 2`) | **CRITICAL** | ✅ Auto |
| `CIS-SYSCTL-006` | 3.2.1 | Kernel/Sysctl | Disable Source Routed Packets (`accept_source_route = 0`) | **MEDIUM** | ✅ Auto |
| `CIS-SYSCTL-007` | 3.2.4 | Kernel/Sysctl | Enable Martian Packet Logging (`log_martians = 1`) | **LOW** | ✅ Auto |
| `CIS-PERM-001` | 6.1.2 | File Perms | Verify `/etc/passwd` Permissions (`0644`, `root:root`) | **HIGH** | ✅ Auto |
| `CIS-PERM-002` | 6.1.3 | File Perms | Verify `/etc/shadow` Permissions (`0640`, `root:shadow`) | **CRITICAL** | ✅ Auto |
| `CIS-PERM-003` | 6.1.4 | File Perms | Verify `/etc/gshadow` Permissions (`0640`, `root:shadow`) | **CRITICAL** | ✅ Auto |
| `CIS-PERM-004` | 6.1.5 | File Perms | Verify `/etc/group` Permissions (`0644`, `root:root`) | **HIGH** | ✅ Auto |
| `CIS-PERM-005` | 5.4.4 | Access Control | Configure Default User `umask 027` in `/etc/login.defs` | **MEDIUM** | ✅ Auto |
| `CIS-PERM-006` | 6.1.10 | File Perms | Verify `/etc/ssh/sshd_config` Permissions (`0600`, `root:root`) | **HIGH** | ✅ Auto |
| `CIS-FW-001` | 3.5.1.1 | Firewall | Ensure Host Firewall (`nftables.conf`) is Present | **HIGH** | ✅ Auto |
| `CIS-FW-002` | 3.5.1.2 | Firewall | Ensure Default Firewall Policy is `DROP` on Input/Forward | **HIGH** | ✅ Auto |
| `CIS-FW-003` | 3.5.1.4 | Firewall | Ensure Loopback Interface Traffic is Accepted | **MEDIUM** | ✅ Auto |

---

## ⚡ Quickstart & Installation

```bash
# Clone and install with development dependencies
git clone https://github.com/cibi-dev/linux-cis-hardener.git
cd linux-cis-hardener
pip install -e .
```

---

## 💻 CLI Usage & Commands

### 1. Audit Target System (Read-Only, Unprivileged)

```bash
# Run complete audit against local host (Console output)
cis-hardener audit

# Run audit and export report to Markdown
cis-hardener audit --format markdown --output cis-audit-report.md

# Run audit in CI/CD pipeline and fail if score is below 90%
cis-hardener audit --fail-under 90.0

# Audit specific sandbox or chroot directory
cis-hardener audit --root-prefix /tmp/chroot-env
```

### 2. Preview Remediation (`--dry-run`)

```bash
# Preview changes that would be applied without touching disk
sudo cis-hardener remediate --dry-run

# Filter preview to SSH rules only
sudo cis-hardener remediate --section SSH --dry-run
```

### 3. Apply Hardening (Privileged Execution)

```bash
# Execute idempotent hardening and create automatic timestamped backup
sudo cis-hardener remediate

# Apply specific rule
sudo cis-hardener remediate --rule CIS-SSH-001
```

### 4. Deterministic Rollback

```bash
# List all previous backup sessions
sudo cis-hardener rollback --list

# Revert to the latest backup session
sudo cis-hardener rollback

# Revert to a specific timestamped session
sudo cis-hardener rollback --session-id cis_session_20260827_200815_123456
```

### 5. Inspect CIS Rule Catalogue

```bash
# List all registered rules in terminal
cis-hardener rules

# Output rule catalogue as JSON
cis-hardener rules --json
```

---

## 🛡️ DevSecOps & Security Governance

This repository enforces the **cibi-dev DevSecOps Security Standard** ([`SECURITY.md`](SECURITY.md)):

1. **Privilege Separation (CWE-250 & CWE-269):** Scanner operates without root; remediator strictly enforces `os.geteuid() == 0` on live systems.
2. **Safe Subprocess Execution (CWE-78):** All system commands use controlled argument lists with `shell=False` and bounded execution timeouts.
3. **Path Traversal Defense (CWE-22):** Strict `os.path.commonpath()` validation ensures backups, file writes, and sandbox operations remain confined.
4. **Data Deserialization & Size Limits (CWE-502 / CWE-400):** Pydantic v2 strict schemas with `extra='forbid'` and file size caps (<10 MB) prevent DoS attacks.
5. **Deterministic Integrity:** SHA-256 hashes verified during backup and rollback.

---

## 📊 Benchmarks & Performance Metrics

Real benchmark results measured across 50 audit runs ([`benchmarks/resultados.json`](benchmarks/resultados.json)):

- **Audit Latency (Mean):** `2.735 ms`
- **P95 Latency:** `4.741 ms`
- **P99 Latency:** `5.878 ms`
- **Audit Throughput:** `~7,901 rules / second`
- **RAM Footprint:** `< 800 MB`

---

## 🧪 Validation & Test Suite

```bash
# Run test suite with strict coverage enforcement (>=90%)
pytest -v

# Run Static Application Security Testing
bandit -r . -ll

# Run secret leak detection
gitleaks detect --no-git --source . -v
```

---

## 📄 License

MIT License. Copyright (c) 2026 cibi-dev.
