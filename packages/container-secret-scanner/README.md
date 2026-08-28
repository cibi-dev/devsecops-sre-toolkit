# 🔒 container-secret-scanner

[![CI & Security Audit](https://github.com/cibi-dev/container-secret-scanner/actions/workflows/security-scan.yml/badge.svg)](https://github.com/cibi-dev/container-secret-scanner/actions)
[![Python Version](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.13%20%7C%203.14-blue.svg)](https://www.python.org/)
[![Security: Bandit SAST](https://img.shields.io/badge/security-bandit%20passed-brightgreen.svg)](https://github.com/PyCQA/bandit)
[![Gitleaks: Clean](https://img.shields.io/badge/gitleaks-0%20leaks-brightgreen.svg)](https://github.com/gitleaks/gitleaks)
[![Coverage](https://img.shields.io/badge/coverage-%E2%89%A593%25-brightgreen.svg)](https://pytest.org)
[![SARIF v2.1.0](https://img.shields.io/badge/SARIF-v2.1.0%20OASIS-orange.svg)](https://sarifweb.azurewebsites.net/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

High-performance, enterprise-grade static DevSecOps secret scanner engineered for **Git repositories**, **local filesystems**, and **OCI container TAR layers** (`.tar`, `.tar.gz`, nested layers). Features 36+ precompiled regex rules, Shannon entropy verification, Python AST static assignment detection, and OASIS SARIF v2.1.0 output for native GitHub Code Scanning integration.

---

## 🚀 Key Features

- **⚡ High-Throughput Multi-Threading:** Bounded worker pool (`ThreadPoolExecutor` $\le 32$ threads) processing $>300$ files/sec.
- **🛡️ 36+ Precompiled Regex Rules:** Comprehensive coverage across AWS, GitHub, GCP, Stripe, Slack, Anthropic, OpenAI, Azure, JWT, PGP/RSA keys, databases, and HashiCorp Vault.
- **🧮 Shannon Entropy Verification:** Evaluates bitwise information density ($H(S) = -\sum p_i \log_2 p_i$) to discard low-entropy false positives.
- **📦 In-Memory OCI TAR Streaming:** Iterative layer scanning using `tarfile.extractfile()` without disk extraction, neutralizing Tar Bombs (CWE-409) and Symlink Traversal (CWE-59/CWE-22).
- **🌳 Python AST Static Analysis:** Traverses Python syntax trees to detect hardcoded credentials in assignments, dicts, kwargs, and walrus operators (CWE-798).
- **📊 Native SARIF v2.1.0 Exporter:** Outputs standardized OASIS SARIF v2.1.0 for GitHub Code Scanning alerts and CI/CD gating.
- **🔒 DevSecOps Sanitization:** Automatic redaction masking (`[REDACTED]...xxxx`) preventing information exposure in logs or terminal stdout (CWE-209).

---

## 🛡️ DevSecOps & Security Hardening Matrix

| Security Control | CWE Reference | Implementation & Defense | Verification |
|---|---|---|:---:|
| **Zero Hardcoded Secrets** | CWE-798 | Hardcoded credential exclusion & AST validation | Gitleaks / Pytest |
| **Tar Bomb Protection** | CWE-409 | Cumulative size limit (500MB) & 10k file quota | Unit tests |
| **Symlink & Path Traversal** | CWE-59 / CWE-22 | Stream extraction with `extractfile()` & `commonpath` | Pytest suite |
| **Resource Quota (DoS)** | CWE-400 | Thread pool strictly clamped to $1 \le \text{workers} \le 32$ | Unit tests |
| **Log Information Disclosure** | CWE-209 | Token redaction mask (`[REDACTED]...xxxx`) | Unit tests |
| **Command Injection Defense** | CWE-78 | Subprocess argument arrays (`shell=False`) | Bandit SAST |
| **Static Code Analysis** | SAST | 0 high/medium issues detected | Bandit `-r . -ll` |
| **Type Safety & Integrity** | Strict typing | Full type annotations with Mypy strict mode | Mypy `src/` |

---

## 📦 Installation

```bash
# Clone the repository
git clone https://github.com/cibi-dev/container-secret-scanner.git
cd container-secret-scanner

# Install in editable mode with development dependencies
pip install -e ".[dev]"
```

---

## 💻 CLI Usage

The tool provides three primary subcommands: `scan-dir`, `scan-tar`, and `scan-git`.

### 1. Scan a Directory or File Tree
```bash
container-secret-scanner scan-dir ./my-project --fail-on-secrets
```

### 2. Scan an OCI Container Image Layer (TAR Archive)
```bash
container-secret-scanner scan-tar ./docker-image.tar --format sarif -o results.sarif
```

### 3. Scan a Git Repository
```bash
container-secret-scanner scan-git ./my-repo --fail-on-secrets
```

### CLI Options & Flags

| Flag | Description | Default |
|---|---|:---:|
| `-f, --format` | Report output format: `console`, `sarif`, `json` | `console` |
| `-o, --output` | Path to save output report file | `None` (stdout) |
| `-e, --entropy` | Minimum Shannon entropy threshold in bits | `4.5` |
| `-w, --workers` | Worker threads (bounded between 1 and 32) | `4` |
| `--fail-on-secrets` | Exit with code `1` if secrets are discovered | `False` |
| `--no-ast` | Disable Python AST static assignment scanner | `False` |
| `--no-color` | Disable ANSI color codes in console report | `False` |
| `-q, --quiet` | Suppress console output (useful in CI) | `False` |

---

## 🐍 Python SDK API

```python
from pathlib import Path
from scanner import SecretScannerEngine, ScanOptions, export_sarif

# Configure scanner options
options = ScanOptions(
    max_workers=8,
    entropy_threshold=4.5,
    enable_ast_scan=True,
)

engine = SecretScannerEngine(options=options)

# 1. Scan filesystem directory
summary = engine.scan_directory(Path("./src"))

# 2. Scan OCI container tarball
summary_tar = engine.scan_tar(Path("./layer.tar"))

print(f"Scanned {summary.files_scanned} files in {summary.duration_seconds:.2f}s")
print(f"Found {len(summary.findings)} secrets:")
for finding in summary.findings:
    print(f"  • [{finding.severity}] {finding.rule_name} in {finding.file_path}:{finding.line_number} -> {finding.redacted_text}")

# Export to SARIF v2.1.0
sarif_json = export_sarif(summary, output_path="sarif-report.json")
```

---

## 🔍 Detection Rules Catalog (36 Rules)

| Rule ID | Rule Name | Category | Severity | Min Entropy | CWE |
|---|---|---|:---:|:---:|:---:|
| `RULE-AWS-AKIA` | AWS Access Key ID (AKIA/ASIA) | Cloud Providers | HIGH | — | CWE-798 |
| `RULE-AWS-SECRET` | AWS Secret Access Key | Cloud Providers | CRITICAL | 4.0 bits | CWE-798 |
| `RULE-GITHUB-PAT` | GitHub Personal Access Token | Version Control | CRITICAL | — | CWE-798 |
| `RULE-GITHUB-FINEGRAINED` | GitHub Fine-Grained Token | Version Control | CRITICAL | — | CWE-798 |
| `RULE-GITHUB-OAUTH` | GitHub OAuth Access Token | Version Control | CRITICAL | — | CWE-798 |
| `RULE-GITHUB-APP` | GitHub App Token | Version Control | CRITICAL | — | CWE-798 |
| `RULE-GITHUB-REFRESH` | GitHub Refresh Token | Version Control | HIGH | — | CWE-798 |
| `RULE-JWT` | JSON Web Token (JWT) | Auth & Tokens | HIGH | 4.0 bits | CWE-312 |
| `RULE-RSA-PRIVATE-KEY` | RSA Private Key Header | Cryptography | CRITICAL | — | CWE-312 |
| `RULE-OPENSSH-PRIVATE-KEY` | OpenSSH Private Key Header | Cryptography | CRITICAL | — | CWE-312 |
| `RULE-EC-PRIVATE-KEY` | EC Private Key Header | Cryptography | CRITICAL | — | CWE-312 |
| `RULE-PGP-PRIVATE-KEY` | PGP Private Key Block | Cryptography | CRITICAL | — | CWE-312 |
| `RULE-GENERIC-PRIVATE-KEY` | Generic Private Key Header | Cryptography | CRITICAL | — | CWE-312 |
| `RULE-SLACK-BOT-TOKEN` | Slack Bot Token (`xoxb-`) | Messaging | CRITICAL | — | CWE-798 |
| `RULE-SLACK-USER-TOKEN` | Slack User Token (`xoxp-`) | Messaging | CRITICAL | — | CWE-798 |
| `RULE-SLACK-WEBHOOK` | Slack Webhook URL | Messaging | HIGH | — | CWE-798 |
| `RULE-STRIPE-SECRET-KEY` | Stripe Live Secret Key | Payments | CRITICAL | — | CWE-798 |
| `RULE-STRIPE-RESTRICTED` | Stripe Restricted API Key | Payments | CRITICAL | — | CWE-798 |
| `RULE-GCP-API-KEY` | Google Cloud / Gemini API Key | Cloud Providers | HIGH | — | CWE-798 |
| `RULE-GCP-SERVICE-ACCOUNT` | GCP Service Account Key ID | Cloud Providers | HIGH | — | CWE-798 |
| `RULE-ANTHROPIC-API-KEY` | Anthropic Claude API Key | Cloud Providers | CRITICAL | — | CWE-798 |
| `RULE-OPENAI-API-KEY` | OpenAI API Key (`sk-...`) | Cloud Providers | CRITICAL | — | CWE-798 |
| `RULE-AZURE-STORAGE-KEY` | Azure Storage Account Key | Cloud Providers | CRITICAL | — | CWE-798 |
| `RULE-SENDGRID-API-KEY` | SendGrid API Key | Messaging | HIGH | — | CWE-798 |
| `RULE-TWILIO-API-KEY` | Twilio API Key | Messaging | HIGH | — | CWE-798 |
| `RULE-DISCORD-BOT-TOKEN` | Discord Bot Token | Messaging | CRITICAL | — | CWE-798 |
| `RULE-NPM-ACCESS-TOKEN` | NPM Access Token | Version Control | CRITICAL | — | CWE-798 |
| `RULE-PYPI-API-TOKEN` | PyPI Upload Token | Version Control | CRITICAL | — | CWE-798 |
| `RULE-DATABASE-URL-PASSWORD` | Database URI Password | Databases | HIGH | — | CWE-798 |
| `RULE-HASHICORP-VAULT-TOKEN` | HashiCorp Vault Token | Auth & Tokens | CRITICAL | — | CWE-798 |
| `RULE-DATABRICKS-TOKEN` | Databricks Personal Token | Cloud Providers | HIGH | — | CWE-798 |
| `RULE-GITLAB-PAT` | GitLab Personal Access Token | Version Control | CRITICAL | — | CWE-798 |
| `RULE-SQUARE-ACCESS-TOKEN` | Square Production Token | Payments | CRITICAL | — | CWE-798 |
| `RULE-SHOPIFY-ACCESS-TOKEN` | Shopify Admin API Token | Payments | HIGH | — | CWE-798 |
| `RULE-HEROKU-API-KEY` | Heroku API Key | Cloud Providers | HIGH | — | CWE-798 |
| `RULE-GENERIC-API-KEY` | Generic High-Entropy Key | Generic | MEDIUM | 4.5 bits | CWE-798 |

---

## ⚡ Performance Benchmarks

Measured on Linux (x86_64, 12 cores):

| Benchmark Target | Files Count | Size | Throughput (Files/sec) | Throughput (MB/sec) |
|---|---|---|:---:|:---:|
| **Directory Scan (4 Workers)** | 150 files | ~0.50 MB | **322.29 files/s** | **0.99 MB/s** |
| **OCI TAR In-Memory Stream** | 150 files | ~0.50 MB | **377.28 files/s** | **1.16 MB/s** |

To reproduce benchmarks locally:
```bash
python benchmarks/run.py
```

---

## 🧪 Testing & Validation Suite

```bash
# 1. Run full unit and integration test suite with coverage
pytest -v --cov=scanner --cov-report=term-missing --cov-fail-under=90

# 2. Run Bandit SAST security audit
bandit -r . -ll

# 3. Run Gitleaks secret leak detection
gitleaks detect --source . --verbose

# 4. Run Mypy strict type checking
mypy src/
```
