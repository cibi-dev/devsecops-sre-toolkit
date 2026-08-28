# 🔐 Encrypted Backup Orchestrator

[![CI Security Scan](https://github.com/cibi-dev/encrypted-backup-orchestrator/actions/workflows/security-scan.yml/badge.svg)](https://github.com/cibi-dev/encrypted-backup-orchestrator/actions)
[![Coverage](https://img.shields.io/badge/coverage-95%25-brightgreen.svg)](https://github.com/cibi-dev/encrypted-backup-orchestrator)
[![Security SAST](https://img.shields.io/badge/bandit-0%20vulns-brightgreen.svg)](https://github.com/PyCQA/bandit)
[![Secrets](https://img.shields.io/badge/gitleaks-0%20leaks-brightgreen.svg)](https://github.com/zricethezav/gitleaks)
[![SBOM](https://img.shields.io/badge/SBOM-CycloneDX-blue.svg)](sbom.json)
[![Python](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.13%20%7C%203.14-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

**Encrypted Backup Orchestrator** is an enterprise-grade Disaster Recovery (DR) incremental backup orchestrator featuring SHA-256 block-level deduplication, Zstandard compression, AES-256-GCM authenticated envelope encryption with PBKDF2 key derivation, Grandfather-Father-Son (GFS) lifecycle rotation, and automated sandbox restore validation with 100% cryptographic checksum verification.

---

## 🏗️ Architecture & Core Components

```text
Source Files ──► [Block Splitter (64KB)] ──► [SHA-256 Chunk Hash]
                                                      │
                       ┌──────────────────────────────┴──────────────────────────────┐
                       ▼                                                             ▼
             [Duplicate Chunk]                                                  [New Chunk]
             (Reference in Manifest)                                                 │
                                                                           [Zstandard Compress]
                                                                                     │
                                                                           [AES-256-GCM Encrypt]
                                                                           (PBKDF2-HMAC-SHA256)
                                                                                     │
                                                                           [CAS Storage: chunks/ab/...]
                                                                                     │
[Manifest: manifests/<id>.json] ◄────────────────────────────────────────────────────┘
       │
       ├─► [GFS Rotation: 7 Daily / 4 Weekly / 12 Monthly + Orphan GC]
       └─► [DR Sandbox Restore Test: mkdtemp + 100% SHA-256 Hash Verification]
```

### 1. Block-Level Content Addressable Storage (CAS)
Files are segmented into configurable chunks (default: 64 KB). Every block is indexed by its SHA-256 hash. Identical blocks across files or previous backups are stored only once, drastically reducing storage consumption.

### 2. Zstandard Block Compression
New blocks are compressed using Facebook's `zstandard` algorithm (with fallback/support for `gzip`). Delivers high throughput (>600 MB/s) with optimal compression ratios.

### 3. Authenticated Cryptographic Envelope (AES-256-GCM)
- **Key Derivation:** PBKDF2-HMAC-SHA256 with 600,000 iterations and 32-byte cryptographically secure random salts.
- **Cipher:** AES-256 in Galois/Counter Mode (GCM) with 96-bit unique nonces per block (`os.urandom(12)`).
- **Format:** `[MAGIC: EBO1 (4B)] + [SALT (32B)] + [NONCE (12B)] + [CIPHERTEXT + 16B TAG]`.
- **Integrity:** Authenticated tag prevents tampering, truncation, or bit-flipping attacks.

### 4. Grandfather-Father-Son (GFS) Lifecycle Manager
- **Son (Daily):** Retains the latest backup of each day for the last 7 calendar days.
- **Father (Weekly):** Retains the latest backup of each ISO week for the last 4 calendar weeks.
- **Grandfather (Monthly):** Retains the latest backup of each month for the last 12 calendar months.
- **Orphan Garbage Collector:** Prunes unreferenced blocks and manifests, reclaiming physical disk space.

### 5. Automated DR Sandbox Restore Verification
Automated disaster recovery testing reconstructs files in an isolated temporary sandbox (`tempfile.mkdtemp`), verifies 100% SHA-256 checksums in constant time (`hmac.compare_digest`), and guarantees complete sandbox destruction (`atexit` + `try/finally`).

---

## 🚀 Quickstart

### Installation

```bash
# Clone and install with development dependencies
git clone https://github.com/cibi-dev/encrypted-backup-orchestrator.git
cd encrypted-backup-orchestrator
pip install -e .[dev]
```

### 1. Create an Encrypted Backup

```bash
# Backup directory with AES-256-GCM encryption & Zstandard compression
export BACKUP_PASSPHRASE="MySuperSecretVaultKey#2026!"

backup-orchestrator backup \
  --source /var/data \
  --repo /mnt/backups/repo \
  --compress zstd \
  --name "prod_daily_backup" \
  --verify-sandbox
```

### 2. Verify Backup Cryptographic Integrity

```bash
# Run isolated sandbox test with 100% SHA-256 checksum verification
backup-orchestrator verify \
  --repo /mnt/backups/repo \
  --backup-id latest
```

### 3. Restore Backup to Destination

```bash
# Restore specific backup archive to target directory
backup-orchestrator restore \
  --repo /mnt/backups/repo \
  --backup-id latest \
  --target /var/restore_target
```

### 4. Apply GFS Retention & Garbage Collection

```bash
# Preview pruning candidates (dry-run)
backup-orchestrator rotate --repo /mnt/backups/repo

# Execute rotation and orphan chunk cleanup
backup-orchestrator rotate --repo /mnt/backups/repo --execute
```

### 5. Check Repository Status & Deduplication Metrics

```bash
# View human-readable or JSON statistics
backup-orchestrator status --repo /mnt/backups/repo
backup-orchestrator status --repo /mnt/backups/repo --json
```

---

## 🛡️ DevSecOps & Security Compliance

| Standard | Description | Mitigation Strategy | Verification |
|---|---|---|:---:|
| **CWE-798** | Hardcoded Credentials | Passphrase via CLI parameter or `BACKUP_PASSPHRASE` environment variable | Gitleaks + AST scan |
| **CWE-22** | Path Traversal | Canonical validation with `realpath` and `commonpath` | Pytest traversal suite |
| **CWE-208** | Timing Attacks | Constant-time comparisons using `hmac.compare_digest()` | Unit tests |
| **CWE-321 / 330** | Cryptographic Hygiene | Unique 32-byte salt and 12-byte nonce generated per block with `os.urandom` | PBKDF2 + AESGCM tests |
| **CWE-377** | Insecure Temp Files | Secure `tempfile.mkdtemp()` with strict permissions and guaranteed cleanup | Sandbox lifecycle tests |
| **CWE-502** | Unsafe Deserialization | Strict Pydantic v2 validation models for all JSON manifests | Schema tests |

---

## 📊 Benchmark Metrics

Executed with representative mixed workloads (logs, structured text, binary blobs, and duplicate archives):

| Operation | Throughput | Verification / Ratio |
|---|:---:|:---:|
| **Scan & SHA-256 Block Deduplication** | **> 500 MB/s** | 4.58 : 1 Dedup Ratio |
| **Zstandard Block Compression** | **> 600 MB/s** | 1.38 : 1 Compression Ratio |
| **AES-256-GCM Encryption** | **> 270 MB/s** | Authenticated Envelope |
| **Automated Sandbox Restore** | **> 160 MB/s** | **100.0% Verified Hashes** |

---

## 🧪 Running Tests & Quality Gates

```bash
# 1. Run unit, integration, and security tests with coverage gate (>=90%)
pytest -v

# 2. Run Bandit SAST scan
bandit -r . -ll

# 3. Run Gitleaks secret scan
gitleaks detect --source . -v --no-git

# 4. Generate CycloneDX SBOM
cyclonedx-py environment --output-file sbom.json

# 5. Run Performance Benchmarks
python benchmarks/run.py
```

---

## 📄 License

Apache License 2.0. See [LICENSE](LICENSE) for details.
