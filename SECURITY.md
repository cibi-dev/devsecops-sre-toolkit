# Security Policy — `devsecops-sre-toolkit`

## Standards Applied (SECURITY.md Canonical #1–17)

### Base Controls (#1–5)
- **#1 Secrets:** Zero hardcoded credentials (CWE-798). Gitleaks pre-commit + CI scanning.
- **#2 Input Validation:** All CLI arguments, JSON/YAML schemas validated via Pydantic v2 with `extra='forbid'` (CWE-20).
- **#3 Safe Deserialization:** Strict `yaml.safe_load()` and `json.loads()` bounded to <1MB (CWE-502, CWE-400).
- **#4 Dependency Pinning:** Dependencies pinned in `pyproject.toml` with reproducible CycloneDX SBOM.
- **#5 Structured Logging & Sanitization:** Zero PII/credential leakage in logs; redacts tokens, URLs with passwords, and paths (CWE-209).

### Phase 2 Controls (#6–13)
- **#6 Safe Archive Handling:** Zip/Tar extraction bounded with `os.path.commonpath()` anti-ZipSlip (CWE-409/59).
- **#7 Bounded Resource Limits:** Alert and manifest evaluator limits file sizes to 1MB and timeouts to 5s (CWE-400).
- **#8 Atomic File Operations:** Temp files created via `tempfile.mkstemp` with `0o600` permissions and cleanup guarantees.
- **#9 Cryptographic Hygiene:** Constant-time hash and token comparisons via `hmac.compare_digest()` (CWE-208).
- **#10 Async & Network Timeouts:** Blackbox prober and reverse proxy enforce non-blocking timeouts with circuit breakers (CWE-400).
- **#11 Privilege Separation:** Strict read-only inspections run non-root; remediation requires explicit confirmation (CWE-250/269).
- **#12 Immutable State & Error Handling:** Generic error messages prevent internal stack/path disclosure (CWE-209).
- **#13 Integrity Verification:** SHA-256 baseline drift detection with HMAC signatures.

### AI & Automation Controls (#14–17)
- **#14 Anti-SSRF:** Probers and webhook exporters enforce private IP blocking (127.0.0.1, 10.0.0.0/8, 169.254.169.254) (CWE-918).
- **#15 AST Code Inspection:** Auto-healer and type refactorer operate on AST nodes without dynamic code evaluation (`eval`/`exec` forbidden).
- **#16 Human-in-the-Loop:** Automated remediations require dry-run validation before applying filesystem changes.
- **#17 Anti-DoS Graph Bounding:** Graph execution bounded with `recursion_limit` and step quotas.

## Reporting Vulnerabilities
Open a private security advisory via GitHub Security Advisories or contact `cibi-dev@users.noreply.github.com`.
