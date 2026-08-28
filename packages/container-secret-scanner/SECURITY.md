# Security Policy

## Reporting a Vulnerability

Please report security vulnerabilities **privately** via email to:
**cibi-dev@users.noreply.github.com**

Do NOT open public GitHub issues for security vulnerabilities or secret leaks.

### Response SLA
- **Acknowledgement:** Within 48 hours.
- **Triage & Remediation Plan:** Within 7 business days.
- **Patch Release:** Prioritized based on CVSS severity (HIGH/CRITICAL within 7 days).

---

## Security Hardening Applied

This project adheres to the strict **cibi-dev DevSecOps & Security Standard**:

| Security Control | Reference / Standard | Verification |
|---|---|:---:|
| Zero Hardcoded Secrets | CWE-798 | Gitleaks in CI & AST verification |
| Tar Bomb & Extraction Limits | CWE-409 | 500MB extracted / 10k file limits in `tar_parser.py` |
| Symlink Escape & Path Traversal | CWE-59 / CWE-22 | Stream extraction with `extractfile()` & `commonpath` check |
| Uncontrolled Resource Consumption | CWE-400 | ThreadPool bounded to max 32 workers |
| Information Exposure via Logs | CWE-209 | Redacted secret masking (`[REDACTED]...xxxx`) |
| Command Injection Defense | CWE-78 | `subprocess.run` with list args (`shell=False`) |
| Static Application Security Testing | Bandit (`-r . -ll`) | 0 findings |
| Dependency Vulnerability Audit | SLSA / `pip-audit --strict` | 0 CVEs |
| Strict Input Validation | Pydantic v2 schemas | Typed validation & bounds checking |
| Supply Chain Integrity | CycloneDX SBOM (`sbom.json`) | Attached to release artifacts |

---

## Architecture Threat Model & Mitigations

### 1. CWE-409 (Tar Bomb Defense)
- **Threat:** Malicious container layer tarball with high compression ratio attempting DoS via memory or disk exhaustion.
- **Mitigation:** Safe iterative parsing using `tarfile.extractfile()`. Bounded byte counter halts processing if cumulative size exceeds 500 MB or single file exceeds 100 MB. Max 10,000 members per archive.

### 2. CWE-59 & CWE-22 (Symlink & Path Traversal Defense)
- **Threat:** Tar archives containing entries with `../` path components or symlinks attempting to overwrite system files or escape scan sandbox.
- **Mitigation:** Absolute path elimination, normalization, validation with `os.path.commonpath`, rejection of link extraction to disk; files are analyzed strictly in-memory from stream objects.

### 3. CWE-400 (Worker Pool Quota)
- **Threat:** Unchecked concurrency starving system resources.
- **Mitigation:** Clamping worker threads between 1 and 32 with explicit thread pool lifecycle management.

### 4. CWE-209 (Secret Exposure Sanitization)
- **Threat:** CLI outputs or reports exposing raw credential strings to log aggregators or terminal history.
- **Mitigation:** Strict redaction mask displaying only `[REDACTED]` or trailing 4 characters for verification.

---

## Supported Versions

| Version | Supported |
|---|:---:|
| Latest release (`main` / `0.1.x`) | ✅ |
| Prior versions | ❌ |
