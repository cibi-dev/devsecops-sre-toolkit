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

This project adheres to the strict **cibi-dev DevSecOps & Security Standard** and implements the following CWE mitigations:

| Security Control | Reference / Standard | Mitigation in `linux-sre-watchdog` | Verification |
|---|---|---|:---:|
| Zero Hardcoded Secrets | CWE-798 | No credentials or sensitive paths hardcoded; synthetic tokens in tests | Gitleaks in CI (`0 leaks`) |
| Least Privilege & Reader/Writer Separation | CWE-250 / CWE-269 | 100% read-only procfs collectors without root. Mutating remediation operations check `os.geteuid() == 0` explicitly and cleanly abort otherwise. | Unit tests & static review |
| Safe Temporary Files & File Locks | CWE-377 / CWE-362 | Concurrency state locking via `fcntl.flock` with strict ≤5s timeout. Automatic cleanup guaranteed via `try/finally` and `atexit`. | Unit tests |
| Safe Subprocess & Command Execution | CWE-78 | Zero raw shell commands (`shell=False` required). Strict whitelist of allowed runbook executables and validated arguments. | Code review & Bandit (`-ll`) |
| Structured Log Sanitization | CWE-209 / CWE-22 | JSON-Lines audit logs with automatic regex masking of sensitive tokens, bearer headers, passwords, and private home paths as `[REDACTED]`. | Unit tests |
| Controlled Deserialization & Schemas | CWE-502 / CWE-20 | Pydantic v2 strict models (`extra='forbid'`) with bounded configuration file reading (<1 MB). | Unit tests |
| Static Application Security Testing | Bandit | SAST scanning across codebase with zero findings allowed | `bandit -r src/ -ll` |
| Dependency Vulnerability Audit | SLSA / Supply Chain | Pinned dependency upper bounds and strict CVE scanning | `pip-audit --strict` |
| Supply Chain Integrity | CycloneDX SBOM | Automated `sbom.json` generation in CI pipeline | GitHub Actions |

---

## Supported Versions

| Version | Supported |
|---|:---:|
| Latest release (`main`) | ✅ |
| Prior versions | ❌ |
