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

This project adheres to the strict **cibi-dev DevSecOps & Security Standard** for production-grade Linux systems:

| Security Control | CWE Reference | Verification & Implementation |
|---|---|---|
| **Zero Hardcoded Secrets** | CWE-798 | Verified via Gitleaks in CI and pre-push hooks |
| **Concurrency Locking** | CWE-362 | Exclusive `fcntl.flock` mutex with strict timeout $\le 5\text{s}$ preventing concurrent double deployments |
| **Secure Temporary Files** | CWE-377 | Atomic POSIX `os.replace` via unique temp pointers, `tempfile.mkstemp()` with guaranteed cleanup |
| **Privilege Separation** | CWE-250 | Read-only operations work without root; mutation/switch operations validate `os.geteuid() == 0` |
| **Command Injection Defense** | CWE-78 | Fixed argument arrays via `subprocess.run(shell=False)` with zero raw shell execution |
| **Path Traversal Defense** | CWE-22 | Strict `Path.resolve()` and `os.path.abspath()` validation on configuration and symlink paths |
| **Bounded Resource Limits** | CWE-400 | Bounded HTTP connection timeouts, max retry thresholds, and bounded non-blocking lock polling |
| **Static Security Analysis** | SAST | Bandit (`bandit -r . -ll`) enforced in CI with 0 findings |
| **Supply Chain Integrity** | SLSA | CycloneDX SBOM (`sbom.json`) generated on release, `pip-audit --strict` in CI |

---

## Supported Versions

| Version | Supported |
|---|:---:|
| Latest release (`main`) | ✅ |
| Prior versions | ❌ |
