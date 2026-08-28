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
| Zero Hardcoded Secrets | CWE-798 | Gitleaks in CI |
| Path Traversal Defense | CWE-22 (`os.path.commonpath`, strict cwd checks) | Pytest suite |
| Safe Subprocess Execution | CWE-78 (`shell=False`, argument list tokenization via `shlex`) | Code review & Bandit |
| Safe Deserialization | CWE-502 (`yaml.safe_load`, Pydantic v2 validation) | Strict schema validation |
| Bounded Memory & Resource Quotas | CWE-400 (Anti-DoS, file size <1MB, job timeouts) | Pytest suite & Timeouts |
| Sensitive Log Sanitization | CWE-209 / CWE-532 (Secret masking `[REDACTED]`) | Pytest suite |
| Static Application Security Testing | Bandit (`-r . -ll`) | 0 findings |
| Dependency Vulnerability Audit | SLSA / `pip-audit --strict` | 0 CVEs |
| Supply Chain Integrity | CycloneDX SBOM (`sbom.json`) | Attached to release |

---

## Supported Versions

| Version | Supported |
|---|:---:|
| Latest release (`main`) | ✅ |
| Prior versions | ❌ |
