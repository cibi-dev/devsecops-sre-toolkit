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
| Path Traversal Defense | CWE-22 (`os.path.commonpath` / `resolve()`) | Pytest test suite |
| Static Application Security Testing | Bandit (`-r . -ll`) | 0 findings |
| Dependency Vulnerability Audit | SLSA / `pip-audit --strict` | 0 CVEs |
| Safe Subprocess Execution | CWE-78 (`shell=False`, argument list) | Code review & Bandit |
| Constant-Time Crypto Comparisons | CWE-208 (`hmac.compare_digest`) | Unit tests |
| Bounded Memory & Resource Quotas | CWE-400 (Anti-DoS: max event size 64KB, max batch 10MB, bounded queues) | Timeout & Stream limits |
| Safe Deserialization | CWE-502 (Strict JSON parsing & Pydantic v2 validation) | Strict schema validation |
| PII & Credentials Redaction | CWE-209 (Private IPs, Bearer tokens, passwords, emails redacted) | Transformer suite |
| Secure Temporary Files & Buffers | CWE-377 (`tempfile` with strict permissions 0o600/0o700) | Buffer test suite |
| Supply Chain Integrity | CycloneDX SBOM (`sbom.json`) | Attached to release |

---

## Supported Versions

| Version | Supported |
|---|:---:|
| Latest release (`main`) | ✅ |
| Prior versions | ❌ |
