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
| Path Traversal Defense | CWE-22 (`realpath` + `commonpath`) | Pytest suite & Sandbox checks |
| Static Application Security Testing | Bandit (`-r . -ll`) | 0 findings |
| Dependency Vulnerability Audit | SLSA / `pip-audit --strict` | 0 CVEs |
| Constant-Time Crypto Comparisons | CWE-208 (`hmac.compare_digest`) | Unit tests |
| Secure Cryptographic Hygiene | CWE-321 / CWE-330 (PBKDF2-HMAC-SHA256, 12-byte Nonces) | Crypto test suite |
| Secure Temporary Files & Cleanup | CWE-377 (`tempfile.mkdtemp` + `try/finally` + `atexit`) | Sandbox restore tests |
| Safe Deserialization | CWE-502 (Pydantic v2 strict schemas) | Strict schema validation |
| Supply Chain Integrity | CycloneDX SBOM (`sbom.json`) | Attached to release |

---

## Supported Versions

| Version | Supported |
|---|:---:|
| Latest release (`main`) | ✅ |
| Prior versions | ❌ |
