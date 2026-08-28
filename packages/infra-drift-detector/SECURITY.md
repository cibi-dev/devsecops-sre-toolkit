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
| 100% Read-Only Guarantee | CWE-250 / CWE-269 | Dedicated pytest immutability test suite |
| Path Traversal Defense | CWE-22 (`commonpath` & strict path sanitation) | Pytest suite (`test_security.py`) |
| Command Injection Mitigation | CWE-78 (`shell=False`, strict regex whitelist) | Bandit & unit tests |
| Safe Deserialization | CWE-502 (`yaml.safe_load`, Pydantic v2 `extra='forbid'`) | Pytest schema test suite |
| Resource Limit Protection | CWE-400 (Max 1MB manifest size, stream hashing) | Unit tests & parser guardrails |
| Sensitive Data Masking | CWE-209 (`[REDACTED]` tokens, passwords, keys) | Secret redaction filters |
| Constant-Time Crypto Comparisons | CWE-208 (`hmac.compare_digest`) | Unit tests |
| Static Application Security Testing | Bandit (`-r . -ll`) | 0 findings |
| Dependency Vulnerability Audit | SLSA / `pip-audit --strict` | 0 CVEs |
| Supply Chain Integrity | CycloneDX SBOM (`sbom.json`) | Attached to release |

---

## Supported Versions

| Version | Supported |
|---|:---:|
| Latest release (`main`) | ✅ |
| Prior versions | ❌ |
