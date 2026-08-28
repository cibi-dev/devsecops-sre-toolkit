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
| Privilege Separation | CWE-250 & CWE-269 | Scanner runs without root; Remediator strictly verifies `os.geteuid() == 0` |
| Safe Subprocess Invocations | CWE-78 | Parameter lists strictly used with `shell=False` and bounded timeouts |
| Path Traversal Defense | CWE-22 | Strict `os.path.commonpath` verification across backup and restore paths |
| Deterministic Rollback & Backups | CWE-377 / SRE Integrity | Automatic `.bak` backups with timestamp and SHA-256 manifest before mutations |
| Zero Hardcoded Secrets | CWE-798 | Gitleaks in CI with 0 leaks |
| Static Application Security Testing | Bandit (`-r . -ll`) | 0 findings |
| Dependency Vulnerability Audit | SLSA / `pip-audit --strict` | 0 CVEs |
| Safe Deserialization & Config Loading | CWE-502 / CWE-20 | `yaml.safe_load()` + Pydantic v2 strict schemas with size limits (<1 MB) |
| Error Message Sanitization | CWE-209 | Sensitive paths, credentials and system details redacted from output |
| Supply Chain Integrity | CycloneDX SBOM (`sbom.json`) | Attached to release |

---

## Supported Versions

| Version | Supported |
|---|:---:|
| Latest release (`main`) | ✅ |
| Prior versions | ❌ |
