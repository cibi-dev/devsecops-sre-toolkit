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

| Security Control | Reference / Standard | Verification & Mitigation |
|---|---|---|
| **Zero Hardcoded Secrets** | CWE-798 | Verified via `gitleaks detect` in CI pipeline. Zero plain secrets stored in code or configuration. |
| **Resource Quotas & Anti-DoS** | CWE-400 | Typed numpy/pandas vector arrays, strictly bounded dataframe memory chunks (`max_memory_mb`), finite float assertions. |
| **Safe Deserialization & Input Parsing** | CWE-502 / CWE-20 | SLO specifications and metrics payloads validated strictly using Pydantic v2 schemas; unvalidated pickles/evals prohibited. |
| **Information Exposure in Logs / Output** | CWE-209 | Sensitive tokens, passwords, API keys, and internal service credentials in outputs automatically masked as `[REDACTED]`. |
| **Path Traversal Defense** | CWE-22 | Config and dataset file paths sanitized against directory traversal attacks (`os.path.realpath`, bounded resolution). |
| **Static Code Analysis** | Bandit (`-r . -ll`) | Continuous verification in CI pipeline with 0 high/medium severity findings. |
| **Dependency Vulnerability Audit** | SLSA / `pip-audit --strict` | Automated verification of third-party package dependencies. |
| **Supply Chain Integrity** | CycloneDX SBOM | Automated generation of `sbom.json` adhering to CycloneDX specification. |

---

## Supported Versions

| Version | Supported |
|---|:---:|
| Latest release (`main`) | ✅ |
| Prior versions | ❌ |
