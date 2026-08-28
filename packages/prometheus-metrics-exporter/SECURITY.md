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
| **Zero Hardcoded Secrets** | CWE-798 | Verified via `gitleaks detect` in CI pipeline. No plain secrets stored in code or config. |
| **Resource Quotas & Anti-DoS** | CWE-400 | Strict request body payload limit (<10 MB, returns HTTP 413), connection timeouts, and bounded buffer streams. |
| **Safe Deserialization** | CWE-502 / CWE-20 | Alert rules parsed strictly using `yaml.safe_load()` and validated via Pydantic v2 schemas (<1 MB file limit). |
| **Information Exposure in Logs** | CWE-209 | Sensitive tokens, passwords, and API keys in Webhook URLs and HTTP headers masked as `[REDACTED]`. |
| **Path Traversal Defense** | CWE-22 | Proc and config file paths sanitized against directory traversal attacks. |
| **Static Code Analysis** | Bandit (`-r . -ll`) | Continuous verification in CI pipeline with 0 high/medium severity findings. |
| **Dependency Vulnerability Audit** | SLSA / `pip-audit --strict` | Automated verification of third-party package dependencies. |
| **Supply Chain Integrity** | CycloneDX SBOM | Automated generation of `sbom.json` adhering to CycloneDX specification. |

---

## Supported Versions

| Version | Supported |
|---|:---:|
| Latest release (`main`) | ✅ |
| Prior versions | ❌ |
