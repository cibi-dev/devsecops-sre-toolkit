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
|---|---|:---:|
| Zero Hardcoded Secrets | CWE-798 | Gitleaks scan in CI / Pre-push hook |
| Evidence Sanitization | CWE-209 / CWE-532 | Redaction of API tokens, Bearer headers, JWTs, private keys, and PII to `[REDACTED]` |
| Parameterized SQL Queries | CWE-89 | SQLite interactions use 100% parameterized queries (`?`, `?`) |
| Read-Only Evidence Collection | CWE-250 | Non-destructive, read-only system inspection without privilege escalation |
| Safe Subprocess Execution | CWE-78 | Execution with `shell=False`, argument list whitelist, and timeouts |
| Static Application Security Testing | Bandit (`-r . -ll`) | 0 findings |
| Dependency Vulnerability Audit | SLSA / `pip-audit --strict` | 0 known CVEs |
| Bounded Memory & Resource Quotas | CWE-400 (Anti-DoS) | Max log line chunking, bounded output caps, and timeout guards |
| Supply Chain Integrity | CycloneDX SBOM (`sbom.json`) | Attached to release and verified via CI |

---

## Threat Model & Invariant Protections

1. **CWE-209 / CWE-532 (Information Exposure Through Log / Post-Mortem Data):**
   - The `EvidenceSanitizer` scans all raw logs, git commits, configuration diffs, and incident details through a deterministic multi-stage regex engine before storage or Markdown report generation.
   - Credentials, private keys (`-----BEGIN PRIVATE KEY-----`), JWTs, and AWS access tokens are masked into `[REDACTED]`.

2. **CWE-89 (Improper Neutralization of Special Elements used in an SQL Command):**
   - Storage uses parameterized queries via Python's native `sqlite3` driver. Dynamic string formatting or concatenation in SQL statements is strictly prohibited.

3. **CWE-78 / CWE-250 (OS Command Injection & Execution with Unnecessary Privileges):**
   - All subprocess calls (e.g., `journalctl`, `git log`, `git diff`) use closed argument lists (`shell=False`), explicit working directories, and timeouts.
   - The collector performs only read-only queries and cannot alter system state, modify system logs, or push git changes.

4. **CWE-400 (Uncontrolled Resource Consumption / ReDoS):**
   - Regular expressions in the sanitizer use bounded, non-backtracking patterns to eliminate catastrophic backtracking risks.
   - Log reading operations enforce maximum line counts and buffer size limits (64KB per line, bounded total capture).

5. **Blameless Culture Invariant:**
   - The `RCAEngine` includes heuristic checks to identify blame-oriented language and encourage constructive, systemic analysis of failure modes.

---

## Supported Versions

| Version | Supported |
|---|:---:|
| Latest release (`main`) | ✅ |
| Prior versions | ❌ |
