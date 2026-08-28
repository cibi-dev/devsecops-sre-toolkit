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

| Security Control | Reference / Standard | Mitigation in `chaos-fault-injector` | Verification |
|---|---|---|:---:|
| Zero Hardcoded Secrets | CWE-798 | No credentials, tokens, or private paths hardcoded; synthetic tokens in tests. | Gitleaks in CI (`0 leaks`) |
| Least Privilege & Privilege Verification | CWE-250 / CWE-269 | Explicit `os.geteuid() == 0` check for real mutating operations (`tc`, process signals). Non-root users safely run `--dry-run` or non-mutating reports. | Unit tests & static review |
| Protected System Whitelist | CWE-250 / CWE-20 | Strictly forbidden to terminate PID 1, `sshd`, `init`, `dbus`, `systemd`, or affect `lo` (loopback) interface. | Unit tests & validation guards |
| Dead-Man Switch & Atomic Rollback | CWE-377 / CWE-362 | Guaranteed auto-stop timer (≤30s), LIFO atomic rollback stack, lockfiles via `fcntl.flock` (≤5s timeout), guaranteed cleanup in `atexit` & signal handlers (`SIGINT`, `SIGTERM`, `SIGHUP`). | Unit tests & benchmark verification |
| Safe Subprocess & Command Execution | CWE-78 | Zero shell invocations (`shell=False` mandatory). Strictly validated command argument vectors for `tc/netem`. | Code review & Bandit (`-ll`) |
| Controlled Resource Limits | CWE-400 | CPU stress bounded by CPU count and duty-cycle sleep intervals with hard maximum timeout (≤30s). | Unit tests & stress control |
| Controlled Deserialization & Schemas | CWE-502 / CWE-20 | Pydantic v2 strict models (`extra='forbid'`) with bounded validation and typing. | Unit tests |
| Static Application Security Testing | Bandit | SAST scanning across codebase with zero findings allowed | `bandit -r src/ -ll` |
| Dependency Vulnerability Audit | SLSA / Supply Chain | Pinned dependency upper bounds and strict CVE scanning | `pip-audit --strict` |
| Supply Chain Integrity | CycloneDX SBOM | Automated `sbom.json` generation in CI pipeline | GitHub Actions |

---

## Supported Versions

| Version | Supported |
|---|:---:|
| Latest release (`main`) | ✅ |
| Prior versions | ❌ |
