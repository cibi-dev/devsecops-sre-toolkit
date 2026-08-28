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

This project adheres to the strict **DevSecOps & Multi-Agent Security Standard (17 Standards)**:

| Security Control | Reference / Standard | Verification |
|---|---|:---:|
| Zero Hardcoded Secrets | CWE-798 | Gitleaks in CI & AST verification |
| AST Guardrails & Deterministic Patching | OWASP LLM01 / CWE-20 | AST verification before applying code patches |
| Graph Bounding & Recursion Limit | OWASP LLM10 / CWE-400 | Hard `recursion_limit <= 4` and max iterations bounded |
| Process Sandboxing & Timeouts | CWE-400 / CWE-78 | `asyncio.timeout(30.0)` and `shell=False` execution |
| Immutable State Models | CWE-20 / CWE-502 | Pydantic v2 `extra='forbid'`, `frozen=True` |
| Safe Deserialization & File I/O | CWE-502 / CWE-22 | `yaml.safe_load`, `json.loads`, `os.path.commonpath` checks |
| Static Application Security Testing | Bandit (`-r . -ll`) | 0 medium/high findings |
| Dependency Vulnerability Audit | SLSA / `pip-audit --strict` | 0 known CVEs |
| Human-in-the-Loop Safeguards | OWASP LLM06 | Dry-run flag and verification before writing to disk |
| Supply Chain Integrity | CycloneDX SBOM (`sbom.json`) | Attached to release artifacts |

---

## Threat Model & Mitigations

### 1. OWASP LLM01 / CWE-20 (Malicious or Broken Patch Injection)
- **Threat:** Automated patching engine generating syntactically invalid Python code or injecting malicious system commands (`os.system`, `rm -rf`, eval).
- **Mitigation:** Strict Abstract Syntax Tree (AST) validation (`ast.parse()`) prior to accepting or proposing any patch. Blacklist of dangerous tokens and AST node validation.

### 2. OWASP LLM10 / CWE-400 (Infinite Cyclic Graph Loops & Resource Exhaustion)
- **Threat:** Self-healing agent looping indefinitely when attempting to fix unsolvable findings, consuming excessive memory and CPU.
- **Mitigation:** Mandatory iteration bounding (`max_iterations <= 3`), LangGraph `recursion_limit = 4`, and `asyncio.timeout(30.0)` across all execution nodes.

### 3. CWE-78 (OS Command Injection Defense)
- **Threat:** Running sub-commands (e.g. bandit or pytest) with unsafe shell interpolation.
- **Mitigation:** Direct programmatic execution via Bandit's Python API or `subprocess.run` with list arguments (`shell=False`).

### 4. CWE-502 (Insecure Deserialization Defense)
- **Threat:** Parsing untrusted report files with unsafe serializers.
- **Mitigation:** Enforcing JSON only, `yaml.safe_load`, and Pydantic v2 immutable schemas with forbidden extra attributes.

---

## Supported Versions

| Version | Supported |
|---|:---:|
| Latest release (`main` / `0.1.x`) | ✅ |
| Prior versions | ❌ |
