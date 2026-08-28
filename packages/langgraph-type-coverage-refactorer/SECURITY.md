# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Security Standards Compliance

This project complies with the canonical 17 DevSecOps standards defined in the workspace root `SECURITY.md`:

1. **#1 Canonical .gitignore**: Comprehensive exclusions for secrets, databases, caches, and test artifacts.
2. **#2 Zero Hardcoded Secrets (CWE-798)**: Zero plain text API keys, tokens, or credentials. Automated verification with Gitleaks.
3. **#3 Path Traversal Defense (CWE-22)**: Strict path containment verification using `os.path.commonpath()` and canonical resolution.
4. **#4 SAST & Dependency Auditing**: Bandit SAST scanner with 0 MEDIUM/HIGH findings and strict dependency pinning.
5. **#5 Least Privilege Execution**: Safe file permissions, no elevated privilege requirements.
6. **#6 Archive Security (CWE-409/59)**: Strict quota and sandbox bounds for archive processing if applicable.
7. **#7 Safe Deserialization (CWE-502)**: Pydantic v2 strict models (`extra='forbid'`, `frozen=True`).
8. **#8 Temp File & Concurrency Safety (CWE-377/362)**: Isolated execution sandboxes using `tempfile.TemporaryDirectory()`.
9. **#9 Constant-Time Cryptography (CWE-208)**: Constant-time hash verification and safe entropy sources.
10. **#10 Bounded Concurrency & Timeouts (CWE-400)**: Enforced `asyncio.timeout(30.0)` and subprocess timeout caps.
11. **#11 Privilege Separation (CWE-250)**: Unprivileged execution sandboxing for code evaluation.
12. **#12 Supply Chain Pinning (SLSA L2)**: Strict dependency constraints and automated SBOM generation (CycloneDX).
13. **#13 Secure Error Handling (CWE-209)**: Sanitized logging without exposing internal filesystem leaks or sensitive tokens.
14. **#14 Anti-SSRF Defense (CWE-918)**: Strict network sandboxing and blocking of private/cloud metadata ranges.
15. **#15 Prompt Injection & AST Guardrails (OWASP LLM01 / CWE-20)**: Deterministic AST syntax validation and AST safety analysis before code modification.
16. **#16 Excessive Agency & Human-in-the-Loop (OWASP LLM06 / CWE-250)**: Explicit interactive confirmation required before in-place file modifications.
17. **#17 Bounding Cyclical Graphs & Anti-DoS (OWASP LLM10 / CWE-400)**: Hard recursion limits (`recursion_limit <= 4`) and global execution timeouts in LangGraph cycles.

## Continuous DevSecOps Gate

```bash
pytest -v --cov --cov-fail-under=90 && bandit -r . -ll && gitleaks detect --no-git --source . -v && cyclonedx-py environment -o sbom.json
```

## Reporting a Vulnerability

Please report security issues directly to security@example.local or open a private advisory.
