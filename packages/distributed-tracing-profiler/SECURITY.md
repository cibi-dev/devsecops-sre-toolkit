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
| Cryptographically Secure IDs | CWE-330 / CWE-208 (`secrets.token_hex`, no `random`) | Pytest suite (`test_security.py`) |
| Sensitive Attribute Redaction | CWE-209 (`[REDACTED]` for Auth/Tokens/PII) | Unit tests & regex sanitization |
| Bounded Memory & Resource Quotas | CWE-400 (Circular Buffer deque maxlen=10,000) | Anti-DoS unit tests |
| Safe Deserialization & No Dynamic Eval | CWE-502 (Safe JSON OTel schemas, no pickle) | Bandit SAST & schema validation |
| Zero Hardcoded Secrets | CWE-798 | Gitleaks in CI (`0 leaks`) |
| Static Application Security Testing | Bandit (`-r . -ll`) | 0 findings |
| Dependency Vulnerability Audit | SLSA / `pip-audit --strict` | 0 CVEs |
| Safe Subprocess Execution | CWE-78 (`shell=False`, argument list) | Code review & Bandit |
| Constant-Time Crypto Comparisons | CWE-208 (`hmac.compare_digest`) | Unit tests |
| Supply Chain Integrity | CycloneDX SBOM (`sbom.json`) | Attached to release |

---

## Mitigaciones Específicas de Seguridad Implementadas

1. **CWE-330 (Use of Insufficiently Random Values) & CWE-208 (Timing Attacks):**
   - Todos los identificadores W3C TraceContext (Trace-ID de 16 bytes y Span-ID de 8 bytes) se generan exclusivamente con `secrets.token_hex()` y validación contra identificadores nulos (`000...000`).
   - Comparaciones criptográficas seguras implementadas con `hmac.compare_digest`.

2. **CWE-209 (Generation of Error Message Containing Sensitive Information):**
   - Sanitización automática y enmascaramiento (`[REDACTED]`) de claves y cabeceras sensibles (`Authorization`, `Bearer`, `Cookie`, `Set-Cookie`, `Token`, `Secret`, `Password`, `API_Key`, `Credit_Card`, `SSN`).
   - Los mensajes de excepción y trazas de error en spans son filtrados antes de ser persistidos o exportados.

3. **CWE-400 (Uncontrolled Resource Consumption / Denial of Service):**
   - El almacenamiento en memoria de spans en `SpanProfiler` está implementado como un buffer circular acotado (`collections.deque(maxlen=10000)`), imposibilitando la saturación de RAM por acumulación de trazas.
   - Cantidad máxima de atributos y eventos acotada rígidamente por span (máximo 128 elementos).

4. **CWE-502 (Deserialization of Untrusted Data):**
   - Todos los exportadores (OpenTelemetry JSON, Jaeger JSON y visualizador ASCII) utilizan serialización JSON estándar sin evaluación dinámica (`eval`), sin llamadas a `pickle`, `marshal` o `shelve`.

---

## Supported Versions

| Version | Supported |
|---|:---:|
| Latest release (`main`) | ✅ |
| Prior versions | ❌ |
