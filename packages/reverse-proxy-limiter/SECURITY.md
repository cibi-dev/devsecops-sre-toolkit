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
| DoS & Resource Quotas | CWE-400 (Max 10MB Content-Length, Concurrency Semaphores, Async Timeouts) | Pytest suite (`test_security.py`) |
| Credential & Log Sanitization | CWE-209 (`[REDACTED]` for Auth/Bearer/X-API-Key/Cookies) | Unit tests & regex sanitization |
| Cryptographically Secure Entropy | CWE-330 (`secrets.token_hex`, `secrets.token_urlsafe`, no `random`) | Pytest suite (`test_security.py`) |
| Constant-Time Comparisons | CWE-208 (`hmac.compare_digest` for API key validation) | Unit tests |
| Security Headers Injection | OWASP Top 10 (HSTS, CSP, X-Frame-Options, X-Content-Type-Options) | Unit tests (`test_server.py`) |
| Safe Deserialization & Config | CWE-502 (Pydantic v2 `extra='forbid'`, no `pickle`/`eval`) | Bandit SAST & schema validation |
| Zero Hardcoded Secrets | CWE-798 | Gitleaks in CI (`0 leaks`) |
| Static Application Security Testing | Bandit (`-r . -ll`) | 0 findings |
| Dependency Vulnerability Audit | SLSA / `pip-audit --strict` | 0 CVEs |
| Safe Subprocess / Networking | CWE-78 / CWE-400 (Explicit timeouts & pool management) | Code review & Bandit |
| Supply Chain Integrity | CycloneDX SBOM (`sbom.json`) | Attached to release |

---

## Mitigaciones Específicas de Seguridad Implementadas

1. **CWE-400 (Uncontrolled Resource Consumption / Denial of Service):**
   - **Límite Estricto de Payload:** Rechazo inmediato (`HTTP 413 Payload Too Large`) para peticiones con `Content-Length > 10 MB` antes de cualquier procesamiento en memoria.
   - **Semáforos de Concurrencia Acotados:** Límite máximo de peticiones simultáneas (`asyncio.Semaphore`) para proteger el servidor proxy contra saturación de descriptores de socket y memoria.
   - **Timeouts Explícitos:** Todas las peticiones hacia upstreams están envueltas en `asyncio.timeout(timeout)` evitando peticiones colgadas (retornando `504 Gateway Timeout`).
   - **Circuit Breaker:** Aislamiento automático de upstreams caídos para evitar cascading failures y sobrecarga inútil.

2. **CWE-209 (Generation of Error Message Containing Sensitive Information):**
   - **Sanitización de Cabeceras y Logs:** Las cabeceras `Authorization`, `X-API-Key`, `Cookie`, `Set-Cookie`, `api_key` y tokens son reemplazados sistemáticamente por `[REDACTED]` en logs y eventos de métricas.
   - **Respuestas de Error Seguras:** Los fallos internos o de upstream devuelven estructuras JSON estandarizadas sin trazas de pila (tracebacks) ni rutas de archivos internos.

3. **CWE-330 (Use of Insufficiently Random Values) & CWE-208 (Timing Attacks):**
   - Generación de claves API de prueba y tokens de sesión utilizando `secrets.token_hex()` y `secrets.token_urlsafe()`.
   - Comparación de claves y tokens con tiempo constante (`hmac.compare_digest`) para prevenir ataques de temporización por canal lateral.

4. **CWE-502 (Deserialization of Untrusted Data):**
   - Validación y parseo estricto con esquemas Pydantic v2 configurados con `extra='forbid'`, sin deserialización dinámica (`pickle`, `marshal` o `eval`).

5. **Inyección Canónica de Cabeceras de Seguridad (OWASP ASVS):**
   - `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload`
   - `X-Content-Type-Options: nosniff`
   - `X-Frame-Options: DENY`
   - `Content-Security-Policy: default-src 'self'`
   - `Referrer-Policy: strict-origin-when-cross-origin`
   - `Permissions-Policy: geolocation=(), camera=(), microphone=()`

---

## Supported Versions

| Version | Supported |
|---|:---:|
| Latest release (`main`) | ✅ |
| Prior versions | ❌ |
