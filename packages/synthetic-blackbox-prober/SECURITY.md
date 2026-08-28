# Security Policy

## Reporting a Vulnerability

Please report security vulnerabilities **privately** via email to:
**cibi-dev@users.noreply.github.com**

Do NOT open public GitHub issues for security vulnerabilities, discovered CVEs, or secret leaks.

### Response SLA
- **Acknowledgement:** Within 48 hours.
- **Triage & Remediation Plan:** Within 7 business days.
- **Patch Release:** Prioritized based on CVSS severity (HIGH/CRITICAL within 7 days).

---

## Security Hardening Applied

This project adheres to the strict **cibi-dev DevSecOps & Security Standard**:

| Security Control | Reference / Standard | Verification |
|---|---|:---:|
| DoS & Resource Quotas | CWE-400 (Async Timeouts, Concurrency Semaphores, Stream Limits) | Pytest suite (`test_security.py`) |
| Credential & Log Sanitization | CWE-209 (`[REDACTED]` for query params, basic auth, bearer tokens, headers) | Unit tests & URL sanitizer |
| Secure TLS Certificate Verification | CWE-295 (Default active CA verification, explicit trust handling) | Pytest suite (`test_security.py`, `test_ssl_probe.py`) |
| Cryptographically Secure Randomness | CWE-330 (`secrets` module for tokens and nonces) | Code review & Bandit SAST |
| Constant-Time Comparisons | CWE-208 (`hmac.compare_digest` for webhook signatures and tokens) | Unit tests |
| Safe Deserialization & Config | CWE-502 (Pydantic v2 validation with strict types, no `pickle`/`eval`) | Bandit SAST & schema validation |
| Zero Hardcoded Secrets | CWE-798 | Gitleaks in CI (`0 leaks`) |
| Static Application Security Testing | Bandit (`-r . -ll`) | 0 findings |
| Dependency Vulnerability Audit | SLSA / `pip-audit --strict` | 0 CVEs |
| Safe Socket & Network I/O | CWE-78 / CWE-400 (Explicit connection timeouts & resource cleanup) | Code review & Bandit |
| Supply Chain Integrity | CycloneDX SBOM (`sbom.json`) | Attached to release |

---

## Mitigaciones Específicas de Seguridad Implementadas

1. **CWE-400 (Uncontrolled Resource Consumption / Denial of Service):**
   - **Timeouts Estrictos en Todas las Sondas:** Todas las operaciones de red (DNS, TCP ping, TLS handshake y HTTP/HTTPS) están delimitadas por `asyncio.timeout` / `asyncio.wait_for` con un valor por defecto de 5-10 segundos. Ninguna conexión puede quedar colgada indefinidamente.
   - **Semáforos de Concurrencia Acotados:** El planificador (`ProbeScheduler`) implementa un `asyncio.Semaphore` (por defecto 50 workers concurrentes) para prevenir el agotamiento de file descriptors (`EMFILE`) o la saturación del loop de eventos durante ráfagas de sondeo masivo.
   - **Límite de Lectura de Payload HTTP:** La sonda HTTP limita la cantidad máxima de bytes descargados (10 MB por defecto) para evitar ataques de DoS por buffers inflados (decompression bombs o streams infinitos).

2. **CWE-295 (Improper Certificate Validation):**
   - **Validación TLS Activa por Defecto:** Las sondas `HTTPProbe` y `SSLCertProbe` utilizan `ssl.create_default_context()` con validación estricta de cadenas de confianza y verificación de hostname (`check_hostname = True`).
   - **Transparencia en Alertas de Certificados:** Se detectan e informan detalladamente anomalías de certificados (autofirmados, revocados, expirados, o cadenas rotas) como estados de error de la sonda, sin desactivar de forma silenciosa la seguridad del transporte.

3. **CWE-209 (Generation of Error Message Containing Sensitive Information):**
   - **Sanitización de URLs y Cabeceras:** Las URLs analizadas son procesadas a través de `sanitize_url()` para enmascarar automáticamente contraseñas de Basic Auth (`https://user:****@host/`) y parámetros sensibles de query string (`token`, `key`, `password`, `secret`, `auth`, `api_key`) sustituyéndolos por `[REDACTED]`.
   - **Enmascaramiento de Cabeceras HTTP:** Cabeceras como `Authorization`, `Proxy-Authorization`, `X-API-Key`, `Cookie` y `Set-Cookie` son filtradas antes de guardarse en los resultados o métricas.

4. **CWE-208 (Observable Timing Discrepancy) & CWE-330 (Insufficient Randomness):**
   - Las firmas de webhooks de notificación HMAC-SHA256 se verifican mediante `hmac.compare_digest` para evitar ataques de canal lateral (timing attacks).
   - Generación de identificadores de sondeo y tokens mediante `secrets.token_hex`.
