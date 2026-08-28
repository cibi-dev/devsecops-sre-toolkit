"""TLS Certificate Inspection and Expiration Synthetic Probe."""

from __future__ import annotations

import asyncio
import socket
import ssl
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class SSLCertProbeResult(BaseModel):
    """Result model for TLS/SSL Certificate inspection."""

    host: str
    port: int = 443
    valid: bool = False
    issuer: Dict[str, str] = Field(default_factory=dict)
    subject: Dict[str, str] = Field(default_factory=dict)
    sans: List[str] = Field(default_factory=list)
    serial_number: Optional[str] = None
    not_before: Optional[datetime] = None
    not_after: Optional[datetime] = None
    days_until_expiration: Optional[float] = None
    alert_level: str = "OK"  # OK, WARNING_30D, CRITICAL_15D, EMERGENCY_7D, EXPIRED, UNKNOWN
    handshake_latency_ms: float = 0.0
    tls_version: Optional[str] = None
    cipher_suite: Optional[str] = None
    ssl_verified: bool = True
    status: str = "SUCCESS"  # SUCCESS, EXPIRED, CERT_VERIFICATION_FAILED, TIMEOUT, ERROR
    error: Optional[str] = None
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def is_success(self) -> bool:
        """Check if SSL verification succeeded and certificate is valid."""
        return self.valid and self.status == "SUCCESS" and self.alert_level != "EXPIRED"


def parse_ssl_date(date_str: str) -> Optional[datetime]:
    """Parse standard OpenSSL ASN.1 date strings to UTC datetime."""
    # Common formats: "May 10 00:00:00 2026 GMT" or "May  8 23:59:59 2026 GMT"
    formats = [
        "%b %d %H:%M:%S %Y %Z",
        "%b  %d %H:%M:%S %Y %Z",
        "%Y%m%d%H%M%SZ",
        "%b %d %H:%M:%S %Y",
    ]
    # Normalize double spaces
    normalized = " ".join(date_str.split())
    for fmt in formats:
        try:
            dt = datetime.strptime(normalized, fmt)
            return dt.replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def extract_dn_dict(dn_tuple: Any) -> Dict[str, str]:
    """Convert OpenSSL distinguished name tuple to flat dictionary."""
    result: Dict[str, str] = {}
    if not isinstance(dn_tuple, (tuple, list)):
        return result
    for rdn in dn_tuple:
        if isinstance(rdn, (tuple, list)):
            for item in rdn:
                if isinstance(item, (tuple, list)) and len(item) == 2:
                    result[str(item[0])] = str(item[1])
    return result


def determine_alert_level(days_remaining: float) -> str:
    """Classify certificate expiration warning tiers based on days remaining."""
    if days_remaining < 0:
        return "EXPIRED"
    elif days_remaining <= 7.0:
        return "EMERGENCY_7D"
    elif days_remaining <= 15.0:
        return "CRITICAL_15D"
    elif days_remaining <= 30.0:
        return "WARNING_30D"
    return "OK"


class SSLCertProbe:
    """Asynchronous TLS certificate prober inspecting validity, SANs and expiration thresholds."""

    def __init__(self, default_timeout: float = 5.0) -> None:
        self.default_timeout = default_timeout

    async def probe(
        self,
        host: str,
        port: int = 443,
        timeout: Optional[float] = None,
        verify_ssl: bool = True,
    ) -> SSLCertProbeResult:
        """Inspect TLS certificate on remote host:port.

        Args:
            host: Hostname to connect and verify.
            port: Port (default 443).
            timeout: Timeout in seconds (default 5.0).
            verify_ssl: Whether to enforce strict CA validation (CWE-295 standard: True).

        Returns:
            SSLCertProbeResult with full certificate attributes and expiration tier.
        """
        eff_timeout = timeout if timeout is not None else self.default_timeout
        clean_host = host.strip()
        start_time = time.perf_counter()

        ssl_ctx = ssl.create_default_context()
        if not verify_ssl:
            ssl_ctx.check_hostname = False
            ssl_ctx.verify_mode = ssl.CERT_NONE

        writer: Optional[asyncio.StreamWriter] = None

        try:
            async with asyncio.timeout(eff_timeout):
                reader, writer = await asyncio.open_connection(
                    host=clean_host,
                    port=port,
                    ssl=ssl_ctx,
                    server_hostname=clean_host,
                )

            handshake_latency_ms = (time.perf_counter() - start_time) * 1000.0
            ssl_object = writer.get_extra_info("ssl_object")

            if not ssl_object:
                return SSLCertProbeResult(
                    host=clean_host,
                    port=port,
                    valid=False,
                    handshake_latency_ms=round(handshake_latency_ms, 3),
                    status="ERROR",
                    error="No SSL object found on connection",
                )

            peercert = ssl_object.getpeercert()
            tls_version = ssl_object.version()
            cipher_info = ssl_object.cipher()
            cipher_suite = cipher_info[0] if cipher_info else None

            # Gracefully close connection
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

            if not peercert:
                return SSLCertProbeResult(
                    host=clean_host,
                    port=port,
                    valid=True if not verify_ssl else False,
                    handshake_latency_ms=round(handshake_latency_ms, 3),
                    tls_version=tls_version,
                    cipher_suite=cipher_suite,
                    ssl_verified=verify_ssl,
                    status="SUCCESS",
                )

            # Parse Issuer, Subject and SANs
            issuer = extract_dn_dict(peercert.get("issuer", ()))
            subject = extract_dn_dict(peercert.get("subject", ()))
            sans = [san[1] for san in peercert.get("subjectAltName", ()) if len(san) == 2 and san[0] == "DNS"]
            serial_number = str(peercert.get("serialNumber", ""))

            not_before = parse_ssl_date(peercert.get("notBefore", ""))
            not_after = parse_ssl_date(peercert.get("notAfter", ""))

            days_remaining: Optional[float] = None
            alert_level = "OK"

            if not_after is not None:
                now_utc = datetime.now(timezone.utc)
                delta = not_after - now_utc
                days_remaining = round(delta.total_seconds() / 86400.0, 2)
                alert_level = determine_alert_level(days_remaining)

            is_expired = alert_level == "EXPIRED"

            return SSLCertProbeResult(
                host=clean_host,
                port=port,
                valid=not is_expired,
                issuer=issuer,
                subject=subject,
                sans=sans,
                serial_number=serial_number,
                not_before=not_before,
                not_after=not_after,
                days_until_expiration=days_remaining,
                alert_level=alert_level,
                handshake_latency_ms=round(handshake_latency_ms, 3),
                tls_version=tls_version,
                cipher_suite=cipher_suite,
                ssl_verified=verify_ssl,
                status="EXPIRED" if is_expired else "SUCCESS",
                error="Certificate is expired" if is_expired else None,
            )

        except TimeoutError:
            latency_ms = (time.perf_counter() - start_time) * 1000.0
            return SSLCertProbeResult(
                host=clean_host,
                port=port,
                valid=False,
                handshake_latency_ms=round(latency_ms, 3),
                status="TIMEOUT",
                error=f"TLS handshake timed out after {eff_timeout}s",
            )
        except (ssl.SSLCertVerificationError, ssl.SSLError) as e:
            latency_ms = (time.perf_counter() - start_time) * 1000.0
            return SSLCertProbeResult(
                host=clean_host,
                port=port,
                valid=False,
                ssl_verified=verify_ssl,
                handshake_latency_ms=round(latency_ms, 3),
                status="CERT_VERIFICATION_FAILED",
                error=f"TLS certificate verification failed: {e}",
            )
        except Exception as e:
            latency_ms = (time.perf_counter() - start_time) * 1000.0
            return SSLCertProbeResult(
                host=clean_host,
                port=port,
                valid=False,
                handshake_latency_ms=round(latency_ms, 3),
                status="ERROR",
                error=f"TLS probe error: {e}",
            )
        finally:
            if writer is not None:
                try:
                    writer.close()
                except Exception:
                    pass
