"""Tests for TLS/SSL Certificate inspection and expiration alerting probe."""

import asyncio
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from prober.probes.ssl_cert import (
    SSLCertProbe,
    SSLCertProbeResult,
    determine_alert_level,
    extract_dn_dict,
    parse_ssl_date,
)


def test_determine_alert_level():
    """Verify exact alert levels for 30/15/7 days and expired thresholds."""
    assert determine_alert_level(-1.0) == "EXPIRED"
    assert determine_alert_level(0.0) == "EMERGENCY_7D"
    assert determine_alert_level(5.0) == "EMERGENCY_7D"
    assert determine_alert_level(7.0) == "EMERGENCY_7D"
    assert determine_alert_level(10.0) == "CRITICAL_15D"
    assert determine_alert_level(15.0) == "CRITICAL_15D"
    assert determine_alert_level(20.0) == "WARNING_30D"
    assert determine_alert_level(30.0) == "WARNING_30D"
    assert determine_alert_level(31.0) == "OK"
    assert determine_alert_level(90.0) == "OK"


def test_parse_ssl_date():
    """Test parsing various ASN.1 / OpenSSL certificate date strings."""
    dt1 = parse_ssl_date("May 10 12:00:00 2026 GMT")
    assert dt1 is not None
    assert dt1.year == 2026
    assert dt1.month == 5
    assert dt1.day == 10
    assert dt1.hour == 12

    # Double-spaced single-digit day
    dt2 = parse_ssl_date("Aug  8 23:59:59 2026 GMT")
    assert dt2 is not None
    assert dt2.year == 2026
    assert dt2.month == 8
    assert dt2.day == 8

    # Invalid date string
    assert parse_ssl_date("invalid-date-string") is None


def test_extract_dn_dict():
    """Test conversion of OpenSSL DN tuples to dictionary."""
    dn_tuple = (
        (("countryName", "US"),),
        (("organizationName", "Example Corp"),),
        (("commonName", "example.com"),),
    )
    res = extract_dn_dict(dn_tuple)
    assert res.get("countryName") == "US"
    assert res.get("organizationName") == "Example Corp"
    assert res.get("commonName") == "example.com"
    assert extract_dn_dict(None) == {}


@pytest.mark.asyncio
async def test_ssl_probe_mock_cert_success():
    """Test SSL certificate probe with mock SSL stream object."""
    mock_writer = MagicMock()
    mock_ssl_obj = MagicMock()

    future_date = datetime.now(timezone.utc) + timedelta(days=45)
    not_after_str = future_date.strftime("%b %d %H:%M:%S %Y GMT")
    not_before_str = (future_date - timedelta(days=90)).strftime("%b %d %H:%M:%S %Y GMT")

    mock_ssl_obj.getpeercert.return_value = {
        "issuer": ((("commonName", "DigiCert Global Root CA"),),),
        "subject": ((("commonName", "api.example.com"),),),
        "subjectAltName": (("DNS", "api.example.com"), ("DNS", "example.com")),
        "serialNumber": "A1B2C3D4E5",
        "notBefore": not_before_str,
        "notAfter": not_after_str,
    }
    mock_ssl_obj.version.return_value = "TLSv1.3"
    mock_ssl_obj.cipher.return_value = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)
    mock_writer.get_extra_info.return_value = mock_ssl_obj
    mock_writer.wait_closed = AsyncMock()

    with patch("asyncio.open_connection", return_value=(MagicMock(), mock_writer)):
        probe = SSLCertProbe(default_timeout=5.0)
        res = await probe.probe(host="api.example.com", port=443)

        assert res.valid is True
        assert res.is_success is True
        assert res.alert_level == "OK"
        assert res.days_until_expiration is not None and res.days_until_expiration > 40
        assert "api.example.com" in res.sans
        assert "example.com" in res.sans
        assert res.issuer.get("commonName") == "DigiCert Global Root CA"
        assert res.tls_version == "TLSv1.3"
        assert res.cipher_suite == "TLS_AES_256_GCM_SHA384"


@pytest.mark.asyncio
async def test_ssl_probe_mock_cert_expiring_soon():
    """Test SSL certificate probe detecting warning tier (<15 days)."""
    mock_writer = MagicMock()
    mock_ssl_obj = MagicMock()

    future_date = datetime.now(timezone.utc) + timedelta(days=12)
    not_after_str = future_date.strftime("%b %d %H:%M:%S %Y GMT")
    not_before_str = (future_date - timedelta(days=90)).strftime("%b %d %H:%M:%S %Y GMT")

    mock_ssl_obj.getpeercert.return_value = {
        "issuer": ((("commonName", "Let's Encrypt Authority X3"),),),
        "subject": ((("commonName", "legacy.example.com"),),),
        "subjectAltName": (("DNS", "legacy.example.com"),),
        "serialNumber": "998877",
        "notBefore": not_before_str,
        "notAfter": not_after_str,
    }
    mock_ssl_obj.version.return_value = "TLSv1.2"
    mock_ssl_obj.cipher.return_value = ("ECDHE-RSA-AES128-GCM-SHA256", "TLSv1.2", 128)
    mock_writer.get_extra_info.return_value = mock_ssl_obj
    mock_writer.wait_closed = AsyncMock()

    with patch("asyncio.open_connection", return_value=(MagicMock(), mock_writer)):
        probe = SSLCertProbe(default_timeout=5.0)
        res = await probe.probe(host="legacy.example.com", port=443)

        assert res.valid is True
        assert res.alert_level == "CRITICAL_15D"
        assert res.days_until_expiration is not None and 11.0 <= res.days_until_expiration <= 13.0


@pytest.mark.asyncio
async def test_ssl_probe_mock_cert_expired():
    """Test SSL certificate probe detecting expired cert."""
    mock_writer = MagicMock()
    mock_ssl_obj = MagicMock()

    past_date = datetime.now(timezone.utc) - timedelta(days=5)
    not_after_str = past_date.strftime("%b %d %H:%M:%S %Y GMT")
    not_before_str = (past_date - timedelta(days=90)).strftime("%b %d %H:%M:%S %Y GMT")

    mock_ssl_obj.getpeercert.return_value = {
        "issuer": ((("commonName", "CA"),),),
        "subject": ((("commonName", "expired.com"),),),
        "notBefore": not_before_str,
        "notAfter": not_after_str,
    }
    mock_ssl_obj.version.return_value = "TLSv1.3"
    mock_ssl_obj.cipher.return_value = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)
    mock_writer.get_extra_info.return_value = mock_ssl_obj
    mock_writer.wait_closed = AsyncMock()

    with patch("asyncio.open_connection", return_value=(MagicMock(), mock_writer)):
        probe = SSLCertProbe(default_timeout=5.0)
        res = await probe.probe(host="expired.com", port=443)

        assert res.valid is False
        assert res.alert_level == "EXPIRED"
        assert res.status == "EXPIRED"


@pytest.mark.asyncio
async def test_ssl_probe_no_ssl_object():
    """Test SSL probe handling writer without ssl_object."""
    mock_writer = MagicMock()
    mock_writer.get_extra_info.return_value = None
    mock_writer.wait_closed = AsyncMock()

    with patch("asyncio.open_connection", return_value=(MagicMock(), mock_writer)):
        probe = SSLCertProbe(default_timeout=5.0)
        res = await probe.probe(host="nossl.local", port=443)
        assert res.status == "ERROR"
        assert "No SSL object found" in str(res.error)


@pytest.mark.asyncio
async def test_ssl_probe_empty_peercert():
    """Test SSL probe handling empty peer certificate in unverified mode."""
    mock_writer = MagicMock()
    mock_ssl_obj = MagicMock()
    mock_ssl_obj.getpeercert.return_value = {}
    mock_ssl_obj.version.return_value = "TLSv1.3"
    mock_ssl_obj.cipher.return_value = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)
    mock_writer.get_extra_info.return_value = mock_ssl_obj
    mock_writer.wait_closed = AsyncMock()

    with patch("asyncio.open_connection", return_value=(MagicMock(), mock_writer)):
        probe = SSLCertProbe(default_timeout=5.0)
        res = await probe.probe(host="unverified.local", port=443, verify_ssl=False)
        assert res.status == "SUCCESS"
        assert res.ssl_verified is False


@pytest.mark.asyncio
async def test_ssl_probe_timeout():
    """Test SSL probe timeout."""
    probe = SSLCertProbe(default_timeout=0.1)
    with patch("asyncio.open_connection", side_effect=TimeoutError()):
        res = await probe.probe(host="unresponsive-host.local", port=443, timeout=0.1)
        assert res.status == "TIMEOUT"
        assert res.valid is False
        assert res.is_success is False


@pytest.mark.asyncio
async def test_ssl_probe_verification_error():
    """Test SSL verification failure error capture (CWE-295)."""
    import ssl
    probe = SSLCertProbe(default_timeout=2.0)
    with patch("asyncio.open_connection", side_effect=ssl.SSLCertVerificationError("Self-signed certificate")):
        res = await probe.probe(host="untrusted.local", port=443, verify_ssl=True)
        assert res.status == "CERT_VERIFICATION_FAILED"
        assert res.valid is False
        assert res.is_success is False
        assert "Self-signed" in str(res.error)


@pytest.mark.asyncio
async def test_ssl_probe_unexpected_error():
    """Test SSL probe handling unexpected runtime exception."""
    probe = SSLCertProbe(default_timeout=2.0)
    with patch("asyncio.open_connection", side_effect=OSError("Network interface down")):
        res = await probe.probe(host="error.local", port=443)
        assert res.status == "ERROR"
        assert "Network interface down" in str(res.error)
