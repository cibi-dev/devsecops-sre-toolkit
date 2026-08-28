"""Tests for Authenticated Cryptographic Engine (AES-256-GCM + PBKDF2)."""

import os
import pytest

from backup.crypto import (
    CryptoEngine,
    AuthenticationError,
    InvalidPayloadError,
    CryptoError,
)


def test_crypto_roundtrip():
    """Test encryption and decryption roundtrip."""
    passphrase = "UltraSecureMasterPassphrase#2026!"
    plaintext = b"Sensitive Enterprise Disaster Recovery Backup Data 12345"
    iterations = 2000  # Fast iteration for unit tests

    encrypted = CryptoEngine.encrypt(plaintext, passphrase=passphrase, iterations=iterations)
    assert encrypted.startswith(CryptoEngine.MAGIC_HEADER)
    assert len(encrypted) > len(plaintext) + 48

    decrypted = CryptoEngine.decrypt(encrypted, passphrase=passphrase, iterations=iterations)
    assert decrypted == plaintext


def test_crypto_bytes_passphrase():
    """Test using bytes for passphrase in encryption and decryption."""
    passphrase_bytes = b"RawBytesPassphrase123"
    plaintext = b"Testing bytes passphrase support"
    iterations = 2000

    encrypted = CryptoEngine.encrypt(plaintext, passphrase=passphrase_bytes, iterations=iterations)
    decrypted = CryptoEngine.decrypt(encrypted, passphrase=passphrase_bytes, iterations=iterations)
    assert decrypted == plaintext


def test_crypto_custom_salt_and_nonce():
    """Test passing custom salt and nonce to encrypt."""
    passphrase = "CustomSaltNoncePass"
    plaintext = b"Custom params test"
    salt = os.urandom(32)
    nonce = os.urandom(12)
    iterations = 2000

    encrypted = CryptoEngine.encrypt(
        plaintext,
        passphrase=passphrase,
        iterations=iterations,
        salt=salt,
        nonce=nonce,
    )
    assert encrypted[4:36] == salt
    assert encrypted[36:48] == nonce

    # Invalid salt/nonce length
    with pytest.raises(ValueError, match="Salt must be 32 bytes"):
        CryptoEngine.encrypt(plaintext, passphrase=passphrase, salt=b"too_short")

    with pytest.raises(ValueError, match="Nonce must be 12 bytes"):
        CryptoEngine.encrypt(plaintext, passphrase=passphrase, nonce=b"bad_nonce")


def test_crypto_wrong_passphrase():
    """Test that wrong passphrase triggers AuthenticationError."""
    passphrase = "CorrectPassword123"
    wrong_pass = "WrongPassword456"
    plaintext = b"Confidential Payload"
    iterations = 2000

    encrypted = CryptoEngine.encrypt(plaintext, passphrase=passphrase, iterations=iterations)
    with pytest.raises(AuthenticationError):
        CryptoEngine.decrypt(encrypted, passphrase=wrong_pass, iterations=iterations)


def test_crypto_tampered_ciphertext():
    """Test that modifying ciphertext bits fails authentication tag validation."""
    passphrase = "TamperDetectionPassphrase"
    plaintext = b"Integrity Protected Data"
    iterations = 2000

    encrypted = bytearray(CryptoEngine.encrypt(plaintext, passphrase=passphrase, iterations=iterations))
    # Flip a bit in the ciphertext payload
    encrypted[-1] ^= 0x01

    with pytest.raises(AuthenticationError):
        CryptoEngine.decrypt(bytes(encrypted), passphrase=passphrase, iterations=iterations)


def test_crypto_tampered_nonce_or_salt():
    """Test that tampering with salt or nonce causes AuthenticationError."""
    passphrase = "NonceTamperTest"
    plaintext = b"Sample Protected Payload"
    iterations = 2000

    encrypted = bytearray(CryptoEngine.encrypt(plaintext, passphrase=passphrase, iterations=iterations))
    # Alter byte in nonce region (offset 36 to 48)
    encrypted[40] ^= 0xFF

    with pytest.raises(AuthenticationError):
        CryptoEngine.decrypt(bytes(encrypted), passphrase=passphrase, iterations=iterations)


def test_crypto_invalid_magic_and_short_payload():
    """Test payload validation for magic bytes and minimum length."""
    with pytest.raises(InvalidPayloadError, match="Payload too short"):
        CryptoEngine.decrypt(b"short", passphrase="pass", iterations=1000)

    # Payload with wrong magic header
    fake_payload = b"XXXX" + os.urandom(32) + os.urandom(12) + os.urandom(32)
    with pytest.raises(InvalidPayloadError, match="Invalid magic header"):
        CryptoEngine.decrypt(fake_payload, passphrase="pass", iterations=1000)


def test_crypto_aad_verification():
    """Test Associated Authenticated Data (AAD) binding."""
    passphrase = "AADProtectionPass"
    plaintext = b"Database Dump Chunk 001"
    aad = b"manifest_id:bkp_20260827_01"
    iterations = 2000

    encrypted = CryptoEngine.encrypt(plaintext, passphrase=passphrase, aad=aad, iterations=iterations)
    # Decrypt with matching AAD succeeds
    decrypted = CryptoEngine.decrypt(encrypted, passphrase=passphrase, aad=aad, iterations=iterations)
    assert decrypted == plaintext

    # Decrypt with mismatched AAD fails
    with pytest.raises(AuthenticationError):
        CryptoEngine.decrypt(encrypted, passphrase=passphrase, aad=b"wrong_aad", iterations=iterations)

    # Decrypt without AAD when AAD was present fails
    with pytest.raises(AuthenticationError):
        CryptoEngine.decrypt(encrypted, passphrase=passphrase, aad=None, iterations=iterations)


def test_crypto_pbkdf2_key_derivation():
    """Test deterministic key derivation from passphrase and salt."""
    salt = os.urandom(32)
    key1 = CryptoEngine.derive_key("MyPassphrase", salt=salt, iterations=2000)
    key2 = CryptoEngine.derive_key("MyPassphrase", salt=salt, iterations=2000)
    assert key1 == key2
    assert len(key1) == 32

    # Different salt produces different key
    diff_salt = os.urandom(32)
    key3 = CryptoEngine.derive_key("MyPassphrase", salt=diff_salt, iterations=2000)
    assert key1 != key3

    # Validation errors
    with pytest.raises(ValueError, match="Salt must be at least 16 bytes"):
        CryptoEngine.derive_key("pass", salt=b"short_salt")

    with pytest.raises(ValueError, match="Iterations must be at least 1000"):
        CryptoEngine.derive_key("pass", salt=salt, iterations=500)


def test_crypto_secure_compare_hashes():
    """Test constant-time hash comparison helper."""
    h1 = "a1b2c3d4e5f6"
    h2 = "a1b2c3d4e5f6"
    h3 = "000000000000"

    assert CryptoEngine.secure_compare_hashes(h1, h2) is True
    assert CryptoEngine.secure_compare_hashes(h1, h3) is False
    assert CryptoEngine.secure_compare_hashes(h1.encode(), h2.encode()) is True


def test_crypto_generate_secure_passphrase():
    """Test secure passphrase generator."""
    pass1 = CryptoEngine.generate_secure_passphrase(32)
    pass2 = CryptoEngine.generate_secure_passphrase(32)

    assert len(pass1) == 32
    assert len(pass2) == 32
    assert pass1 != pass2

    # Length clamping
    short_pass = CryptoEngine.generate_secure_passphrase(8)
    assert len(short_pass) >= 16
