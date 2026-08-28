"""
Authenticated Cryptographic Engine (AES-256-GCM + PBKDF2-HMAC-SHA256).
"""

from __future__ import annotations

import hmac
import os
import secrets
import string
from typing import Optional

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


class CryptoError(Exception):
    """Base exception for cryptographic operations."""


class AuthenticationError(CryptoError):
    """Raised when authentication tag verification fails (data tampered or wrong key)."""


class InvalidPayloadError(CryptoError):
    """Raised when encrypted payload structure or magic header is invalid."""


class CryptoEngine:
    """Enterprise AES-256-GCM encryption with PBKDF2 key derivation."""

    MAGIC_HEADER = b"EBO1"  # Encrypted Backup Orchestrator v1
    SALT_SIZE = 32          # 256 bits
    NONCE_SIZE = 12         # 96 bits (standard for AES-GCM)
    KEY_SIZE = 32           # 256 bits for AES-256
    TAG_SIZE = 16           # 128 bits
    DEFAULT_ITERATIONS = 600_000

    @classmethod
    def derive_key(
        cls,
        passphrase: str | bytes,
        salt: bytes,
        iterations: int = DEFAULT_ITERATIONS,
    ) -> bytes:
        """
        Derive a 256-bit symmetric key from passphrase and salt using PBKDF2-HMAC-SHA256.

        Args:
            passphrase: Secret passphrase as string or bytes.
            salt: Cryptographically secure random salt (32 bytes).
            iterations: Number of PBKDF2 iterations (default: 600,000).

        Returns:
            32-byte derived AES key.
        """
        if isinstance(passphrase, str):
            passphrase_bytes = passphrase.encode("utf-8")
        else:
            passphrase_bytes = passphrase

        if len(salt) < 16:
            raise ValueError("Salt must be at least 16 bytes for security")

        if iterations < 1000:
            raise ValueError("Iterations must be at least 1000")

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=cls.KEY_SIZE,
            salt=salt,
            iterations=iterations,
        )
        return kdf.derive(passphrase_bytes)

    @classmethod
    def encrypt(
        cls,
        data: bytes,
        passphrase: str | bytes,
        aad: Optional[bytes] = None,
        iterations: int = DEFAULT_ITERATIONS,
        salt: Optional[bytes] = None,
        nonce: Optional[bytes] = None,
    ) -> bytes:
        """
        Encrypt data using AES-256-GCM with PBKDF2-derived key and unique nonce.

        Args:
            data: Raw plaintext bytes.
            passphrase: Encryption passphrase.
            aad: Optional additional authenticated data.
            iterations: PBKDF2 iteration count.
            salt: Optional explicit salt (for testing; defaults to os.urandom(32)).
            nonce: Optional explicit nonce (for testing; defaults to os.urandom(12)).

        Returns:
            Formatted encrypted payload: MAGIC (4B) + SALT (32B) + NONCE (12B) + CIPHERTEXT+TAG.
        """
        if salt is None:
            salt = os.urandom(cls.SALT_SIZE)
        elif len(salt) != cls.SALT_SIZE:
            raise ValueError(f"Salt must be {cls.SALT_SIZE} bytes")

        if nonce is None:
            nonce = os.urandom(cls.NONCE_SIZE)
        elif len(nonce) != cls.NONCE_SIZE:
            raise ValueError(f"Nonce must be {cls.NONCE_SIZE} bytes")

        key = cls.derive_key(passphrase, salt, iterations=iterations)
        aesgcm = AESGCM(key)

        try:
            ciphertext_and_tag = aesgcm.encrypt(nonce, data, associated_data=aad)
        except Exception as exc:
            raise CryptoError(f"Encryption failed: {exc}") from exc

        return cls.MAGIC_HEADER + salt + nonce + ciphertext_and_tag

    @classmethod
    def decrypt(
        cls,
        payload: bytes,
        passphrase: str | bytes,
        aad: Optional[bytes] = None,
        iterations: int = DEFAULT_ITERATIONS,
    ) -> bytes:
        """
        Decrypt and verify AES-256-GCM payload.

        Args:
            payload: Encrypted bytes with standard EBO1 header.
            passphrase: Decryption passphrase.
            aad: Optional additional authenticated data matching encryption.
            iterations: PBKDF2 iteration count.

        Returns:
            Decrypted plaintext bytes.
        """
        min_len = len(cls.MAGIC_HEADER) + cls.SALT_SIZE + cls.NONCE_SIZE + cls.TAG_SIZE
        if len(payload) < min_len:
            raise InvalidPayloadError(
                f"Payload too short: expected at least {min_len} bytes, got {len(payload)}"
            )

        magic = payload[: len(cls.MAGIC_HEADER)]
        if not hmac.compare_digest(magic, cls.MAGIC_HEADER):
            raise InvalidPayloadError("Invalid magic header: not an EBO1 encrypted payload")

        offset = len(cls.MAGIC_HEADER)
        salt = payload[offset : offset + cls.SALT_SIZE]
        offset += cls.SALT_SIZE
        nonce = payload[offset : offset + cls.NONCE_SIZE]
        offset += cls.NONCE_SIZE
        ciphertext_and_tag = payload[offset:]

        key = cls.derive_key(passphrase, salt, iterations=iterations)
        aesgcm = AESGCM(key)

        try:
            plaintext = aesgcm.decrypt(nonce, ciphertext_and_tag, associated_data=aad)
        except InvalidTag as exc:
            raise AuthenticationError(
                "Authentication failed: invalid passphrase, corrupted data, or AAD mismatch"
            ) from exc
        except Exception as exc:
            raise CryptoError(f"Decryption error: {exc}") from exc

        return plaintext

    @classmethod
    def secure_compare_hashes(cls, hash1: str | bytes, hash2: str | bytes) -> bool:
        """
        Compare two hashes in constant time to prevent timing attacks (CWE-208).

        Args:
            hash1: First hash digest.
            hash2: Second hash digest.

        Returns:
            True if identical, False otherwise.
        """
        h1 = hash1.encode("utf-8") if isinstance(hash1, str) else hash1
        h2 = hash2.encode("utf-8") if isinstance(hash2, str) else hash2
        return hmac.compare_digest(h1, h2)

    @classmethod
    def generate_secure_passphrase(cls, length: int = 32) -> str:
        """
        Generate a cryptographically secure random passphrase (CWE-330).

        Args:
            length: Length of passphrase (min 16).

        Returns:
            High-entropy alphanumeric + symbol passphrase string.
        """
        if length < 16:
            length = 16
        alphabet = string.ascii_letters + string.digits + "!@#$%^&*()-_=+"
        return "".join(secrets.choice(alphabet) for _ in range(length))
