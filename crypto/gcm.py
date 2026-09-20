"""AES-128-GCM document protection using PyCryptodome.

This is the library-first reference implementation.  Metadata must already be
encoded into one unambiguous byte string before it is supplied as AAD.
"""
#AES-128-GCM=AES-CTR encryption+GHASH authentication
from __future__ import annotations

from dataclasses import dataclass
import os

from Crypto.Cipher import AES


AES128_KEY_SIZE = 16
GCM_NONCE_SIZE = 12
GCM_TAG_SIZE = 16
MAX_DOCUMENT_SIZE = 2 * 1024 * 1024 * 1024  # Project limit: 2 GiB


class AuthenticationError(Exception):
    """Raised without revealing why document verification failed."""


@dataclass(frozen=True)
class GCMProtectedData:
    nonce: bytes
    ciphertext: bytes
    tag: bytes


def _require_bytes(name: str, value: bytes) -> None:
    if not isinstance(value, bytes):
        raise TypeError(f"{name} must be bytes")


def generate_document_key() -> bytes:
    """Generate a fresh random AES-128 document key."""
    return os.urandom(AES128_KEY_SIZE)


def generate_nonce() -> bytes:
    """Generate the recommended 96-bit GCM nonce."""
    return os.urandom(GCM_NONCE_SIZE)


def encrypt_gcm(
    plaintext: bytes,
    aad: bytes,
    key: bytes,
    *,
    nonce: bytes | None = None,
) -> GCMProtectedData:
    """Encrypt and authenticate one document.

    Supplying ``nonce`` is useful for official test vectors.  Production code
    should omit it so a fresh nonce is generated.  A nonce must never repeat
    under the same key.
    """
    _require_bytes("plaintext", plaintext)
    _require_bytes("aad", aad)
    _require_bytes("key", key)

    if len(key) != AES128_KEY_SIZE:
        raise ValueError("AES-128 key must be exactly 16 bytes")
    if len(plaintext) > MAX_DOCUMENT_SIZE:
        raise ValueError("document exceeds the configured size limit")

    if nonce is None:
        nonce = generate_nonce()
    else:
        _require_bytes("nonce", nonce)
    if len(nonce) != GCM_NONCE_SIZE:
        raise ValueError("GCM nonce must be exactly 12 bytes")
    #AES-128-GCM object:
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=GCM_TAG_SIZE)
    #Authenticating metadata
    cipher.update(aad)
    #C=GCMEncrypt(Kdoc​,N,P,AAD)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return GCMProtectedData(nonce=nonce, ciphertext=ciphertext, tag=tag)


def protect_new_document(plaintext: bytes, aad: bytes) -> tuple[GCMProtectedData, bytes]:
    """Generate a fresh key and protect a new upload.

    The returned key must be wrapped for each authorized recipient.  It must
    never be stored on the server in plaintext.
    """
    key = generate_document_key()
    return encrypt_gcm(plaintext, aad, key), key


def decrypt_gcm(protected: GCMProtectedData, aad: bytes, key: bytes) -> bytes:
    """Verify the GCM tag and return plaintext only after verification.

    PyCryptodome performs tag verification inside ``decrypt_and_verify``.
    Callers receive the same generic exception for every authentication
    failure and should display only "Document verification failed".
    """
    if not isinstance(protected, GCMProtectedData):
        raise TypeError("protected must be GCMProtectedData")
    _require_bytes("aad", aad)
    _require_bytes("key", key)

    if len(key) != AES128_KEY_SIZE:
        raise ValueError("AES-128 key must be exactly 16 bytes")
    if len(protected.nonce) != GCM_NONCE_SIZE or len(protected.tag) != GCM_TAG_SIZE:
        raise AuthenticationError("Document verification failed")
    if len(protected.ciphertext) > MAX_DOCUMENT_SIZE:
        raise AuthenticationError("Document verification failed")

    try:
        cipher = AES.new(
            key,
            AES.MODE_GCM,
            nonce=protected.nonce,
            mac_len=GCM_TAG_SIZE,
        )
        cipher.update(aad)
        return cipher.decrypt_and_verify(protected.ciphertext, protected.tag)
    except (ValueError, KeyError, TypeError) as exc:
        raise AuthenticationError("Document verification failed") from exc
