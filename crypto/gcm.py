"""AES-128-GCM document protection using PyCryptodome.

This is the library-first reference implementation. Metadata must already be
encoded into one unambiguous byte string before it is supplied as AAD.
"""

from __future__ import annotations

# ==============================================================================
# IMPORTS & DEPENDENCIES
# ==============================================================================

from dataclasses import dataclass
import os

from Crypto.Cipher import AES

# ==============================================================================
# PROTOCOL CONSTANTS
# ==============================================================================

AES128_KEY_SIZE = 16
GCM_NONCE_SIZE = 12
GCM_TAG_SIZE = 16
MAX_DOCUMENT_SIZE = 2 * 1024 * 1024 * 1024  # Project limit: 2 GiB

# ==============================================================================
# CUSTOM EXCEPTIONS
# ==============================================================================

class AuthenticationError(Exception):
    """Raised without revealing why document verification failed."""

# ==============================================================================
# DATA STRUCTURES
# ==============================================================================

@dataclass(frozen=True)
class GCMProtectedData:
    nonce: bytes
    ciphertext: bytes
    tag: bytes

# ==============================================================================
# HELPER UTILITIES
# ==============================================================================

def _require_bytes(name: str, value: bytes) -> None:
    """Validate that input fields are strictly byte instances."""
    if not isinstance(value, bytes):
        raise TypeError(f"{name} must be bytes")


def generate_document_key() -> bytes:
    """Generate a fresh random 128-bit AES document key."""
    return os.urandom(AES128_KEY_SIZE)


def generate_nonce() -> bytes:
    """Generate the recommended 96-bit (12-byte) GCM nonce."""
    return os.urandom(GCM_NONCE_SIZE)

# ==============================================================================
# ENCRYPTION & DECISION LOGIC
# ==============================================================================

def encrypt_gcm(
    plaintext: bytes,
    aad: bytes,
    key: bytes,
    *,
    nonce: bytes | None = None,
) -> GCMProtectedData:
    """
    Encrypt and authenticate a document payload using AES-128-GCM.

    Computes counter mode ciphertext alongside a GHASH authentication tag over
    both the ciphertext and Additional Authenticated Data (AAD).
    """
    
    # 1. Input Type and Parameter Validation
    _require_bytes("plaintext", plaintext)
    _require_bytes("aad", aad)
    _require_bytes("key", key)

    if len(key) != AES128_KEY_SIZE:
        raise ValueError("AES-128 key must be exactly 16 bytes")
    if len(plaintext) > MAX_DOCUMENT_SIZE:
        raise ValueError("document exceeds the configured size limit")

    # 2. Nonce Generation / Validation
    if nonce is None:
        nonce = generate_nonce()
    else:
        _require_bytes("nonce", nonce)
        
    if len(nonce) != GCM_NONCE_SIZE:
        raise ValueError("GCM nonce must be exactly 12 bytes")

    # 3. AES-GCM Cipher Initialisation & Processing
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=GCM_TAG_SIZE)
    cipher.update(aad)  # Authenticate AAD header
    
    # Generate CTR ciphertext and GHASH authentication tag
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    
    return GCMProtectedData(nonce=nonce, ciphertext=ciphertext, tag=tag)


def protect_new_document(plaintext: bytes, aad: bytes) -> tuple[GCMProtectedData, bytes]:
    """
    Generate a fresh document key and protect a new upload.

    Returns the protected data structure and the newly generated key.
    """
    key = generate_document_key()
    return encrypt_gcm(plaintext, aad, key), key


def decrypt_gcm(protected: GCMProtectedData, aad: bytes, key: bytes) -> bytes:
    """
    Verify the GCM tag and return plaintext only after successful verification.

    Executes tag verification before releasing decrypted bytes.
    Raises a unified generic AuthenticationError on any tag or format mismatch.
    """
    
    # 1. Field and Structural Checks
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

    # 2. Decryption and GHASH Authentication Check
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
        # Uniform exception masking to prevent side-channel leakage
        raise AuthenticationError("Document verification failed") from exc
