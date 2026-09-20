"""Protect and recover a document key for one recipient.

The sender creates a fresh ephemeral P-256 key pair. ECDH and
HKDF-SHA-256 derive an AES-128-GCM key-wrapping key.

The key-wrapping key protects Kdoc before the wrapped key is stored
on the untrusted server.
"""

from __future__ import annotations

from dataclasses import dataclass
import os

from crypto.ecc import Point
from crypto.ecdh import (
    generate_keypair,
    is_valid_public_key,
    shared_secret_bytes,
)
from crypto.gcm import (
    AuthenticationError,
    GCMProtectedData,
    decrypt_gcm,
    encrypt_gcm,
)
from crypto.hkdf import derive_wrapping_key


DOCUMENT_KEY_SIZE = 16
WRAPPING_SALT_SIZE = 16


# ============================================================
# Stored Wrapped-Key Object
# ============================================================

@dataclass(frozen=True)
class WrappedDocumentKey:
    """
    Information needed by the recipient to recover Kdoc.

    These values are public and may be stored on the server.
    The document key itself remains encrypted.
    """

    ephemeral_public_key: Point
    salt: bytes
    nonce: bytes
    encrypted_key: bytes
    tag: bytes


# ============================================================
# Validation and Encoding
# ============================================================

def _require_string(name: str, value: str) -> None:
    """Require a non-empty string."""

    if not isinstance(value, str):
        raise TypeError(f"{name} must be a string")

    if len(value) == 0:
        raise ValueError(f"{name} must not be empty")


def _encode_field(value: bytes) -> bytes:
    """Encode one bytes field using a four-byte length prefix."""

    return len(value).to_bytes(4, byteorder="big") + value


def encode_public_key(public_key: Point) -> bytes:
    """
    Encode a P-256 public key using the uncompressed format:

        0x04 || x || y

    Each coordinate is stored as exactly 32 bytes.
    """

    if not is_valid_public_key(public_key):
        raise ValueError("invalid P-256 public key")

    x, y = public_key

    return (
        b"\x04"
        + x.to_bytes(32, byteorder="big")
        + y.to_bytes(32, byteorder="big")
    )


def build_key_wrap_context(
    sender_id: str,
    recipient_id: str,
    document_id: str,
    version: int,
    ephemeral_public_key: Point,
) -> bytes:
    """
    Create the exact context authenticated during key wrapping.

    It binds the wrapped Kdoc to:
        - the sender
        - the recipient
        - the document
        - the document version
        - the ephemeral ECDH public key
    """

    _require_string("sender ID", sender_id)
    _require_string("recipient ID", recipient_id)
    _require_string("document ID", document_id)

    if not isinstance(version, int) or isinstance(version, bool):
        raise TypeError("version must be an integer")

    if version < 1:
        raise ValueError("version must be at least 1")

    return (
        b"SecureVault-KeyWrap-Context-v1"
        + _encode_field(sender_id.encode("utf-8"))
        + _encode_field(recipient_id.encode("utf-8"))
        + _encode_field(document_id.encode("utf-8"))
        + version.to_bytes(8, byteorder="big")
        + _encode_field(encode_public_key(ephemeral_public_key))
    )


# ============================================================
# Wrap Kdoc
# ============================================================

def wrap_document_key(
    document_key: bytes,
    recipient_public_key: Point,
    sender_id: str,
    recipient_id: str,
    document_id: str,
    version: int,
) -> WrappedDocumentKey:
    """
    Protect Kdoc for one recipient.

    A fresh ephemeral ECDH key pair is generated for every wrapping
    operation. The ephemeral private key is used only inside this
    function and is not returned or stored.
    """

    if not isinstance(document_key, bytes):
        raise TypeError("document key must be bytes")

    if len(document_key) != DOCUMENT_KEY_SIZE:
        raise ValueError("document key must be exactly 16 bytes")

    if not is_valid_public_key(recipient_public_key):
        raise ValueError("recipient public key is invalid")

    # Generate a new temporary ECDH key pair for this recipient.
    ephemeral_private_key, ephemeral_public_key = generate_keypair()

    # Calculate the 32-byte ECDH shared secret.
    shared_secret = shared_secret_bytes(
        ephemeral_private_key,
        recipient_public_key,
    )

    # The salt is public and is stored with the wrapped key.
    salt = os.urandom(WRAPPING_SALT_SIZE)

    # Bind the wrapping operation to its intended users and document.
    context = build_key_wrap_context(
        sender_id,
        recipient_id,
        document_id,
        version,
        ephemeral_public_key,
    )

    # Derive a separate 16-byte AES-GCM key-wrapping key.
    wrapping_key = derive_wrapping_key(
        shared_secret,
        salt,
        context,
    )

    # Encrypt Kdoc. The context is authenticated as GCM AAD.
    protected = encrypt_gcm(
        plaintext=document_key,
        aad=context,
        key=wrapping_key,
    )

    return WrappedDocumentKey(
        ephemeral_public_key=ephemeral_public_key,
        salt=salt,
        nonce=protected.nonce,
        encrypted_key=protected.ciphertext,
        tag=protected.tag,
    )


# ============================================================
# Unwrap Kdoc
# ============================================================

def unwrap_document_key(
    wrapped_key: WrappedDocumentKey,
    recipient_private_key: int,
    sender_id: str,
    recipient_id: str,
    document_id: str,
    version: int,
) -> bytes:
    """
    Recover Kdoc using the recipient's private ECDH key.

    AES-GCM verifies the wrapped key and its context before returning
    the plaintext document key.
    """

    if not isinstance(wrapped_key, WrappedDocumentKey):
        raise TypeError("wrapped_key must be WrappedDocumentKey")

    if not is_valid_public_key(wrapped_key.ephemeral_public_key):
        raise AuthenticationError("Key verification failed")

    if (
        not isinstance(wrapped_key.salt, bytes)
        or len(wrapped_key.salt) != WRAPPING_SALT_SIZE
    ):
        raise AuthenticationError("Key verification failed")

    # The recipient obtains the same ECDH shared secret using their
    # private key and the sender's ephemeral public key.
    shared_secret = shared_secret_bytes(
        recipient_private_key,
        wrapped_key.ephemeral_public_key,
    )

    # Rebuild exactly the same authenticated context.
    context = build_key_wrap_context(
        sender_id,
        recipient_id,
        document_id,
        version,
        wrapped_key.ephemeral_public_key,
    )

    # Derive the same AES-GCM wrapping key.
    wrapping_key = derive_wrapping_key(
        shared_secret,
        wrapped_key.salt,
        context,
    )

    protected = GCMProtectedData(
        nonce=wrapped_key.nonce,
        ciphertext=wrapped_key.encrypted_key,
        tag=wrapped_key.tag,
    )

    # decrypt_gcm verifies the tag before returning Kdoc.
    document_key = decrypt_gcm(
        protected,
        context,
        wrapping_key,
    )

    if len(document_key) != DOCUMENT_KEY_SIZE:
        raise AuthenticationError("Key verification failed")

    return document_key