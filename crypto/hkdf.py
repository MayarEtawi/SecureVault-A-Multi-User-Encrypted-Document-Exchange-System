"""HKDF-SHA-256 built using our own HMAC-SHA-256 implementation.

HKDF is used to derive a 16-byte AES-GCM key-wrapping key from the
32-byte shared secret produced by P-256 ECDH.

The raw ECDH shared secret must never be used directly as an AES key;
use HKDF.
"""

import struct

from .hmac_sha256 import hmac_sha256


SHA256_DIGEST_SIZE = 32
MAX_OUTPUT_SIZE = 255 * SHA256_DIGEST_SIZE

# P-256 produces a 256-bit x-coordinate.
ECDH_SHARED_SECRET_SIZE = 32

# AES-128-GCM requires a 16-byte key.
WRAPPING_KEY_SIZE = 16

# A fresh public salt is generated for each key-wrapping operation.
# It MUST come from a cryptographically secure random source, e.g.
# Python's `secrets.token_bytes(16)`. This module only checks its
# length; it cannot check where the caller got it from.
WRAPPING_SALT_SIZE = 16

# Limit the context size to prevent excessive resource usage.
MAX_CONTEXT_SIZE = 4096

# Each length-prefixed string field in the sharing context uses a
# 2-byte length prefix, so no single field may exceed this size.
MAX_CONTEXT_FIELD_SIZE = 65535

# This fixed application label separates document-key wrapping from
# every other possible use of the same ECDH shared secret.
KEY_WRAP_INFO_PREFIX = b"SecureVault/ECDH-KeyWrap/AES128-GCM/v1"


# ============================================================
# Input Validation
# ============================================================

def _require_bytes(name: str, value: bytes) -> None:
    """Require a value to be a bytes object."""
    if not isinstance(value, bytes):
        raise TypeError(f"{name} must be bytes")


# ============================================================
# HKDF-Extract
# ============================================================

def hkdf_extract(salt: bytes, input_key_material: bytes) -> bytes:
    """
    HKDF-Extract converts input key material into a 32-byte
    pseudorandom key (PRK).

    In our system, input_key_material is normally the 32-byte
    x-coordinate produced by P-256 ECDH.
    """
    _require_bytes("HKDF salt", salt)
    _require_bytes("HKDF input key material", input_key_material)

    if len(input_key_material) == 0:
        raise ValueError("HKDF input key material must not be empty")

    # RFC 5869 treats an empty salt as HashLen zero bytes.
    if len(salt) == 0:
        salt = b"\x00" * SHA256_DIGEST_SIZE

    return hmac_sha256(salt, input_key_material)


# ============================================================
# HKDF-Expand
# ============================================================

def hkdf_expand(
    pseudorandom_key: bytes,
    info: bytes,
    output_length: int,
) -> bytes:
    """
    HKDF-Expand produces output_length bytes from the pseudorandom key.

    The info field binds the derived key to its intended purpose and
    protocol context.
    """
    _require_bytes("HKDF pseudorandom key", pseudorandom_key)
    _require_bytes("HKDF info", info)

    if len(pseudorandom_key) != SHA256_DIGEST_SIZE:
        raise ValueError(
            "HKDF pseudorandom key must be exactly 32 bytes"
        )

    if not isinstance(output_length, int) or isinstance(output_length, bool):
        raise TypeError("HKDF output length must be an integer")

    if output_length < 1 or output_length > MAX_OUTPUT_SIZE:
        raise ValueError(
            "HKDF output length must be between 1 and 8160 bytes"
        )

    output = bytearray()
    previous_block = b""

    # SHA-256 produces 32 bytes in each expansion block.
    number_of_blocks = (
        output_length + SHA256_DIGEST_SIZE - 1
    ) // SHA256_DIGEST_SIZE

    for block_number in range(1, number_of_blocks + 1):
        previous_block = hmac_sha256(
            pseudorandom_key,
            previous_block
            + info
            + bytes([block_number]),
        )

        output.extend(previous_block)

    return bytes(output[:output_length])


# ============================================================
# Complete HKDF
# ============================================================

def hkdf_sha256(
    input_key_material: bytes,
    salt: bytes,
    info: bytes,
    output_length: int,
) -> bytes:
    """
    Perform HKDF-Extract followed by HKDF-Expand.
    """
    pseudorandom_key = hkdf_extract(
        salt,
        input_key_material,
    )

    return hkdf_expand(
        pseudorandom_key,
        info,
        output_length,
    )


# ============================================================
# Sharing Context Encoding
# ============================================================
#
# WHY THIS EXISTS:
#
# derive_wrapping_key() needs one "context" byte string that
# uniquely identifies a single sharing operation (who sent it, who
# it's for, which document, which version). If we built that string
# by simply concatenating the raw fields, two DIFFERENT sets of
# field values could produce the EXACT SAME bytes -- for example
# "la" + "yla" + "omardoc1" gives the same bytes as
# "layla" + "omar" + "doc1". Since the wrapping key is derived from
# these bytes, both cases would then get the same wrapping key,
# even though they should not.
#
# The fix is to prefix every variable-length field with its length
# before concatenating. That way the boundary between fields can
# never be misread, no matter what the field values are.

def _pack_context_str(value: str, field_name: str) -> bytes:
    """Length-prefix one text field: [2-byte length][UTF-8 bytes]."""
    if not isinstance(value, str):
        raise TypeError(f"{field_name} must be a string")

    raw = value.encode("utf-8")

    if len(raw) == 0:
        raise ValueError(f"{field_name} must not be empty")

    if len(raw) > MAX_CONTEXT_FIELD_SIZE:
        raise ValueError(f"{field_name} is too long")

    return struct.pack(">H", len(raw)) + raw


def build_sharing_context(
    sender_id: str,
    recipient_id: str,
    document_id: str,
    version: int,
) -> bytes:
    """
    Build the canonical context bytes for one document share.

    Each text field is prefixed with its own length so that field
    boundaries can never be confused (see note above). The version
    number uses a fixed 4-byte width, so it needs no length prefix.

    Pass the result of this function as the `context` argument of
    derive_wrapping_key().
    """
    if not isinstance(version, int) or isinstance(version, bool):
        raise TypeError("version must be an integer")

    if version < 0:
        raise ValueError("version must not be negative")

    if version > 0xFFFFFFFF:
        raise ValueError("version is too large")

    return (
        _pack_context_str(sender_id, "sender_id")
        + _pack_context_str(recipient_id, "recipient_id")
        + _pack_context_str(document_id, "document_id")
        + struct.pack(">I", version)
    )


# ============================================================
# Key-Wrapping Key Derivation
# ============================================================

def derive_wrapping_key(
    shared_secret: bytes,
    salt: bytes,
    context: bytes,
) -> bytes:
    """
    Derive a 16-byte AES-128-GCM key-wrapping key from an ECDH
    shared secret.

    context must be a canonical, unambiguous encoding containing
    security-relevant information such as:

        - sender identity
        - recipient identity
        - document ID
        - document version

    Build it with build_sharing_context() above, which length-prefixes
    every field so two different sets of values can never collide into
    the same bytes.

    salt must be freshly generated with a cryptographically secure
    random source (e.g. Python's secrets.token_bytes(16)) by the
    caller. This function only checks its length, not its randomness.

    The same shared secret, salt, and context produce the same
    wrapping key for Layla and Omar.
    """
    _require_bytes("ECDH shared secret", shared_secret)
    _require_bytes("wrapping salt", salt)
    _require_bytes("wrapping context", context)

    if len(shared_secret) != ECDH_SHARED_SECRET_SIZE:
        raise ValueError(
            "P-256 ECDH shared secret must be exactly 32 bytes"
        )

    if len(salt) != WRAPPING_SALT_SIZE:
        raise ValueError(
            "wrapping salt must be exactly 16 bytes"
        )

    if len(context) == 0:
        raise ValueError(
            "wrapping context must not be empty"
        )

    if len(context) > MAX_CONTEXT_SIZE:
        raise ValueError(
            "wrapping context is too large"
        )

    # Include the fixed protocol label before the specific sharing
    # context to provide domain separation.
    info = (
        KEY_WRAP_INFO_PREFIX
        + len(context).to_bytes(4, byteorder="big")
        + context
    )

    return hkdf_sha256(
        input_key_material=shared_secret,
        salt=salt,
        info=info,
        output_length=WRAPPING_KEY_SIZE,
    )
