"""User certificate representation and canonical encoding.

A certificate connects one username to two separate P-256 public keys:

1. An ECDH public key for document-key sharing.
2. An ECDSA public key for digital signatures.

The CA signs the canonical certificate body.
"""

from __future__ import annotations

from dataclasses import dataclass

from crypto.ecc import Point
from crypto.ecdsa import is_valid_public_key


CERTIFICATE_VERSION = 1
SERIAL_NUMBER_SIZE = 16
MAX_NAME_SIZE = 128

CERTIFICATE_PREFIX = b"SecureVault-User-Certificate-v1"


@dataclass(frozen=True)
class UserCertificate:
    """Certificate binding a username to its public keys."""

    version: int
    serial_number: bytes
    issuer: str
    username: str

    # Public key used only for ECDH key agreement.
    ecdh_public_key: Point

    # Public key used only for ECDSA signature verification.
    ecdsa_public_key: Point

    # Unix timestamps in seconds.
    valid_from: int
    valid_until: int

    # The CA's ECDSA signature (r, s).
    ca_signature: tuple[int, int] | None = None


# ============================================================
# Basic Encoding
# ============================================================

def _encode_field(value: bytes) -> bytes:
    """Encode a bytes field with a four-byte length prefix."""

    return len(value).to_bytes(4, byteorder="big") + value


def encode_public_key(public_key: Point) -> bytes:
    """
    Encode a P-256 public key in uncompressed format:

        0x04 || x || y

    The result is exactly 65 bytes.
    """

    if not is_valid_public_key(public_key):
        raise ValueError("invalid P-256 public key")

    x, y = public_key

    return (
        b"\x04"
        + x.to_bytes(32, byteorder="big")
        + y.to_bytes(32, byteorder="big")
    )


# ============================================================
# Certificate Validation
# ============================================================

def validate_certificate_fields(certificate: UserCertificate) -> None:
    """
    Check that all certificate fields have valid types and values.

    This function checks the structure only. It does not verify the
    CA signature.
    """

    if not isinstance(certificate, UserCertificate):
        raise TypeError("certificate must be a UserCertificate")

    if certificate.version != CERTIFICATE_VERSION:
        raise ValueError("unsupported certificate version")

    if not isinstance(certificate.serial_number, bytes):
        raise TypeError("certificate serial number must be bytes")

    if len(certificate.serial_number) != SERIAL_NUMBER_SIZE:
        raise ValueError("certificate serial number must be exactly 16 bytes")

    for field_name, value in (
        ("issuer", certificate.issuer),
        ("username", certificate.username),
    ):
        if not isinstance(value, str):
            raise TypeError(f"{field_name} must be a string")

        encoded_value = value.encode("utf-8")

        if len(encoded_value) == 0:
            raise ValueError(f"{field_name} must not be empty")

        if len(encoded_value) > MAX_NAME_SIZE:
            raise ValueError(
                f"{field_name} must not exceed {MAX_NAME_SIZE} bytes"
            )

    if not is_valid_public_key(certificate.ecdh_public_key):
        raise ValueError("invalid ECDH public key")

    if not is_valid_public_key(certificate.ecdsa_public_key):
        raise ValueError("invalid ECDSA public key")

    if certificate.ecdh_public_key == certificate.ecdsa_public_key:
        raise ValueError(
            "ECDH and ECDSA public keys must be different"
        )

    for field_name, value in (
        ("valid_from", certificate.valid_from),
        ("valid_until", certificate.valid_until),
    ):
        if not isinstance(value, int) or isinstance(value, bool):
            raise TypeError(f"{field_name} must be an integer")

        if value < 0 or value >= 2**64:
            raise ValueError(f"{field_name} is outside the valid range")

    if certificate.valid_until <= certificate.valid_from:
        raise ValueError(
            "certificate expiration must be after its starting time"
        )


# ============================================================
# Canonical Certificate Body
# ============================================================

def encode_certificate_body(certificate: UserCertificate) -> bytes:
    """
    Encode all certificate fields except the CA signature.

    These exact bytes are signed by the CA. Length prefixes make the
    representation unambiguous.
    """

    validate_certificate_fields(certificate)

    return (
        CERTIFICATE_PREFIX
        + certificate.version.to_bytes(2, byteorder="big")
        + certificate.serial_number
        + _encode_field(certificate.issuer.encode("utf-8"))
        + _encode_field(certificate.username.encode("utf-8"))
        + _encode_field(
            encode_public_key(certificate.ecdh_public_key)
        )
        + _encode_field(
            encode_public_key(certificate.ecdsa_public_key)
        )
        + certificate.valid_from.to_bytes(8, byteorder="big")
        + certificate.valid_until.to_bytes(8, byteorder="big")
    )