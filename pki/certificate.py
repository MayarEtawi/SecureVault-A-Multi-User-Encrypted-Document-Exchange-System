"""User certificate representation and canonical encoding."""

from __future__ import annotations

from dataclasses import dataclass

from crypto.ecc import Point, n
from crypto.ecdsa import is_valid_public_key


CERTIFICATE_VERSION = 1
SERIAL_NUMBER_SIZE = 16
MAX_NAME_SIZE = 128
CERTIFICATE_PREFIX = b"SecureVault-User-Certificate-v1"


@dataclass(frozen=True)
class UserCertificate:
    """Bind one username to separate ECDH and ECDSA public keys."""

    version: int
    serial_number: bytes
    issuer: str
    username: str
    ecdh_public_key: Point
    ecdsa_public_key: Point
    valid_from: int
    valid_until: int
    ca_signature: tuple[int, int] | None = None


def _encode_field(value: bytes) -> bytes:
    """Encode a bytes field with a four-byte length prefix."""
    return len(value).to_bytes(4, byteorder="big") + value


def encode_public_key(public_key: Point) -> bytes:
    """Encode a P-256 public key as 0x04 || x || y."""
    if not is_valid_public_key(public_key):
        raise ValueError("invalid P-256 public key")

    x, y = public_key

    return (
        b"\x04"
        + x.to_bytes(32, byteorder="big")
        + y.to_bytes(32, byteorder="big")
    )


def validate_certificate_fields(certificate: UserCertificate) -> None:
    """Reject malformed certificate fields before signing or verification."""
    if not isinstance(certificate, UserCertificate):
        raise TypeError("certificate must be a UserCertificate")

    if (
        not isinstance(certificate.version, int)
        or isinstance(certificate.version, bool)
        or certificate.version != CERTIFICATE_VERSION
    ):
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

        try:
            encoded_value = value.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise ValueError(f"{field_name} is not valid UTF-8 text") from exc

        if not (1 <= len(encoded_value) <= MAX_NAME_SIZE):
            raise ValueError(
                f"{field_name} must contain 1 to {MAX_NAME_SIZE} UTF-8 bytes"
            )

    if not is_valid_public_key(certificate.ecdh_public_key):
        raise ValueError("invalid ECDH public key")

    if not is_valid_public_key(certificate.ecdsa_public_key):
        raise ValueError("invalid ECDSA public key")

    if certificate.ecdh_public_key == certificate.ecdsa_public_key:
        raise ValueError("ECDH and ECDSA public keys must be different")

    for field_name, value in (
        ("valid_from", certificate.valid_from),
        ("valid_until", certificate.valid_until),
    ):
        if not isinstance(value, int) or isinstance(value, bool):
            raise TypeError(f"{field_name} must be an integer")

        if not (0 <= value < 2**64):
            raise ValueError(f"{field_name} is outside the valid range")

    if certificate.valid_until <= certificate.valid_from:
        raise ValueError("certificate expiration must follow its start time")

    if certificate.ca_signature is not None:
        signature = certificate.ca_signature

        if not isinstance(signature, tuple) or len(signature) != 2:
            raise ValueError("CA signature must be an (r, s) tuple")

        r, s = signature
        for component in (r, s):
            if (
                not isinstance(component, int)
                or isinstance(component, bool)
                or not (1 <= component < n)
            ):
                raise ValueError("invalid CA signature component")


def encode_certificate_body(certificate: UserCertificate) -> bytes:
    """Encode the exact certificate fields signed by the CA."""
    validate_certificate_fields(certificate)

    return (
        CERTIFICATE_PREFIX
        + certificate.version.to_bytes(2, byteorder="big")
        + certificate.serial_number
        + _encode_field(certificate.issuer.encode("utf-8"))
        + _encode_field(certificate.username.encode("utf-8"))
        + _encode_field(encode_public_key(certificate.ecdh_public_key))
        + _encode_field(encode_public_key(certificate.ecdsa_public_key))
        + certificate.valid_from.to_bytes(8, byteorder="big")
        + certificate.valid_until.to_bytes(8, byteorder="big")
    )
