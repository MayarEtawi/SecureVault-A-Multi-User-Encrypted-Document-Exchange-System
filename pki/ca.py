"""Small Certificate Authority for SecureVault."""

from __future__ import annotations

from dataclasses import replace
import secrets
import time

from crypto.ecc import Point, n
from crypto.ecdsa import (
    generate_keypair as generate_ecdsa_keypair,
    is_valid_public_key,
    sign,
    verify,
)
from pki.certificate import (
    CERTIFICATE_VERSION,
    SERIAL_NUMBER_SIZE,
    UserCertificate,
    encode_certificate_body,
    validate_certificate_fields,
)


DEFAULT_CA_NAME = "SecureVault Root CA"
DEFAULT_VALIDITY_SECONDS = 365 * 24 * 60 * 60


def generate_ca_keypair() -> tuple[int, Point]:
    """Generate the CA's ECDSA signing key pair."""
    return generate_ecdsa_keypair()


def issue_certificate(
    ca_private_key: int,
    username: str,
    ecdh_public_key: Point,
    ecdsa_public_key: Point,
    *,
    issuer: str = DEFAULT_CA_NAME,
    valid_from: int | None = None,
    validity_seconds: int = DEFAULT_VALIDITY_SECONDS,
) -> UserCertificate:
    """
    Sign a certificate binding a username to two public keys.

    The caller must first authenticate and authorize the username and keys.
    Keep this function and the CA private key outside the document server.
    """
    if not isinstance(ca_private_key, int) or isinstance(ca_private_key, bool):
        raise TypeError("CA private key must be an integer")

    if not (1 <= ca_private_key < n):
        raise ValueError("invalid CA private key")

    if valid_from is None:
        valid_from = int(time.time())

    if not isinstance(valid_from, int) or isinstance(valid_from, bool):
        raise TypeError("valid_from must be an integer")

    if not isinstance(validity_seconds, int) or isinstance(
        validity_seconds, bool
    ):
        raise TypeError("validity period must be an integer")

    if validity_seconds <= 0:
        raise ValueError("validity period must be positive")

    unsigned_certificate = UserCertificate(
        version=CERTIFICATE_VERSION,
        serial_number=secrets.token_bytes(SERIAL_NUMBER_SIZE),
        issuer=issuer,
        username=username,
        ecdh_public_key=ecdh_public_key,
        ecdsa_public_key=ecdsa_public_key,
        valid_from=valid_from,
        valid_until=valid_from + validity_seconds,
        ca_signature=None,
    )

    # This validates all fields, including timestamp range, before signing.
    certificate_body = encode_certificate_body(unsigned_certificate)
    signature = sign(certificate_body, ca_private_key)

    signed_certificate = replace(
        unsigned_certificate,
        ca_signature=signature,
    )
    validate_certificate_fields(signed_certificate)

    return signed_certificate


def verify_certificate(
    certificate: UserCertificate,
    trusted_ca_public_key: Point,
    *,
    expected_username: str | None = None,
    expected_issuer: str = DEFAULT_CA_NAME,
    current_time: int | None = None,
) -> bool:
    """Check the certificate fields, identity, lifetime, and CA signature."""
    try:
        if not isinstance(certificate, UserCertificate):
            return False

        if not is_valid_public_key(trusted_ca_public_key):
            return False

        validate_certificate_fields(certificate)

        if certificate.ca_signature is None:
            return False

        if certificate.issuer != expected_issuer:
            return False

        if (
            expected_username is not None
            and certificate.username != expected_username
        ):
            return False

        if current_time is None:
            current_time = int(time.time())

        if not isinstance(current_time, int) or isinstance(current_time, bool):
            return False

        if not (
            certificate.valid_from <= current_time < certificate.valid_until
        ):
            return False

        certificate_body = encode_certificate_body(certificate)

        return verify(
            certificate_body,
            certificate.ca_signature,
            trusted_ca_public_key,
        )

    except (TypeError, ValueError, OverflowError, UnicodeError):
        return False
