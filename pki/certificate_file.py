"""Read a CA-issued SecureVault certificate from JSON."""

import json
from pathlib import Path

from crypto.ecdsa import is_valid_public_key
from pki.certificate import UserCertificate, validate_certificate_fields


def _public_key_from_hex(value: str):
    encoded = bytes.fromhex(value)

    if len(encoded) != 65 or encoded[0] != 4:
        raise ValueError("invalid public key encoding")

    public_key = (
        int.from_bytes(encoded[1:33], "big"),
        int.from_bytes(encoded[33:65], "big"),
    )

    if not is_valid_public_key(public_key):
        raise ValueError("invalid public key")

    return public_key


def load_certificate(path: str) -> UserCertificate:
    """Parse a certificate file; the caller must verify its CA signature."""
    certificate_path = Path(path)

    if certificate_path.stat().st_size > 4096:
        raise ValueError("certificate file is too large")

    data = json.loads(certificate_path.read_text(encoding="utf-8"))

    certificate = UserCertificate(
        version=data["version"],
        serial_number=bytes.fromhex(data["serial_number"]),
        issuer=data["issuer"],
        username=data["username"],
        ecdh_public_key=_public_key_from_hex(data["ecdh_public_key"]),
        ecdsa_public_key=_public_key_from_hex(data["ecdsa_public_key"]),
        valid_from=data["valid_from"],
        valid_until=data["valid_until"],
        ca_signature=tuple(data["ca_signature"]),
    )

    validate_certificate_fields(certificate)
    return certificate
