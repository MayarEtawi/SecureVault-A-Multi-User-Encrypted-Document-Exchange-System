"""Read a CA-issued SecureVault certificate from JSON."""

"""
Module Functionality Overview:
- _public_key_from_hex(): Helper function to convert a 65-byte hex string into x, y point coordinates and make sure the key is valid.
- load_certificate(): Main function to read the JSON file, check the file size, parse certificate data into a UserCertificate object, and validate fields.
"""

import json
from pathlib import Path

from crypto.ecdsa import is_valid_public_key
from pki.certificate import UserCertificate, validate_certificate_fields


# ============================================================
# Constants & Configuration
# ============================================================

MAX_CERT_FILE_SIZE = 4096  # max allowed certificate file size in bytes (4KB)


# ============================================================
# Helper Functions
# ============================================================

def _public_key_from_hex(value: str):
    """Convert uncompressed public key hex string to (x, y) tuple."""

    # decode hex string into raw bytes
    encoded = bytes.fromhex(value)

    # make sure key length is exactly 65 bytes and starts with 0x04 uncompressed prefix
    if len(encoded) != 65 or encoded[0] != 4:
        raise ValueError("invalid public key encoding")

    # parse 32-byte x and y coordinate integers
    public_key = (
        int.from_bytes(encoded[1:33], "big"),
        int.from_bytes(encoded[33:65], "big"),
    )

    # make sure public key point is valid on the ecdsa curve
    if not is_valid_public_key(public_key):
        raise ValueError("invalid public key")

    return public_key


# ============================================================
# Main Loader Logic
# ============================================================

def load_certificate(path: str) -> UserCertificate:
    """Parse a certificate file; the caller must verify its CA signature."""

    # set up path object for reading file
    certificate_path = Path(path)

    # make sure file size is not larger than allowed max limit
    if certificate_path.stat().st_size > MAX_CERT_FILE_SIZE:
        raise ValueError("certificate file is too large")

    # read and parse raw json content
    data = json.loads(certificate_path.read_text(encoding="utf-8"))

    # construct user certificate object from parsed json fields
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

    # make sure certificate fields pass structural validation checks
    validate_certificate_fields(certificate)

    return certificate
