"""Create a signed certificate enrollment request."""

import json
import secrets
from pathlib import Path

from crypto.ecdsa import sign
from pki.certificate import encode_public_key


REQUEST_PREFIX = b"SecureVault-Enrollment-Request-v1"
REQUEST_ID_SIZE = 16


def request_bytes(username, ecdh_public_key, ecdsa_public_key, request_id):
    """Return the unambiguous bytes signed by the applicant."""
    if not isinstance(username, str) or not username.strip():
        raise ValueError("username must not be empty")

    name = username.strip().encode("utf-8")
    if len(name) > 128:
        raise ValueError("username is too long")

    if not isinstance(request_id, bytes) or len(request_id) != REQUEST_ID_SIZE:
        raise ValueError("request_id must be 16 bytes")

    return (
        REQUEST_PREFIX
        + len(name).to_bytes(2, "big")
        + name
        + encode_public_key(ecdh_public_key)
        + encode_public_key(ecdsa_public_key)
        + request_id
    )


def save_enrollment_request(
    path,
    username,
    ecdh_public_key,
    ecdsa_public_key,
    ecdsa_private_key,
):
    """Save a request signed by the corresponding ECDSA private key."""
    username = username.strip()
    request_id = secrets.token_bytes(REQUEST_ID_SIZE)

    body = request_bytes(
        username,
        ecdh_public_key,
        ecdsa_public_key,
        request_id,
    )
    signature = sign(body, ecdsa_private_key)

    request = {
        "username": username,
        "ecdh_public_key": encode_public_key(ecdh_public_key).hex(),
        "ecdsa_public_key": encode_public_key(ecdsa_public_key).hex(),
        "request_id": request_id.hex(),
        "request_signature": [signature[0], signature[1]],
    }

    with Path(path).open("x", encoding="utf-8") as file:
        json.dump(request, file, indent=2)
