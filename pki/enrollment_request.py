"""Create a certificate request for review by the CA administrator."""

import json
from pathlib import Path

from pki.certificate import encode_public_key


def save_enrollment_request(
    path: str,
    username: str,
    ecdh_public_key,
    ecdsa_public_key,
) -> None:
    """Save only the username and public keys."""
    if not isinstance(username, str) or not username.strip():
        raise ValueError("username must not be empty")

    request = {
        "username": username.strip(),
        "ecdh_public_key": encode_public_key(ecdh_public_key).hex(),
        "ecdsa_public_key": encode_public_key(ecdsa_public_key).hex(),
    }

    destination = Path(path)

    with destination.open("x", encoding="utf-8") as file:
        json.dump(request, file, indent=2)