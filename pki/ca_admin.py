"""Offline administrator operations for the SecureVault CA."""

import json
import os
from pathlib import Path
import hashlib

from crypto.ecdsa import is_valid_public_key
from crypto.ecc import Point, n
from pki.ca import generate_ca_keypair, issue_certificate
from pki.certificate import UserCertificate
from crypto.ecdsa import verify as verify_ecdsa_signature
from pki.enrollment_request import request_bytes

def initialize_ca(private_key_path: str, public_key_path: str) -> Point:
    """
    Create the CA key pair once.

    Keep private_key_path outside the project and document server.
    Install a trusted copy of public_key_path in each client.
    """
    private_path = Path(private_key_path)
    public_path = Path(public_key_path)

    if private_path.exists() or public_path.exists():
        raise FileExistsError("CA keys already exist; refusing to replace them")

    private_key, public_key = generate_ca_keypair()

    # Exclusive creation prevents accidentally replacing an existing key.
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    descriptor = os.open(private_path, flags, 0o600)

    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as file:
            file.write(f"{private_key:x}\n")
    except Exception:
        private_path.unlink(missing_ok=True)
        raise

    try:
        public_path.write_text(
            json.dumps({
                "x": f"{public_key[0]:x}",
                "y": f"{public_key[1]:x}",
            }),
            encoding="utf-8",
        )
    except Exception:
        private_path.unlink(missing_ok=True)
        raise

    return public_key


def load_ca_private_key(private_key_path: str) -> int:
    """Load the CA signing key from the administrator's private file."""
    private_key = int(
        Path(private_key_path).read_text(encoding="utf-8").strip(),
        16,
    )

    if not (1 <= private_key < n):
        raise ValueError("invalid CA private key file")

    return private_key


def load_ca_public_key(public_key_path: str) -> Point:
    """Load a CA public key from an already trusted local file."""
    from crypto.ecdsa import is_valid_public_key

    data = json.loads(
        Path(public_key_path).read_text(encoding="utf-8")
    )

    public_key = (int(data["x"], 16), int(data["y"], 16))

    if not is_valid_public_key(public_key):
        raise ValueError("invalid CA public key file")

    return public_key


def approve_and_issue_certificate(
    private_key_path: str,
    username: str,
    ecdh_public_key: Point,
    ecdsa_public_key: Point,
    *,
    identity_verified: bool,
) -> UserCertificate:
    """
    Issue a certificate only after the CA administrator has checked
    the claimant's right to use this username and these public keys.

    identity_verified must come from the administrator's own approval
    process; never take it from a client or server request.
    """
    if identity_verified is not True:
        raise PermissionError("CA administrator has not approved this request")

    ca_private_key = load_ca_private_key(private_key_path)

    return issue_certificate(
        ca_private_key=ca_private_key,
        username=username,
        ecdh_public_key=ecdh_public_key,
        ecdsa_public_key=ecdsa_public_key,
    )


def _read_public_key(hex_value: str) -> Point:
    encoded = bytes.fromhex(hex_value)

    if len(encoded) != 65 or encoded[0] != 4:
        raise ValueError("invalid public key encoding")

    public_key = (
        int.from_bytes(encoded[1:33], "big"),
        int.from_bytes(encoded[33:65], "big"),
    )

    if not is_valid_public_key(public_key):
        raise ValueError("invalid public key")

    return public_key


def issue_from_request(
    request_path: str,
    certificate_path: str,
    private_key_path: str,
) -> None:
    """Verify a signed request before asking the CA administrator to approve."""
    request_file = Path(request_path)

    if request_file.stat().st_size > 4096:
        raise ValueError("certificate request is too large")

    try:
        request = json.loads(request_file.read_text(encoding="utf-8"))

        if not isinstance(request, dict):
            raise ValueError("request must be an object")

        username = request["username"]
        ecdh_public_key = _read_public_key(request["ecdh_public_key"])
        ecdsa_public_key = _read_public_key(request["ecdsa_public_key"])

        request_id = bytes.fromhex(request["request_id"])
        signature = request["request_signature"]

        if not isinstance(signature, list) or len(signature) != 2:
            raise ValueError("invalid signature format")

        signed_body = request_bytes(
            username,
            ecdh_public_key,
            ecdsa_public_key,
            request_id,
        )

        if not verify_ecdsa_signature(
            signed_body,
            tuple(signature),
            ecdsa_public_key,
        ):
            raise ValueError("invalid request signature")

        ecdh_encoded = bytes.fromhex(request["ecdh_public_key"])
        ecdsa_encoded = bytes.fromhex(request["ecdsa_public_key"])

    except (KeyError, TypeError, ValueError, UnicodeError) as exc:
        raise ValueError("invalid enrollment request") from exc

    # This prompt is reached only after the signature has passed.
    print("Requested username:", username)
    print("ECDH fingerprint:", hashlib.sha256(ecdh_encoded).hexdigest())
    print("ECDSA fingerprint:", hashlib.sha256(ecdsa_encoded).hexdigest())
    print("Check the applicant's right to this username and these keys.")

    checked_username = input("Username verified independently: ").strip()
    checked_ecdh = input("ECDH fingerprint read from applicant: ").strip().lower()
    checked_ecdsa = input("ECDSA fingerprint read from applicant: ").strip().lower()

    if (
        checked_username != username
        or checked_ecdh != hashlib.sha256(ecdh_encoded).hexdigest()
        or checked_ecdsa != hashlib.sha256(ecdsa_encoded).hexdigest()
    ):
        raise PermissionError("independent identity/key check failed")

    approval = input("Type APPROVE after the checks: ")
    if approval != "APPROVE":
        raise PermissionError("certificate request was not approved")

    certificate = approve_and_issue_certificate(
        private_key_path,
        username,
        ecdh_public_key,
        ecdsa_public_key,
        identity_verified=True,
    )

    result = {
        "version": certificate.version,
        "serial_number": certificate.serial_number.hex(),
        "issuer": certificate.issuer,
        "username": certificate.username,
        "ecdh_public_key": ecdh_encoded.hex(),
        "ecdsa_public_key": ecdsa_encoded.hex(),
        "valid_from": certificate.valid_from,
        "valid_until": certificate.valid_until,
        "ca_signature": list(certificate.ca_signature),
    }

    with Path(certificate_path).open("x", encoding="utf-8") as file:
        json.dump(result, file, indent=2)
