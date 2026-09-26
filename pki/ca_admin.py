"""Offline administrator operations for the SecureVault CA."""

import json
import os
from pathlib import Path
import hashlib

from crypto.ecdsa import is_valid_public_key
from crypto.ecc import Point, n
from pki.ca import generate_ca_keypair, issue_certificate
from pki.certificate import UserCertificate


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
    """Review a request locally, then issue a CA-signed certificate."""
    request_file = Path(request_path)

    if request_file.stat().st_size > 4096:
        raise ValueError("certificate request is too large")

    request = json.loads(request_file.read_text(encoding="utf-8"))

    username = request["username"]
    ecdh_encoded = bytes.fromhex(request["ecdh_public_key"])
    ecdsa_encoded = bytes.fromhex(request["ecdsa_public_key"])

    ecdh_public_key = _read_public_key(request["ecdh_public_key"])
    ecdsa_public_key = _read_public_key(request["ecdsa_public_key"])

    print("Requested username:", username)
    print("ECDH fingerprint:", hashlib.sha256(ecdh_encoded).hexdigest())
    print("ECDSA fingerprint:", hashlib.sha256(ecdsa_encoded).hexdigest())
    print("Check the applicant's right to this username and these keys.")

    approval = input("Type APPROVE only after checking: ")

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