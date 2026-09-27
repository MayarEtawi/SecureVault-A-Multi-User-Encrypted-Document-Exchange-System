# auth/certificate_enrollment.py

"""Request and validate a user's certificate during registration."""

from collections.abc import Callable
import hashlib
from pki.certificate import encode_public_key
from crypto.ecc import Point
from pki.ca import verify_certificate
from pki.certificate import UserCertificate
from pathlib import Path
from uuid import uuid4

from pki.enrollment_request import save_enrollment_request
from pki.certificate_file import load_certificate

class CertificateEnrollmentError(Exception):
    """The CA did not provide a certificate matching this registration."""


def enroll_certificate(
    username: str,
    ecdh_public_key: Point,
    ecdsa_public_key: Point,
    ecdsa_private_key: int,
    request_certificate: Callable[
        [str, Point, Point, int], UserCertificate
    ],
    trusted_ca_public_key: Point,
) -> UserCertificate:
    """
    Ask the authorized CA for a certificate and validate its response.

    request_certificate must authenticate the requester and authorize
    the username before the CA issues a certificate. Its implementation
    belongs to the CA setup, not to this client file.
    """
    if not callable(request_certificate):
        raise TypeError("request_certificate must be callable")

    certificate = request_certificate(
        username,
        ecdh_public_key,
        ecdsa_public_key,
        ecdsa_private_key,
    )

    if not verify_certificate(
        certificate,
        trusted_ca_public_key,
        expected_username=username,
    ):
        raise CertificateEnrollmentError(
            "Certificate enrollment failed"
        )

    if (
        certificate.ecdh_public_key != ecdh_public_key
        or certificate.ecdsa_public_key != ecdsa_public_key
    ):
        raise CertificateEnrollmentError(
            "Certificate enrollment failed"
        )

    return certificate

def request_certificate_offline(
    username: str,
    ecdh_public_key: Point,
    ecdsa_public_key: Point,
    ecdsa_private_key: int,  # جديد
) -> UserCertificate:
    """Submit a request for separate CA approval on this demo machine."""
    requests_directory = Path.home() / "SecureVault-Requests"
    requests_directory.mkdir(exist_ok=True)

    request_id = uuid4().hex
    request_path = requests_directory / f"{request_id}.request.json"
    certificate_path = requests_directory / f"{request_id}.certificate.json"

    save_enrollment_request(
        str(request_path),
        username,
        ecdh_public_key,
        ecdsa_public_key,
        ecdsa_private_key,
    )

    print("Certificate request saved:", request_path)
    print("CA certificate output path:", certificate_path)
    print(
        "Your ECDH fingerprint:",
        hashlib.sha256(encode_public_key(ecdh_public_key)).hexdigest(),
    )
    print(
        "Your ECDSA fingerprint:",
        hashlib.sha256(encode_public_key(ecdsa_public_key)).hexdigest(),
    )
    input("Ask the CA administrator to approve it, then press Enter: ")

    if not certificate_path.is_file():
        raise CertificateEnrollmentError("CA certificate was not issued")

    return load_certificate(str(certificate_path))
