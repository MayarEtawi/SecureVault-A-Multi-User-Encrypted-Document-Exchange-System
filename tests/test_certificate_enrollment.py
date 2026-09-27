from dataclasses import replace

import pytest

from auth.certificate_enrollment import (
    CertificateEnrollmentError,
    enroll_certificate,
)
from crypto.ecdh import generate_keypair as generate_ecdh_keypair
from crypto.ecdsa import (
    generate_keypair as generate_ecdsa_keypair,
    verify,
)
from pki.ca import generate_ca_keypair, issue_certificate
from pki.certificate import encode_public_key
from pki.enrollment_request import request_bytes, save_enrollment_request


def test_signed_request_contains_valid_proof_of_possession(tmp_path):
    ecdsa_private, ecdsa_public = generate_ecdsa_keypair()
    _, ecdh_public = generate_ecdh_keypair()
    path = tmp_path / "request.json"

    save_enrollment_request(
        str(path), "Omar", ecdh_public, ecdsa_public, ecdsa_private
    )

    import json
    request = json.loads(path.read_text(encoding="utf-8"))

    assert request["username"] == "Omar"
    assert request["ecdh_public_key"] == encode_public_key(ecdh_public).hex()

    body = request_bytes(
        request["username"],
        ecdh_public,
        ecdsa_public,
        bytes.fromhex(request["request_id"]),
    )
    assert verify(
        body,
        tuple(request["request_signature"]),
        ecdsa_public,
    )


def test_enrollment_accepts_matching_ca_certificate():
    ca_private, ca_public = generate_ca_keypair()
    _, ecdh_public = generate_ecdh_keypair()
    ecdsa_private, ecdsa_public = generate_ecdsa_keypair()

    def request_certificate(username, ecdh_key, ecdsa_key, signing_key):
        assert signing_key == ecdsa_private
        return issue_certificate(
            ca_private, username, ecdh_key, ecdsa_key
        )

    certificate = enroll_certificate(
        "Omar",
        ecdh_public,
        ecdsa_public,
        ecdsa_private,
        request_certificate,
        ca_public,
    )

    assert certificate.username == "Omar"


def test_enrollment_rejects_ca_certificate_with_different_keys():
    ca_private, ca_public = generate_ca_keypair()
    _, ecdh_public = generate_ecdh_keypair()
    ecdsa_private, ecdsa_public = generate_ecdsa_keypair()
    _, other_ecdh_public = generate_ecdh_keypair()

    def request_certificate(username, ecdh_key, ecdsa_key, signing_key):
        return issue_certificate(
            ca_private, username, other_ecdh_public, ecdsa_key
        )

    with pytest.raises(CertificateEnrollmentError):
        enroll_certificate(
            "Omar",
            ecdh_public,
            ecdsa_public,
            ecdsa_private,
            request_certificate,
            ca_public,
        )
