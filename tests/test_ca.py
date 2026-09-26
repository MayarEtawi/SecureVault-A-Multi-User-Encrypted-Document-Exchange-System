# tests/test_ca.py

import pytest

from crypto.ecc import Point, n
from crypto.ecdh import generate_keypair as generate_ecdh_keypair
from crypto.ecdsa import generate_keypair as generate_ecdsa_keypair
from pki.ca import (
    DEFAULT_CA_NAME,
    DEFAULT_VALIDITY_SECONDS,
    generate_ca_keypair,
    issue_certificate,
    verify_certificate,
)
from pki.certificate import UserCertificate


# ============================================================
# Key Pair Generation Tests
# ============================================================

def test_generate_ca_keypair_returns_valid_keys():
    private_key, public_key = generate_ca_keypair()

    assert isinstance(private_key, int)
    assert 1 <= private_key < n
    assert isinstance(public_key, tuple)
    assert len(public_key) == 2


# ============================================================
# Certificate Issuance Tests
# ============================================================

def test_issue_certificate_defaults():
    ca_private_key, _ = generate_ca_keypair()
    _, ecdh_pub = generate_ecdh_keypair()
    _, ecdsa_pub = generate_ecdsa_keypair()

    cert = issue_certificate(
        ca_private_key=ca_private_key,
        username="Alice",
        ecdh_public_key=ecdh_pub,
        ecdsa_public_key=ecdsa_pub,
    )

    assert isinstance(cert, UserCertificate)
    assert cert.username == "Alice"
    assert cert.issuer == DEFAULT_CA_NAME
    assert cert.valid_until - cert.valid_from == DEFAULT_VALIDITY_SECONDS
    assert cert.ca_signature is not None


def test_issue_certificate_invalid_ca_private_key():
    _, ecdh_pub = generate_ecdh_keypair()
    _, ecdsa_pub = generate_ecdsa_keypair()

    with pytest.raises(TypeError):
        issue_certificate(
            ca_private_key="not_an_int",
            username="Alice",
            ecdh_public_key=ecdh_pub,
            ecdsa_public_key=ecdsa_pub,
        )

    with pytest.raises(ValueError):
        issue_certificate(
            ca_private_key=0,  # Invalid range (must be >= 1)
            username="Alice",
            ecdh_public_key=ecdh_pub,
            ecdsa_public_key=ecdsa_pub,
        )


def test_issue_certificate_invalid_validity_period():
    ca_private_key, _ = generate_ca_keypair()
    _, ecdh_pub = generate_ecdh_keypair()
    _, ecdsa_pub = generate_ecdsa_keypair()

    with pytest.raises(TypeError):
        issue_certificate(
            ca_private_key=ca_private_key,
            username="Alice",
            ecdh_public_key=ecdh_pub,
            ecdsa_public_key=ecdsa_pub,
            validity_seconds="3600",
        )

    with pytest.raises(ValueError):
        issue_certificate(
            ca_private_key=ca_private_key,
            username="Alice",
            ecdh_public_key=ecdh_pub,
            ecdsa_public_key=ecdsa_pub,
            validity_seconds=0,
        )


# ============================================================
# Verification Edge Cases & Exception Handling
# ============================================================

def test_verify_certificate_invalid_types_returns_false():
    _, ca_public_key = generate_ca_keypair()

    # Invalid certificate object
    assert verify_certificate("not_a_cert", ca_public_key) is False

    # Invalid CA public key format
    ca_private_key, _ = generate_ca_keypair()
    _, ecdh_pub = generate_ecdh_keypair()
    _, ecdsa_pub = generate_ecdsa_keypair()
    cert = issue_certificate(ca_private_key, "Alice", ecdh_pub, ecdsa_pub)

    assert verify_certificate(cert, "invalid_ca_pubkey") is False


def test_verify_certificate_custom_time_and_issuer():
    ca_private_key, ca_public_key = generate_ca_keypair()
    _, ecdh_pub = generate_ecdh_keypair()
    _, ecdsa_pub = generate_ecdsa_keypair()

    custom_issuer = "Custom Security CA"
    start_time = 500_000

    cert = issue_certificate(
        ca_private_key=ca_private_key,
        username="Bob",
        ecdh_public_key=ecdh_pub,
        ecdsa_public_key=ecdsa_pub,
        issuer=custom_issuer,
        valid_from=start_time,
        validity_seconds=1000,
    )

    # Valid check
    assert verify_certificate(
        cert,
        ca_public_key,
        expected_username="Bob",
        expected_issuer=custom_issuer,
        current_time=start_time + 500,
    ) is True

    # Mismatched expected issuer
    assert verify_certificate(
        cert,
        ca_public_key,
        expected_username="Bob",
        expected_issuer="Wrong CA Name",
        current_time=start_time + 500,
    ) is False