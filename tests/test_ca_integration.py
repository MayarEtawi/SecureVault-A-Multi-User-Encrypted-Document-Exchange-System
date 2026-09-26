from dataclasses import replace

import pytest

import client.share as share_client
from crypto.ecdh import generate_keypair as generate_ecdh_keypair
from crypto.ecdsa import generate_keypair as generate_ecdsa_keypair
from crypto.freshness import VersionTracker
from crypto.sharing import create_share, open_share
from pki.ca import generate_ca_keypair, issue_certificate


def test_client_rejects_valid_certificate_for_wrong_recipient(monkeypatch):
    ca_private, ca_public = generate_ca_keypair()
    _, ecdh_public = generate_ecdh_keypair()
    _, ecdsa_public = generate_ecdsa_keypair()

    # This certificate is genuinely signed by the CA, but belongs to Trudy.
    trudy_certificate = issue_certificate(
        ca_private,
        "Trudy",
        ecdh_public,
        ecdsa_public,
    )

    def fake_send_request(request):
        assert request == {"type": "GET_USER", "username": "Omar"}
        return {
            "status": True,
            "credential_record": {"certificate": trudy_certificate},
        }

    monkeypatch.setattr(share_client, "send_request", fake_send_request)

    with pytest.raises(ValueError, match="Recipient certificate verification failed"):
        share_client.get_verified_recipient_certificate("Omar", ca_public)


def _make_share():
    ca_private, ca_public = generate_ca_keypair()

    _, sender_ecdh_public = generate_ecdh_keypair()
    sender_ecdsa_private, sender_ecdsa_public = generate_ecdsa_keypair()
    sender_certificate = issue_certificate(
        ca_private,
        "Layla",
        sender_ecdh_public,
        sender_ecdsa_public,
    )

    recipient_ecdh_private, recipient_ecdh_public = generate_ecdh_keypair()
    _, recipient_ecdsa_public = generate_ecdsa_keypair()
    recipient_certificate = issue_certificate(
        ca_private,
        "Omar",
        recipient_ecdh_public,
        recipient_ecdsa_public,
    )

    document_key = bytes(range(16))
    record = create_share(
        document_key=document_key,
        document_id="test-document",
        sender_username="Layla",
        sender_ecdsa_private_key=sender_ecdsa_private,
        recipient_certificate=recipient_certificate,
        trusted_ca_public_key=ca_public,
        version=1,
        expected_recipient_username="Omar",
    )

    return record, sender_certificate, recipient_ecdh_private, ca_public


def test_receiver_rejects_changed_sender_certificate():
    record, sender_certificate, recipient_private, ca_public = _make_share()
    _, attacker_ecdsa_public = generate_ecdsa_keypair()

    altered_certificate = replace(
        sender_certificate,
        ecdsa_public_key=attacker_ecdsa_public,
    )

    with pytest.raises(ValueError):
        open_share(
            record=record,
            sender_certificate=altered_certificate,
            recipient_username="Omar",
            recipient_ecdh_private_key=recipient_private,
            trusted_ca_public_key=ca_public,
            version_tracker=VersionTracker(),
        )


def test_receiver_rejects_changed_signed_share_field():
    record, sender_certificate, recipient_private, ca_public = _make_share()

    altered_record = replace(record, document_id="different-document")

    with pytest.raises(ValueError, match="invalid signature"):
        open_share(
            record=altered_record,
            sender_certificate=sender_certificate,
            recipient_username="Omar",
            recipient_ecdh_private_key=recipient_private,
            trusted_ca_public_key=ca_public,
            version_tracker=VersionTracker(),
        )