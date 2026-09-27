import json
import hashlib
import pytest

from crypto.ecdh import generate_keypair as generate_ecdh_keypair
from crypto.ecdsa import generate_keypair as generate_ecdsa_keypair
from pki.ca_admin import initialize_ca, issue_from_request
from pki.certificate import encode_public_key
from pki.enrollment_request import save_enrollment_request


def make_request(tmp_path, signing_private_key=None):
    _, ecdh_public = generate_ecdh_keypair()
    ecdsa_private, ecdsa_public = generate_ecdsa_keypair()

    if signing_private_key is None:
        signing_private_key = ecdsa_private

    request_path = tmp_path / "user.request.json"
    save_enrollment_request(
        str(request_path),
        "Omar",
        ecdh_public,
        ecdsa_public,
        signing_private_key,
    )
    return request_path


def make_ca(tmp_path):
    private_path = tmp_path / "ca_private.hex"
    public_path = tmp_path / "ca_public.json"
    initialize_ca(str(private_path), str(public_path))
    return private_path


def test_valid_signed_request_can_be_approved(tmp_path, monkeypatch):
    request_path = make_request(tmp_path)
    ca_private_path = make_ca(tmp_path)
    certificate_path = tmp_path / "omar.certificate.json"

    request = json.loads(request_path.read_text(encoding="utf-8"))
    answers = iter([
        request["username"],
        hashlib.sha256(bytes.fromhex(request["ecdh_public_key"])).hexdigest(),
        hashlib.sha256(bytes.fromhex(request["ecdsa_public_key"])).hexdigest(),
        "APPROVE",
    ])
    monkeypatch.setattr("builtins.input", lambda prompt: next(answers))
    issue_from_request(
        str(request_path),
        str(certificate_path),
        str(ca_private_path),
    )

    assert certificate_path.is_file()
    certificate = json.loads(certificate_path.read_text(encoding="utf-8"))
    assert certificate["username"] == "Omar"


def test_changed_username_is_rejected_before_approval(tmp_path, monkeypatch):
    request_path = make_request(tmp_path)
    ca_private_path = make_ca(tmp_path)
    certificate_path = tmp_path / "omar.certificate.json"

    request = json.loads(request_path.read_text(encoding="utf-8"))
    request["username"] = "Trudy"
    request_path.write_text(json.dumps(request), encoding="utf-8")

    def approval_must_not_be_requested(prompt):
        pytest.fail("CA asked for APPROVE before checking the signature")

    monkeypatch.setattr("builtins.input", approval_must_not_be_requested)

    with pytest.raises(ValueError, match="invalid enrollment request"):
        issue_from_request(
            str(request_path),
            str(certificate_path),
            str(ca_private_path),
        )

    assert not certificate_path.exists()


def test_changed_ecdh_key_is_rejected_before_approval(tmp_path, monkeypatch):
    request_path = make_request(tmp_path)
    ca_private_path = make_ca(tmp_path)
    certificate_path = tmp_path / "omar.certificate.json"

    _, other_ecdh_public = generate_ecdh_keypair()
    request = json.loads(request_path.read_text(encoding="utf-8"))
    request["ecdh_public_key"] = encode_public_key(other_ecdh_public).hex()
    request_path.write_text(json.dumps(request), encoding="utf-8")

    monkeypatch.setattr(
        "builtins.input",
        lambda prompt: pytest.fail("Invalid request reached APPROVE"),
    )

    with pytest.raises(ValueError, match="invalid enrollment request"):
        issue_from_request(
            str(request_path),
            str(certificate_path),
            str(ca_private_path),
        )

    assert not certificate_path.exists()


def test_wrong_signing_private_key_is_rejected(tmp_path, monkeypatch):
    other_private, _ = generate_ecdsa_keypair()
    request_path = make_request(tmp_path, signing_private_key=other_private)
    ca_private_path = make_ca(tmp_path)
    certificate_path = tmp_path / "omar.certificate.json"

    monkeypatch.setattr(
        "builtins.input",
        lambda prompt: pytest.fail("Invalid request reached APPROVE"),
    )

    with pytest.raises(ValueError, match="invalid enrollment request"):
        issue_from_request(
            str(request_path),
            str(certificate_path),
            str(ca_private_path),
        )

    assert not certificate_path.exists()
