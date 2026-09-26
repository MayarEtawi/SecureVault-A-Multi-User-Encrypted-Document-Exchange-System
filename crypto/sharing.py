# crypto/sharing.py
#
# Sharing protocol: a signed, replay-protected envelope around
# key_wrap.py's WrappedDocumentKey.
#
# key_wrap.py already does the actual cryptographic work of protecting
# Kdoc for one recipient (ephemeral ECDH + HKDF + AES-128-GCM). What it
# does NOT do is authenticate who the sender really is: anyone can call
# wrap_document_key() and put "layla" in sender_id as a plain string --
# encrypting to Omar's public key needs no proof of identity. So this
# module's job is exactly the outer layer:
#
#   - verify both parties' certificates against the trusted CA
#     (Section 7.4) before trusting their keys at all,
#   - wrap/unwrap Kdoc by calling into key_wrap.py directly (no
#     reimplementation of ECDH/HKDF/GCM here),
#   - ECDSA-sign the whole record with the sender's real long-term
#     signing key (Section 7.5) -- THIS is what actually proves the
#     claimed sender_id is genuine,
#   - enforce freshness via freshness.VersionTracker, called only
#     after signature verification AND successful unwrap, per that
#     module's own documented contract.
#
# Kdoc is 16 bytes (AES-128), matching key_wrap.DOCUMENT_KEY_SIZE --
# not 32, which was an earlier incorrect assumption on my part.

from __future__ import annotations

import time
from dataclasses import dataclass

from crypto.ecc import Point
from crypto.ecdsa import sign as ecdsa_sign, verify as ecdsa_verify
from crypto.gcm import AuthenticationError
from pki.certificate import UserCertificate
from pki.ca import verify_certificate, DEFAULT_CA_NAME

# Corrected package imports to match project structure
from crypto.key_wrap import (
    DOCUMENT_KEY_SIZE,
    WrappedDocumentKey,
    encode_public_key,
    wrap_document_key,
    unwrap_document_key,
)
from crypto.freshness import VersionTracker, ReplayError

SCALAR_LEN = 32  # P-256 order n fits in 32 bytes


# ============================================================
# Canonical encoding helpers (same length-prefixed style used
# throughout the rest of the project)
# ============================================================

def _encode_bytes(b: bytes) -> bytes:
    return len(b).to_bytes(4, "big") + b


def _decode_bytes(buf: bytes, offset: int) -> tuple[bytes, int]:
    length = int.from_bytes(buf[offset:offset + 4], "big")
    offset += 4
    value = buf[offset:offset + length]
    if len(value) != length:
        raise ValueError("truncated buffer while decoding length-prefixed field")
    offset += length
    return value, offset


def _encode_str(s: str) -> bytes:
    return _encode_bytes(s.encode("utf-8"))


def _decode_str(buf: bytes, offset: int) -> tuple[str, int]:
    raw, offset = _decode_bytes(buf, offset)
    return raw.decode("utf-8"), offset


def _encode_point(point: Point) -> bytes:
    return _encode_bytes(encode_public_key(point))


def _decode_point(buf: bytes, offset: int) -> tuple[Point, int]:
    raw, offset = _decode_bytes(buf, offset)
    # raw is 0x04 || x(32) || y(32), per key_wrap.encode_public_key
    if len(raw) != 65 or raw[0] != 0x04:
        raise ValueError("invalid encoded public key in share record")
    x = int.from_bytes(raw[1:33], "big")
    y = int.from_bytes(raw[33:65], "big")
    return (x, y), offset


def _encode_int(value: int, length: int) -> bytes:
    return value.to_bytes(length, "big")


def _decode_int(buf: bytes, offset: int, length: int) -> tuple[int, int]:
    value = int.from_bytes(buf[offset:offset + length], "big")
    return value, offset + length


# ============================================================
# Share Record
# ============================================================

@dataclass(frozen=True)
class ShareRecord:
    version: int
    document_id: str
    sender_username: str
    recipient_username: str
    wrapped_key: WrappedDocumentKey
    timestamp: int
    signature: tuple[int, int] | None = None  # sender's ECDSA (r, s)

    def signable_bytes(self) -> bytes:
        """
        Canonical, unambiguous encoding of every field EXCEPT the
        signature -- exactly what the sender ECDSA-signs and the
        recipient re-derives and checks. The version is covered here,
        which is what authenticates the freshness value itself.
        """
        w = self.wrapped_key
        return (
            _encode_int(self.version, 8)
            + _encode_str(self.document_id)
            + _encode_str(self.sender_username)
            + _encode_str(self.recipient_username)
            + _encode_point(w.ephemeral_public_key)
            + _encode_bytes(w.salt)
            + _encode_bytes(w.nonce)
            + _encode_bytes(w.encrypted_key)
            + _encode_bytes(w.tag)
            + _encode_int(self.timestamp, 8)
        )

    def to_bytes(self) -> bytes:
        if self.signature is None:
            raise ValueError("cannot serialize an unsigned ShareRecord")
        r, s = self.signature
        return self.signable_bytes() + _encode_int(r, SCALAR_LEN) + _encode_int(s, SCALAR_LEN)

    @classmethod
    def from_bytes(cls, data: bytes) -> ShareRecord:
        offset = 0
        version, offset = _decode_int(data, offset, 8)
        document_id, offset = _decode_str(data, offset)
        sender_username, offset = _decode_str(data, offset)
        recipient_username, offset = _decode_str(data, offset)
        ephemeral_public_key, offset = _decode_point(data, offset)
        salt, offset = _decode_bytes(data, offset)
        nonce, offset = _decode_bytes(data, offset)
        encrypted_key, offset = _decode_bytes(data, offset)
        tag, offset = _decode_bytes(data, offset)
        timestamp, offset = _decode_int(data, offset, 8)
        r, offset = _decode_int(data, offset, SCALAR_LEN)
        s, offset = _decode_int(data, offset, SCALAR_LEN)

        if offset != len(data):
            raise ValueError("trailing data after decoding ShareRecord")

        wrapped_key = WrappedDocumentKey(
            ephemeral_public_key=ephemeral_public_key,
            salt=salt,
            nonce=nonce,
            encrypted_key=encrypted_key,
            tag=tag,
        )

        return cls(
            version=version,
            document_id=document_id,
            sender_username=sender_username,
            recipient_username=recipient_username,
            wrapped_key=wrapped_key,
            timestamp=timestamp,
            signature=(r, s),
        )


# ============================================================
# create_share / open_share
# ============================================================

def create_share(
    document_key: bytes,
    document_id: str,
    sender_username: str,
    sender_ecdsa_private_key: int,
    recipient_certificate: UserCertificate,
    trusted_ca_public_key: Point,
    version: int,
    timestamp: int | None = None,
    *,
    expected_ca_issuer: str = DEFAULT_CA_NAME,
) -> ShareRecord:
    """
    Package `document_key` (the 16-byte Kdoc from key_wrap.py /
    Student 2's document-encryption code) for
    `recipient_certificate`'s owner.

    - sender_ecdsa_private_key: sender's long-term SIGNING key (from
      crypto/ecdsa.py). This is what actually proves sender_username
      is genuine -- key_wrap.py's wrapping step alone does not
      authenticate the sender.
    - recipient_certificate: MUST be the recipient's real, CA-issued
      UserCertificate. Verified against trusted_ca_public_key before
      its ECDH public key is trusted (Section 7.4).
    - version: caller-supplied, strictly increasing per document_id
      (freshness.VersionTracker rejects version <= the last one
      accepted for this document_id).
    """
    if len(document_key) != DOCUMENT_KEY_SIZE:
        raise ValueError(f"document_key must be exactly {DOCUMENT_KEY_SIZE} bytes")

    if timestamp is None:
        timestamp = int(time.time())

    if not verify_certificate(
        recipient_certificate,
        trusted_ca_public_key,
        expected_issuer=expected_ca_issuer,
    ):
        raise ValueError("recipient certificate failed CA verification")

    recipient_username = recipient_certificate.username

    wrapped_key = wrap_document_key(
        document_key,
        recipient_certificate.ecdh_public_key,
        sender_username,
        recipient_username,
        document_id,
        version,
    )

    record = ShareRecord(
        version=version,
        document_id=document_id,
        sender_username=sender_username,
        recipient_username=recipient_username,
        wrapped_key=wrapped_key,
        timestamp=timestamp,
        signature=None,
    )

    signature = ecdsa_sign(record.signable_bytes(), sender_ecdsa_private_key)
    return ShareRecord(**{**record.__dict__, "signature": signature})


def open_share(
    record: ShareRecord,
    sender_certificate: UserCertificate,
    recipient_username: str,
    recipient_ecdh_private_key: int,
    trusted_ca_public_key: Point,
    version_tracker: VersionTracker,
    *,
    expected_ca_issuer: str = DEFAULT_CA_NAME,
) -> bytes:
    """
    Verify and unwrap a ShareRecord, returning the original 16-byte
    document key (Kdoc).

    Raises ValueError for: wrong recipient, invalid sender
    certificate, invalid/missing signature, or failed unwrap (tampered
    data, or the record wasn't actually addressed to this recipient's
    private key). Raises freshness.ReplayError for a stale/replayed
    version -- this is checked LAST, only after a fully successful and
    authenticated unwrap, per freshness.VersionTracker's own
    documented contract ("call this only after GCM and signature
    verification").
    """
    if not verify_certificate(
        sender_certificate,
        trusted_ca_public_key,
        expected_username=record.sender_username,
        expected_issuer=expected_ca_issuer,
    ):
        raise ValueError("sender certificate failed CA verification")

    if record.recipient_username != recipient_username:
        raise ValueError("record is not addressed to this recipient")

    if record.signature is None:
        raise ValueError("share record is unsigned")

    # 1. Verify the sender's signature BEFORE trusting anything else,
    #    including the version field -- this is what actually
    #    authenticates the sender_username claim, since key_wrap.py's
    #    wrapping step does not.
    if not ecdsa_verify(record.signable_bytes(), record.signature, sender_certificate.ecdsa_public_key):
        raise ValueError("invalid signature on share record")

    # 2. Unwrap Kdoc via key_wrap.py. Any tampering with the wrapped
    #    fields is caught here by the GCM tag.
    try:
        document_key = unwrap_document_key(
            record.wrapped_key,
            recipient_ecdh_private_key,
            record.sender_username,
            record.recipient_username,
            record.document_id,
            record.version,
        )
    except AuthenticationError as exc:
        raise ValueError("failed to unwrap document key (tampered data or wrong recipient key)") from exc

    # 3. Freshness check LAST, only after both signature verification
    #    and a fully successful unwrap -- matching
    #    VersionTracker.check_and_record's documented contract. This
    #    also means a stale/replayed version never burns a NEWER
    #    counter value by accident, since we only get here once
    #    everything else has already succeeded.
    version_tracker.check_and_record(record.document_id.encode("utf-8"), record.version)

    return document_key
