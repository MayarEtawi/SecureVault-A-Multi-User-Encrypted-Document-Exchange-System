"""Integration tests for metadata, format and AES-GCM document protection."""

import copy

import pytest

from crypto.gcm import (
    encrypt_gcm,
    generate_document_key,
)

from documents.format import (
    MAGIC,
    METADATA_LENGTH_SIZE,
    build_aad,
    parse_document,
    serialize_document,
)

from documents.metadata import (
    decode_public,
    encode_private,
    encode_public,
)

from documents.protect import protect_document

from documents.verify import (
    DocumentVerificationError,
    verify_document,
)


# ============================================================
# Test helpers
# ============================================================

def make_metadata(file_size: int) -> dict:
    """Return valid public and private document metadata."""
    return {
        "document_id": "document-001",
        "owner_id": "layla",
        "version": 1,
        "filename": "thesis.pdf",
        "file_type": "application/pdf",
        "file_size": file_size,
        "timestamp": "2026-09-14T12:00:00Z",
    }


def flip_byte(data: bytes, position: int) -> bytes:
    """Return a copy of data with one bit changed."""
    changed = bytearray(data)
    changed[position] ^= 1
    return bytes(changed)


def protect_with_existing_key(
    plaintext: bytes,
    metadata: dict,
    document_key: bytes,
) -> bytes:
    """
    Protect a document using a supplied key.

    This helper is used only for controlled security tests.
    Production uploads should generate a fresh document key.
    """

    public_metadata = {
        "document_id": metadata["document_id"],
        "owner_id": metadata["owner_id"],
        "version": metadata["version"],
        "file_size": metadata["file_size"],
        "timestamp": metadata["timestamp"],
    }

    metadata_bytes = encode_public(public_metadata)

    private_payload = encode_private(
        metadata["filename"],
        metadata["file_type"],
        plaintext,
    )

    aad = build_aad(
        metadata_bytes,
        len(private_payload),
    )

    protected = encrypt_gcm(
        private_payload,
        aad,
        document_key,
    )

    return serialize_document(
        metadata_bytes,
        protected.nonce,
        protected.ciphertext,
        protected.tag,
    )


# ============================================================
# Successful protection and recovery
# ============================================================

def test_complete_document_round_trip():
    plaintext = b"Private thesis contents"
    metadata = make_metadata(len(plaintext))

    protected_document, document_key = protect_document(
        plaintext,
        metadata,
    )

    recovered_plaintext, recovered_metadata = verify_document(
        protected_document,
        document_key,
    )

    assert recovered_plaintext == plaintext
    assert recovered_metadata == metadata


def test_empty_document_round_trip():
    plaintext = b""
    metadata = make_metadata(0)

    protected_document, document_key = protect_document(
        plaintext,
        metadata,
    )

    recovered_plaintext, recovered_metadata = verify_document(
        protected_document,
        document_key,
    )

    assert recovered_plaintext == b""
    assert recovered_metadata == metadata


def test_binary_document_round_trip():
    plaintext = bytes(range(256))
    metadata = make_metadata(len(plaintext))

    protected_document, document_key = protect_document(
        plaintext,
        metadata,
    )

    recovered_plaintext, recovered_metadata = verify_document(
        protected_document,
        document_key,
    )

    assert recovered_plaintext == plaintext
    assert recovered_metadata == metadata


def test_unicode_filename_round_trip():
    plaintext = b"Unicode filename test"

    metadata = make_metadata(len(plaintext))
    metadata["filename"] = "مشروع التخرج.pdf"
    metadata["file_type"] = "application/pdf"

    protected_document, document_key = protect_document(
        plaintext,
        metadata,
    )

    recovered_plaintext, recovered_metadata = verify_document(
        protected_document,
        document_key,
    )

    assert recovered_plaintext == plaintext
    assert recovered_metadata["filename"] == "مشروع التخرج.pdf"
    assert recovered_metadata["file_type"] == "application/pdf"


# ============================================================
# Metadata visibility and privacy
# ============================================================

def test_only_public_metadata_is_stored_in_clear():
    plaintext = b"Private thesis contents"
    metadata = make_metadata(len(plaintext))

    protected_document, _ = protect_document(
        plaintext,
        metadata,
    )

    parsed = parse_document(protected_document)
    public_metadata = decode_public(parsed["metadata"])

    assert public_metadata == {
        "document_id": "document-001",
        "owner_id": "layla",
        "version": 1,
        "file_size": len(plaintext),
        "timestamp": "2026-09-14T12:00:00Z",
    }

    assert "filename" not in public_metadata
    assert "file_type" not in public_metadata


def test_filename_file_type_and_content_are_encrypted():
    plaintext = b"Private thesis contents"
    metadata = make_metadata(len(plaintext))

    protected_document, _ = protect_document(
        plaintext,
        metadata,
    )

    filename_bytes = metadata["filename"].encode("utf-8")
    file_type_bytes = metadata["file_type"].encode("utf-8")

    assert filename_bytes not in protected_document
    assert file_type_bytes not in protected_document
    assert plaintext not in protected_document


def test_ciphertext_includes_private_metadata():
    plaintext = b"Private thesis contents"
    metadata = make_metadata(len(plaintext))

    protected_document, _ = protect_document(
        plaintext,
        metadata,
    )

    parsed = parse_document(protected_document)

    # The encrypted payload contains:
    #
    # [filename length]
    # || [filename]
    # || [file-type length]
    # || [file type]
    # || [document contents]
    #
    # Therefore, the ciphertext is larger than the document contents.
    assert len(parsed["ciphertext"]) > len(plaintext)


# ============================================================
# Incorrect key
# ============================================================

def test_wrong_key_is_rejected():
    plaintext = b"Private document"
    metadata = make_metadata(len(plaintext))

    protected_document, document_key = protect_document(
        plaintext,
        metadata,
    )

    # Create another valid 16-byte key.
    wrong_key = bytes(
        byte ^ 1
        for byte in document_key
    )

    with pytest.raises(
        DocumentVerificationError,
        match="^Document verification failed$",
    ):
        verify_document(
            protected_document,
            wrong_key,
        )


def test_invalid_key_length_is_rejected():
    plaintext = b"Private document"
    metadata = make_metadata(len(plaintext))

    protected_document, _ = protect_document(
        plaintext,
        metadata,
    )

    wrong_key = b"short-key"

    with pytest.raises(
        DocumentVerificationError,
        match="^Document verification failed$",
    ):
        verify_document(
            protected_document,
            wrong_key,
        )


# ============================================================
# Ciphertext modification
# ============================================================

def test_ciphertext_tampering_is_rejected():
    plaintext = b"Private document"
    metadata = make_metadata(len(plaintext))

    protected_document, document_key = protect_document(
        plaintext,
        metadata,
    )

    parsed = parse_document(protected_document)

    ciphertext_start = (
        len(parsed["aad"])
        + len(parsed["nonce"])
    )

    tampered_document = flip_byte(
        protected_document,
        ciphertext_start,
    )

    with pytest.raises(
        DocumentVerificationError,
        match="^Document verification failed$",
    ):
        verify_document(
            tampered_document,
            document_key,
        )


def test_added_ciphertext_bytes_with_updated_length_are_rejected():
    plaintext = b"Private document"
    metadata = make_metadata(len(plaintext))

    protected_document, document_key = protect_document(
        plaintext,
        metadata,
    )

    parsed = parse_document(protected_document)

    # Trudy adds bytes to the ciphertext.
    changed_ciphertext = (
        parsed["ciphertext"]
        + b"malicious-data"
    )

    # serialize_document creates a structurally correct document
    # containing the new ciphertext length.
    #
    # However, Trudy cannot calculate a valid new GCM tag.
    tampered_document = serialize_document(
        parsed["metadata"],
        parsed["nonce"],
        changed_ciphertext,
        parsed["tag"],
    )

    with pytest.raises(
        DocumentVerificationError,
        match="^Document verification failed$",
    ):
        verify_document(
            tampered_document,
            document_key,
        )


def test_removed_ciphertext_bytes_with_updated_length_are_rejected():
    plaintext = b"Private document"
    metadata = make_metadata(len(plaintext))

    protected_document, document_key = protect_document(
        plaintext,
        metadata,
    )

    parsed = parse_document(protected_document)

    assert len(parsed["ciphertext"]) > 1

    # Trudy removes one byte and updates the ciphertext length,
    # but keeps the old GCM tag.
    changed_ciphertext = parsed["ciphertext"][:-1]

    tampered_document = serialize_document(
        parsed["metadata"],
        parsed["nonce"],
        changed_ciphertext,
        parsed["tag"],
    )

    with pytest.raises(
        DocumentVerificationError,
        match="^Document verification failed$",
    ):
        verify_document(
            tampered_document,
            document_key,
        )


def test_encrypted_filename_tampering_is_rejected():
    plaintext = b"Private document"
    metadata = make_metadata(len(plaintext))

    protected_document, document_key = protect_document(
        plaintext,
        metadata,
    )

    parsed = parse_document(protected_document)

    ciphertext_start = (
        len(parsed["aad"])
        + len(parsed["nonce"])
    )

    # The first two encrypted payload bytes contain the filename
    # length. The following bytes contain the filename.
    tampered_document = flip_byte(
        protected_document,
        ciphertext_start + 2,
    )

    with pytest.raises(
        DocumentVerificationError,
        match="^Document verification failed$",
    ):
        verify_document(
            tampered_document,
            document_key,
        )


# ============================================================
# Tag substitution
# ============================================================

def test_tag_from_another_document_is_rejected():
    document_key = generate_document_key()

    plaintext_a = b"Document A contents"
    metadata_a = make_metadata(len(plaintext_a))
    metadata_a["document_id"] = "document-A"
    metadata_a["owner_id"] = "layla"

    plaintext_b = b"Document B contents"
    metadata_b = make_metadata(len(plaintext_b))
    metadata_b["document_id"] = "document-B"
    metadata_b["owner_id"] = "omar"

    # Deliberately use the same key for both documents.
    # This proves that a tag is tied to its ciphertext,
    # nonce and AAD, not only to the AES key.
    document_a = protect_with_existing_key(
        plaintext_a,
        metadata_a,
        document_key,
    )

    document_b = protect_with_existing_key(
        plaintext_b,
        metadata_b,
        document_key,
    )

    # Confirm that both original documents are valid.
    recovered_a, recovered_metadata_a = verify_document(
        document_a,
        document_key,
    )

    recovered_b, recovered_metadata_b = verify_document(
        document_b,
        document_key,
    )

    assert recovered_a == plaintext_a
    assert recovered_metadata_a == metadata_a
    assert recovered_b == plaintext_b
    assert recovered_metadata_b == metadata_b

    parsed_a = parse_document(document_a)
    parsed_b = parse_document(document_b)

    # Trudy copies Document A's valid tag and attaches it
    # to Document B.
    tampered_document_b = serialize_document(
        parsed_b["metadata"],
        parsed_b["nonce"],
        parsed_b["ciphertext"],
        parsed_a["tag"],
    )

    with pytest.raises(
        DocumentVerificationError,
        match="^Document verification failed$",
    ):
        verify_document(
            tampered_document_b,
            document_key,
        )


# ============================================================
# Public metadata modification
# ============================================================

def test_public_metadata_tampering_is_rejected():
    plaintext = b"Private document"
    metadata = make_metadata(len(plaintext))

    protected_document, document_key = protect_document(
        plaintext,
        metadata,
    )

    # Stored format begins with:
    #
    # 4-byte MAGIC
    # || 4-byte metadata length
    # || public metadata
    metadata_start = (
        len(MAGIC)
        + METADATA_LENGTH_SIZE
    )

    tampered_document = flip_byte(
        protected_document,
        metadata_start,
    )

    with pytest.raises(
        DocumentVerificationError,
        match="^Document verification failed$",
    ):
        verify_document(
            tampered_document,
            document_key,
        )


# ============================================================
# Nonce and tag modification
# ============================================================

def test_nonce_tampering_is_rejected():
    plaintext = b"Private document"
    metadata = make_metadata(len(plaintext))

    protected_document, document_key = protect_document(
        plaintext,
        metadata,
    )

    parsed = parse_document(protected_document)
    nonce_start = len(parsed["aad"])

    tampered_document = flip_byte(
        protected_document,
        nonce_start,
    )

    with pytest.raises(
        DocumentVerificationError,
        match="^Document verification failed$",
    ):
        verify_document(
            tampered_document,
            document_key,
        )


def test_tag_tampering_is_rejected():
    plaintext = b"Private document"
    metadata = make_metadata(len(plaintext))

    protected_document, document_key = protect_document(
        plaintext,
        metadata,
    )

    tampered_document = flip_byte(
        protected_document,
        len(protected_document) - 1,
    )

    with pytest.raises(
        DocumentVerificationError,
        match="^Document verification failed$",
    ):
        verify_document(
            tampered_document,
            document_key,
        )


# ============================================================
# Malformed stored-object tests
# ============================================================

def test_extra_data_is_rejected():
    plaintext = b"Private document"
    metadata = make_metadata(len(plaintext))

    protected_document, document_key = protect_document(
        plaintext,
        metadata,
    )

    with pytest.raises(
        DocumentVerificationError,
        match="^Document verification failed$",
    ):
        verify_document(
            protected_document + b"extra",
            document_key,
        )


def test_truncated_document_is_rejected():
    plaintext = b"Private document"
    metadata = make_metadata(len(plaintext))

    protected_document, document_key = protect_document(
        plaintext,
        metadata,
    )

    with pytest.raises(
        DocumentVerificationError,
        match="^Document verification failed$",
    ):
        verify_document(
            protected_document[:-1],
            document_key,
        )


def test_invalid_magic_is_rejected():
    plaintext = b"Private document"
    metadata = make_metadata(len(plaintext))

    protected_document, document_key = protect_document(
        plaintext,
        metadata,
    )

    tampered_document = flip_byte(
        protected_document,
        0,
    )

    with pytest.raises(
        DocumentVerificationError,
        match="^Document verification failed$",
    ):
        verify_document(
            tampered_document,
            document_key,
        )


# ============================================================
# Metadata validation
# ============================================================

def test_declared_file_size_must_match_plaintext():
    plaintext = b"Private document"
    metadata = make_metadata(len(plaintext) + 1)

    with pytest.raises(
        ValueError,
        match="file_size does not match",
    ):
        protect_document(
            plaintext,
            metadata,
        )


@pytest.mark.parametrize(
    "missing_field",
    [
        "document_id",
        "owner_id",
        "version",
        "filename",
        "file_type",
        "file_size",
        "timestamp",
    ],
)
def test_missing_metadata_field_is_rejected(missing_field):
    plaintext = b"Private document"
    metadata = make_metadata(len(plaintext))

    del metadata[missing_field]

    with pytest.raises(
        ValueError,
        match="Missing or unexpected metadata fields",
    ):
        protect_document(
            plaintext,
            metadata,
        )


def test_unexpected_metadata_field_is_rejected():
    plaintext = b"Private document"
    metadata = make_metadata(len(plaintext))

    metadata["unexpected"] = "value"

    with pytest.raises(
        ValueError,
        match="Missing or unexpected metadata fields",
    ):
        protect_document(
            plaintext,
            metadata,
        )


@pytest.mark.parametrize(
    "field",
    [
        "filename",
        "file_type",
    ],
)
def test_empty_private_metadata_is_rejected(field):
    plaintext = b"Private document"
    metadata = make_metadata(len(plaintext))

    metadata[field] = ""

    with pytest.raises(
        ValueError,
        match=f"{field} must not be empty",
    ):
        protect_document(
            plaintext,
            metadata,
        )


# ============================================================
# Key and nonce uniqueness
# ============================================================

def test_new_uploads_receive_different_keys_and_nonces():
    plaintext = b"same document"
    metadata = make_metadata(len(plaintext))

    first_document, first_key = protect_document(
        plaintext,
        copy.deepcopy(metadata),
    )

    second_document, second_key = protect_document(
        plaintext,
        copy.deepcopy(metadata),
    )

    first_parsed = parse_document(first_document)
    second_parsed = parse_document(second_document)

    assert first_key != second_key
    assert first_parsed["nonce"] != second_parsed["nonce"]
    assert first_document != second_document