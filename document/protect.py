"""Encrypt and authenticate a document using AES-128-GCM."""

from crypto.gcm import (encrypt_gcm,generate_document_key,)

from .format import (MAX_CIPHERTEXT_SIZE,build_aad,serialize_document,)

from .metadata import (PUBLIC_FIELDS,encode_private,encode_public,)


PRIVATE_FIELDS = {"filename", "file_type"}
ALL_METADATA_FIELDS = PUBLIC_FIELDS | PRIVATE_FIELDS


def protect_document(plaintext: bytes,metadata: dict,) -> tuple[bytes, bytes]:
    """
    Protect a new document.

    Public metadata is authenticated as AES-GCM AAD.
    The filename, file type and document contents are encrypted.

    Returns:
        protected_document:
            Safe to store on the untrusted server.

        document_key:
            Must remain on the trusted client and later be
            wrapped for every authorized recipient.
    """

    if not isinstance(plaintext, bytes):
        raise TypeError("Plaintext must be bytes")

    if not isinstance(metadata, dict):
        raise TypeError("Metadata must be a dictionary")

    if set(metadata) != ALL_METADATA_FIELDS:
        raise ValueError("Missing or unexpected metadata fields")

    if metadata["file_size"] != len(plaintext):
        raise ValueError(
            "file_size does not match the plaintext"
        )

    # Only these fields remain visible to the server.
    public_metadata = {
        "document_id": metadata["document_id"],
        "owner_id": metadata["owner_id"],
        "version": metadata["version"],
        "file_size": metadata["file_size"],
        "timestamp": metadata["timestamp"],
    }

    metadata_bytes = encode_public(public_metadata)

    # Filename and file type become part of the encrypted plaintext.
    private_payload = encode_private(
        metadata["filename"],
        metadata["file_type"],
        plaintext,
    )

    if len(private_payload) > MAX_CIPHERTEXT_SIZE:
        raise ValueError("Encrypted payload is too large")

    # Generate a fresh random AES-128 document key.
    document_key = generate_document_key()

    # GCM ciphertext has the same length as private_payload.
    aad = build_aad(metadata_bytes,len(private_payload),)

    protected = encrypt_gcm(private_payload,aad,document_key,)

    serialized_document = serialize_document(
        metadata_bytes,
        protected.nonce,
        protected.ciphertext,
        protected.tag,
    )

    return serialized_document, document_key
