"""Encrypt and authenticate a document using AES-128-GCM."""

from crypto.gcm import (
    encrypt_gcm,
    generate_document_key,
)

from .format import (
    MAX_CIPHERTEXT_SIZE,
    build_aad,
    serialize_document,
)

from .metadata import encode_metadata


def protect_document(
    plaintext: bytes,
    metadata: dict,
) -> tuple[bytes, bytes]:
    """
    Protect a new document.

    Returns:
        protected_document:
            Safe to store on the untrusted server.

        document_key:
            Must remain on the trusted client and later be
            wrapped for every authorized recipient.
    """

    if not isinstance(plaintext, bytes):
        raise TypeError("Plaintext must be bytes")

    if len(plaintext) > MAX_CIPHERTEXT_SIZE:
        raise ValueError("Plaintext is too large")

    metadata_bytes = encode_metadata(metadata)

    if metadata["file_size"] != len(plaintext):
        raise ValueError(
            "file_size does not match the plaintext"
        )

    # Generate a fresh random AES-128 key.
    document_key = generate_document_key()

    # GCM ciphertext has the same length as the plaintext.
    aad = build_aad(
        metadata_bytes,
        len(plaintext),
    )

    # encrypt_gcm generates a fresh 12-byte nonce.
    protected = encrypt_gcm(
        plaintext,
        aad,
        document_key,
    )

    serialized_document = serialize_document(
        metadata_bytes,
        protected.nonce,
        protected.ciphertext,
        protected.tag,
    )

    return serialized_document, document_key