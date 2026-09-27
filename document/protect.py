"""Encrypt and authenticate a document using AES-128-GCM."""

"""
Module summary:
- protect_document(): Takes plain file content and metadata dict, builds clear AAD header,
  encrypts private data with AES-GCM, generates new key, and packs everything to binary format.
"""

from crypto.gcm import (
    encrypt_gcm,
    generate_document_key,
)

from .format import (
    MAX_CIPHERTEXT_SIZE,
    build_aad,
    serialize_document,
)

from .metadata import (
    PUBLIC_FIELDS,
    encode_private,
    encode_public,
)

# Private fields that must be hidden inside encrypted payload
PRIVATE_FIELDS = {"file_type"}

# Combine public and private set to check all required keys
ALL_METADATA_FIELDS = PUBLIC_FIELDS | PRIVATE_FIELDS


def protect_document(plaintext: bytes, metadata: dict) -> tuple[bytes, bytes]:
    """
    Protect a new document for safe storage.

    Public metadata stays readable as AAD header but cannot be modified.
    File type and file contents are encrypted into ciphertext.

    Returns:
        serialized_document: Packed binary payload for sending to server.
        document_key: Secret key that stays on client side.
    """

    # Make sure plaintext input is bytes type
    if not isinstance(plaintext, bytes):
        raise TypeError("Plaintext must be bytes")

    # Make sure metadata is dictionary
    if not isinstance(metadata, dict):
        raise TypeError("Metadata must be a dictionary")

    # Check dict keys equal all required public and private fields
    if set(metadata) != ALL_METADATA_FIELDS:
        raise ValueError("Missing or unexpected metadata fields")

    # Make sure file size metadata matches actual plaintext length
    if metadata["file_size"] != len(plaintext):
        raise ValueError("file_size does not match the plaintext")

    # Extract public fields to build clear text header
    public_metadata = {
        "document_id": metadata["document_id"],
        "owner_id": metadata["owner_id"],
        "version": metadata["version"],
        "filename": metadata["filename"],
        "file_size": metadata["file_size"],
        "timestamp": metadata["timestamp"],
    }

    # Pack public header dictionary into byte format
    metadata_bytes = encode_public(public_metadata)

    # Pack secret file_type string together with plaintext content
    private_payload = encode_private(metadata["file_type"], plaintext)

    # Check payload size is not bigger than max allowed limit
    if len(private_payload) > MAX_CIPHERTEXT_SIZE:
        raise ValueError("Encrypted payload is too large")

    # Generate new random key for this document encryption
    document_key = generate_document_key()

    # Build AAD byte array using metadata bytes and payload size
    aad = build_aad(metadata_bytes, len(private_payload))

    # Encrypt private payload with AES-GCM mode using key and AAD
    protected = encrypt_gcm(private_payload, aad, document_key)

    # Put all output fields together into final binary stream
    serialized_document = serialize_document(
        metadata_bytes,
        protected.nonce,
        protected.ciphertext,
        protected.tag,
    )

    return serialized_document, document_key
