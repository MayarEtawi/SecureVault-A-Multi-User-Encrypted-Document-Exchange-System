"""Validate and deterministically encode document metadata."""

import json


REQUIRED_FIELDS = {
    "document_id",
    "version",
    "owner_id",
    "filename",
    "file_type",
    "file_size",
    "timestamp",
}

STRING_FIELDS = (
    "document_id",
    "owner_id",
    "filename",
    "file_type",
    "timestamp",
)


def validate_metadata(metadata: dict) -> None:
    if not isinstance(metadata, dict):
        raise TypeError("Metadata must be a dictionary")

    if set(metadata) != REQUIRED_FIELDS:
        raise ValueError("Missing or unexpected metadata fields")

    for field in STRING_FIELDS:
        if not isinstance(metadata[field], str):
            raise TypeError(f"{field} must be a string")

        if metadata[field].strip() == "":
            raise ValueError(f"{field} must not be empty")

    if (
        not isinstance(metadata["version"], int)
        or isinstance(metadata["version"], bool)
    ):
        raise TypeError("version must be an integer")

    if metadata["version"] < 1:
        raise ValueError("version must be positive")

    if (
        not isinstance(metadata["file_size"], int)
        or isinstance(metadata["file_size"], bool)
    ):
        raise TypeError("file_size must be an integer")

    if metadata["file_size"] < 0:
        raise ValueError("file_size must not be negative")


def encode_metadata(metadata: dict) -> bytes:
    """Convert metadata into one canonical byte representation."""

    validate_metadata(metadata)

    text = json.dumps(
        metadata,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )

    return text.encode("utf-8")


def decode_metadata(data: bytes) -> dict:
    """Decode and validate canonical metadata bytes."""

    if not isinstance(data, bytes):
        raise TypeError("Metadata must be bytes")

    try:
        metadata = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise ValueError("Invalid metadata") from None

    validate_metadata(metadata)

    # Ensure that there is only one accepted encoding.
    if encode_metadata(metadata) != data:
        raise ValueError("Metadata is not canonically encoded")

    return metadata