"""Length-prefixed binary format for AES-GCM protected documents."""


MAGIC = b"SGC2"

NONCE_SIZE = 12
TAG_SIZE = 16

METADATA_LENGTH_SIZE = 4
CIPHERTEXT_LENGTH_SIZE = 8

MAX_METADATA_SIZE = 64 * 1024
MAX_CIPHERTEXT_SIZE = 2 * 1024 * 1024 * 1024


# Stored format:
#
# MAGIC
# || METADATA_LENGTH
# || METADATA
# || CIPHERTEXT_LENGTH
# || NONCE
# || CIPHERTEXT
# || GCM_TAG


def build_aad(metadata: bytes, ciphertext_length: int) -> bytes:
    """Build the clear header authenticated as GCM AAD."""

    if not isinstance(metadata, bytes):
        raise TypeError("Metadata must be bytes")

    if (
        not isinstance(ciphertext_length, int)
        or isinstance(ciphertext_length, bool)
    ):
        raise TypeError("Ciphertext length must be an integer")

    if len(metadata) > MAX_METADATA_SIZE:
        raise ValueError("Metadata is too large")

    if (
        ciphertext_length < 0
        or ciphertext_length > MAX_CIPHERTEXT_SIZE
    ):
        raise ValueError("Ciphertext length is invalid")

    return (
        MAGIC
        + len(metadata).to_bytes(METADATA_LENGTH_SIZE, "big")
        + metadata
        + ciphertext_length.to_bytes(CIPHERTEXT_LENGTH_SIZE, "big")
    )


def serialize_document(
    metadata: bytes,
    nonce: bytes,
    ciphertext: bytes,
    tag: bytes,
) -> bytes:
    """Combine all protected-document fields into one binary object."""

    fields = (metadata, nonce, ciphertext, tag)

    if not all(isinstance(value, bytes) for value in fields):
        raise TypeError("Document fields must be bytes")

    if len(nonce) != NONCE_SIZE:
        raise ValueError("Nonce must be 12 bytes")

    if len(tag) != TAG_SIZE:
        raise ValueError("GCM tag must be 16 bytes")

    aad = build_aad(metadata, len(ciphertext))

    return aad + nonce + ciphertext + tag


def parse_document(data: bytes) -> dict:
    """Parse a serialized protected document safely."""

    if not isinstance(data, bytes):
        raise TypeError("Protected document must be bytes")

    minimum_size = (
        len(MAGIC)
        + METADATA_LENGTH_SIZE
        + CIPHERTEXT_LENGTH_SIZE
        + NONCE_SIZE
        + TAG_SIZE
    )

    if len(data) < minimum_size:
        raise ValueError("Protected document is too short")

    position = 0

    # Read and verify the magic bytes.
    if data[position:position + len(MAGIC)] != MAGIC:
        raise ValueError("Invalid magic")

    position += len(MAGIC)

    # Read the metadata length.
    metadata_length = int.from_bytes(
        data[position:position + METADATA_LENGTH_SIZE],
        "big",
    )

    position += METADATA_LENGTH_SIZE

    if metadata_length > MAX_METADATA_SIZE:
        raise ValueError("Metadata is too large")

    metadata_end = position + metadata_length

    # Ensure all required fields still fit inside the object.
    required_after_metadata = (
        CIPHERTEXT_LENGTH_SIZE
        + NONCE_SIZE
        + TAG_SIZE
    )

    if metadata_end + required_after_metadata > len(data):
        raise ValueError("Invalid metadata length")

    metadata = data[position:metadata_end]
    position = metadata_end

    # Read the ciphertext length.
    ciphertext_length = int.from_bytes(
        data[position:position + CIPHERTEXT_LENGTH_SIZE],
        "big",
    )

    position += CIPHERTEXT_LENGTH_SIZE

    if ciphertext_length > MAX_CIPHERTEXT_SIZE:
        raise ValueError("Ciphertext is too large")

    # Everything before the nonce is authenticated as AAD.
    aad_end = position

    nonce = data[position:position + NONCE_SIZE]
    position += NONCE_SIZE

    ciphertext_end = position + ciphertext_length

    # Reject missing bytes and unexpected extra bytes.
    if ciphertext_end + TAG_SIZE != len(data):
        raise ValueError(
            "Invalid ciphertext length or extra data"
        )

    ciphertext = data[position:ciphertext_end]
    tag = data[ciphertext_end:]

    return {
        "metadata": metadata,
        "nonce": nonce,
        "ciphertext": ciphertext,
        "tag": tag,
        "aad": data[:aad_end],
    }
