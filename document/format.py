"""Length-prefixed binary format for AES-GCM protected documents.

This module provides binary serialization and parsing for documents protected with AES-GCM encryption.

Overall functionality:
1. build_aad(): Constructs the cleartext binary header (magic bytes + metadata + length fields) 
   that acts as Additional Authenticated Data (AAD) during AES-GCM encryption/decryption.
2. serialize_document(): Combines the AAD header, nonce, ciphertext, and authentication tag into 
   a single formatted byte stream for storage or transmission.
3. parse_document(): Unpacks a serialized byte stream, validates magic headers and field bounds, 
   and extracts the metadata, nonce, ciphertext, tag, and AAD for decryption.

Binary Layout:
+--------+-----------------+----------+-------------------+-------+------------+---------+
| MAGIC  | METADATA_LENGTH | METADATA | CIPHERTEXT_LENGTH | NONCE | CIPHERTEXT | GCM_TAG |
| 4B     | 4B              | Variable | 8B                | 12B   | Variable   | 16B     |
+--------+-----------------+----------+-------------------+-------+------------+---------+
"""

# ==============================================================================
# CONSTANTS & CONFIGURATION
# ==============================================================================

MAGIC = b"SGC2"

# Cryptographic component sizes (in bytes)
NONCE_SIZE = 12
TAG_SIZE = 16

# Header field length representations (in bytes)
METADATA_LENGTH_SIZE = 4
CIPHERTEXT_LENGTH_SIZE = 8

# Bound constraints for safety validation
MAX_METADATA_SIZE = 64 * 1024               # Max 64 KB
MAX_CIPHERTEXT_SIZE = 2 * 1024 * 1024 * 1024 # Max 2 GB


# ==============================================================================
# SERIALIZATION & HEADER BUILDING
# ==============================================================================

def build_aad(metadata: bytes, ciphertext_length: int) -> bytes:
    """Construct the cleartext binary header used as GCM Additional Authenticated Data (AAD)."""
    # Type validations
    if not isinstance(metadata, bytes):
        raise TypeError("Metadata must be bytes")
    if not isinstance(ciphertext_length, int) or isinstance(ciphertext_length, bool):
        raise TypeError("Ciphertext length must be an integer")

    # Bound checks
    if len(metadata) > MAX_METADATA_SIZE:
        raise ValueError("Metadata is too large")
    if ciphertext_length < 0 or ciphertext_length > MAX_CIPHERTEXT_SIZE:
        raise ValueError("Ciphertext length is invalid")

    # Binary assembly
    metadata_len_bytes = len(metadata).to_bytes(METADATA_LENGTH_SIZE, "big")
    ciphertext_len_bytes = ciphertext_length.to_bytes(CIPHERTEXT_LENGTH_SIZE, "big")

    return MAGIC + metadata_len_bytes + metadata + ciphertext_len_bytes


def serialize_document(metadata: bytes, nonce: bytes, ciphertext: bytes, tag: bytes) -> bytes:
    """Combine all protected-document components into a single binary payload."""
    fields = (metadata, nonce, ciphertext, tag)
    if not all(isinstance(value, bytes) for value in fields):
        raise TypeError("Document fields must be bytes")

    # Validate fixed-length crypto fields
    if len(nonce) != NONCE_SIZE:
        raise ValueError("Nonce must be 12 bytes")
    if len(tag) != TAG_SIZE:
        raise ValueError("GCM tag must be 16 bytes")

    # Build AAD header and assemble complete stream
    aad = build_aad(metadata, len(ciphertext))
    return aad + nonce + ciphertext + tag


# ==============================================================================
# DESERIALIZATION & PARSING
# ==============================================================================

def parse_document(data: bytes) -> dict:
    """Unpack and validate a serialized protected document stream.

    Returns:
        dict: Containing 'metadata', 'nonce', 'ciphertext', 'tag', and 'aad'.
    """
    if not isinstance(data, bytes):
        raise TypeError("Protected document must be bytes")

    # Enforce minimum payload length to avoid out-of-bounds indexing
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

    # 1. Validate Magic Header
    if data[position:position + len(MAGIC)] != MAGIC:
        raise ValueError("Invalid magic header")
    position += len(MAGIC)

    # 2. Extract and validate Metadata
    metadata_length = int.from_bytes(data[position:position + METADATA_LENGTH_SIZE], "big")
    position += METADATA_LENGTH_SIZE

    if metadata_length > MAX_METADATA_SIZE:
        raise ValueError("Metadata is too large")

    metadata_end = position + metadata_length
    required_after_metadata = CIPHERTEXT_LENGTH_SIZE + NONCE_SIZE + TAG_SIZE

    if metadata_end + required_after_metadata > len(data):
        raise ValueError("Invalid metadata length")

    metadata = data[position:metadata_end]
    position = metadata_end

    # 3. Extract Ciphertext Length & Mark End of AAD
    ciphertext_length = int.from_bytes(data[position:position + CIPHERTEXT_LENGTH_SIZE], "big")
    position += CIPHERTEXT_LENGTH_SIZE

    if ciphertext_length > MAX_CIPHERTEXT_SIZE:
        raise ValueError("Ciphertext is too large")

    aad_end = position  # AAD includes MAGIC + METADATA_LENGTH + METADATA + CIPHERTEXT_LENGTH

    # 4. Extract Nonce, Ciphertext, and Authentication Tag
    nonce = data[position:position + NONCE_SIZE]
    position += NONCE_SIZE

    ciphertext_end = position + ciphertext_length
    if ciphertext_end + TAG_SIZE != len(data):
        raise ValueError("Invalid ciphertext length or trailing extra data")

    ciphertext = data[position:ciphertext_end]
    tag = data[ciphertext_end:]

    return {
        "metadata": metadata,
        "nonce": nonce,
        "ciphertext": ciphertext,
        "tag": tag,
        "aad": data[:aad_end]
    }
