"""Encode and decode public and private document metadata."""
#allows us to convert numbers into bytes 
#I->Unsigned 4-byte integer Q->Unsigned 8-byte integer H->Unsigned 2-byte integer
#> = big-endian byte order
import struct

# These fields remain visible to the server.
# AES-GCM authenticates them as AAD, so they cannot be modified.
PUBLIC_FIELDS = {
    "document_id",
    "owner_id",
    "version",
    "file_size",
    "timestamp",
}

# A string length is stored in two bytes.
# Two bytes can represent values from 0 to 65535.
MAX_STRING_SIZE = 65535
STRING_LENGTH_SIZE = 2


# ============================================================
# String encoding and decoding
# ============================================================
#convert a string into bytes
def pack_string(value: str, field_name: str) -> bytes:
    """
    Convert a string into:

        [2-byte length][UTF-8 string bytes]

    Example:
        "pdf" becomes:

        00 03 70 64 66
        ----- --------
        length  "pdf"
    """

    # The input must be a Python string.
    if not isinstance(value, str):
        raise TypeError(f"{field_name} must be a string")

    # Reject empty strings and strings containing only spaces.
    if value.strip() == "":
        raise ValueError(f"{field_name} must not be empty")

  
    # This is safe. It allows English, Arabic and other
    # Unicode characters to be stored into bytes
    encoded_value = value.encode("utf-8")

    # The length must fit inside two bytes.
    if len(encoded_value) > MAX_STRING_SIZE:
        raise ValueError(f"{field_name} is too long")

    #stores the length of the string in two bytes, followed by the UTF-8 encoded string itself.
    encoded_length = struct.pack(">H", len(encoded_value))
    return encoded_length + encoded_value

#reverse the pack_string()
def read_string(data: bytes, position: int) -> tuple[str, int]:
    """
    Read one string stored as:

        [2-byte length][UTF-8 string bytes]

    Returns:
        decoded string
        position immediately after the string
    """

    # We need two bytes to read the string length.
    if position + STRING_LENGTH_SIZE > len(data):
        raise ValueError("Invalid encoded string")

    # Read the unsigned two-byte length.
    string_length = struct.unpack_from(">H",data,position,)[0]#since it might return a tuple (3,) ->[0]->3

    # Move past the two length bytes.
    position += STRING_LENGTH_SIZE

    # Calculate where the string should end.
    string_end = position + string_length

    # Reject the data if it claims to contain more bytes
    # than are actually available.
    if string_end > len(data):
        raise ValueError("Invalid encoded string")

    string_bytes = data[position:string_end]

    try:
        decoded_string = string_bytes.decode("utf-8")
    except UnicodeDecodeError:
        raise ValueError("Invalid UTF-8 string") from None

    return decoded_string, string_end


# ============================================================
# Integer validation
# ============================================================

def check_integer(value,field_name: str,minimum: int,maximum: int,) -> None:
    """Check that a metadata value is an integer in the allowed range."""
    # In Python, bool is a subclass of int.
    # Therefore, True and False must be rejected explicitly.
    if not isinstance(value, int) or isinstance(value, bool):
        raise TypeError(f"{field_name} must be an integer")
    if value < minimum or value > maximum:
        raise ValueError(f"{field_name} is out of range")


# ============================================================
# Public metadata
# ============================================================

def encode_public(metadata: dict) -> bytes:
    """
    Encode public metadata.

    This data remains readable by the server, but it is
    authenticated as AES-GCM AAD.

    Format:

        [document ID]
        [owner ID]
        [4-byte version]
        [8-byte file size]
        [timestamp]
    """

    if not isinstance(metadata, dict):
        raise TypeError("Metadata must be a dictionary")

    # Require exactly the expected public fields.
    # This prevents private fields such as filename from
    # accidentally being stored publicly.
    if set(metadata.keys()) != PUBLIC_FIELDS:
        raise ValueError(
            "Missing or unexpected public metadata fields"
        )

    # Version is stored using four bytes.
    check_integer(metadata["version"],"version",1,2**32 - 1,)

    # File size is stored using eight bytes.
    check_integer(metadata["file_size"],"file_size",0,2**64 - 1,)

    document_id_bytes = pack_string(metadata["document_id"],"document_id",)

    owner_id_bytes = pack_string(metadata["owner_id"],"owner_id",)

    # >I means an unsigned 4-byte integer.
    version_bytes = struct.pack(">I",metadata["version"],)

    # >Q means an unsigned 8-byte integer.
    file_size_bytes = struct.pack(">Q",metadata["file_size"],)

    timestamp_bytes = pack_string(metadata["timestamp"],"timestamp",)

    return (document_id_bytes+ owner_id_bytes+ version_bytes+ file_size_bytes+ timestamp_bytes)


def decode_public(data: bytes) -> dict:
    """Decode public metadata bytes back into a dictionary."""

    if not isinstance(data, bytes):
        raise TypeError("Public metadata must be bytes")

    position = 0

    # Read the first two length-prefixed strings.
    document_id, position = read_string(data,position,)

    owner_id, position = read_string(data,position,)

    # Version needs four bytes and file size needs eight.
    #
    # Total required:
    #     4 + 8 = 12 bytes
    if position + 12 > len(data):
        raise ValueError("Public metadata is incomplete")

    version = struct.unpack_from(">I",data,position,)[0]

    position += 4

    file_size = struct.unpack_from(">Q",data,position,)[0]

    position += 8

    timestamp, position = read_string(data,position,)

    # No unexplained bytes should remain.
    if position != len(data):
        raise ValueError("Public metadata contains extra data")

    metadata = {
        "document_id": document_id,
        "owner_id": owner_id,
        "version": version,
        "file_size": file_size,
        "timestamp": timestamp,
    }

    # Validate the decoded values.
    #
    # It also confirms that the input uses our one accepted
    # encoding format.
    if encode_public(metadata) != data:
        raise ValueError("Invalid public metadata")

    return metadata


# ============================================================
# Private metadata and document contents
# ============================================================

def encode_private(filename: str,file_type: str,content: bytes,) -> bytes:
    """
    Build the private payload encrypted by AES-GCM.

    Format:

        [filename]
        [file type]
        [document contents]

    The document content does not need a length because it
    occupies all remaining bytes.
    """

    if not isinstance(content, bytes):
        raise TypeError("Document content must be bytes")

    filename_bytes = pack_string(filename,"filename",)

    file_type_bytes = pack_string(file_type,"file_type",)

    return (filename_bytes+ file_type_bytes+ content)


def decode_private(payload: bytes,) -> tuple[str, str, bytes]:
    """
    Decode the private payload after AES-GCM verification.

    Important:
        Do not call this function before the GCM tag has
        been verified successfully.
    """

    if not isinstance(payload, bytes):
        raise TypeError("Private payload must be bytes")

    position = 0

    filename, position = read_string(payload,position,)

    file_type, position = read_string(payload,position,)

    # Defensive validation of decrypted private metadata.
    if filename.strip() == "":
        raise ValueError("Filename must not be empty")

    if file_type.strip() == "":
        raise ValueError("File type must not be empty")

    # Everything remaining belongs to the document.
    content = payload[position:]

    return filename, file_type, content
