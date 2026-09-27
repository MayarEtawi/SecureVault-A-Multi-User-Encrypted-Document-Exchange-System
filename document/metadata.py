"""Encode and decode public and private document metadata."""

"""
Module summary:
- pack_string(): Convert string into 2-byte length then bytes.
- read_string(): Read string from byte array using the length prefix.
- check_integer(): Check if number is integer inside correct min/max limits.
- encode_public(): Turn public dict metadata into bytes for AES-GCM AAD.
- decode_public(): Read public metadata bytes back to dict and check validity.
- encode_private(): Pack secret file type and data before doing encryption.
- decode_private(): Read secret file type and data after decryption finished.
"""

# Import struct for change numbers into bytes format
# I = 4 bytes number, Q = 8 bytes number, H = 2 bytes number
# > means big-endian order
import struct

# Public fields list. Server can read this data.
# AES-GCM check this as AAD so nobody can edit it.
PUBLIC_FIELDS = {
    "document_id",
    "owner_id",
    "version",
    "filename",
    "file_size",
    "timestamp",
}

# Max string length size in two bytes
MAX_STRING_SIZE = 65535
STRING_LENGTH_SIZE = 2


# ============================================================
# String encoding and decoding
# ============================================================

def pack_string(value: str, field_name: str) -> bytes:
    """
    Convert string to bytes like this:
    [2-byte size][UTF-8 string bytes]
    
    Example:
    "pdf" becomes:
    00 03 70 64 66
    """
    # Value must be python string
    if not isinstance(value, str):
        raise TypeError(f"{field_name} must be a string")
    
    # Do not accept empty string or string with only space
    if value.strip() == "":
        raise ValueError(f"{field_name} must not be empty")
    
    # Change string to utf-8 bytes. Works for English and Arabic text
    encoded_value = value.encode("utf-8")
    
    # Check string size not bigger than max size
    if len(encoded_value) > MAX_STRING_SIZE:
        raise ValueError(f"{field_name} is too long")
    
    # Pack length in 2 bytes and attach encoded text
    encoded_length = struct.pack(">H", len(encoded_value))
    return encoded_length + encoded_value


def read_string(data: bytes, position: int) -> tuple[str, int]:
    """
    Read length-prefixed string from data.
    Return decoded string and next index position.
    """
    # Need 2 bytes minimum to read length
    if position + STRING_LENGTH_SIZE > len(data):
        raise ValueError("Invalid encoded string")
    
    # Read length number from 2 bytes
    string_length = struct.unpack_from(">H", data, position)[0]
    position += STRING_LENGTH_SIZE
    
    # Calculate end index for string
    string_end = position + string_length
    
    # Stop if string length goes outside data size
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

def check_integer(value, field_name: str, minimum: int, maximum: int) -> None:
    """Check number is correct integer and in valid range."""
    # Boolean is child class of int in python so reject True/False
    if not isinstance(value, int) or isinstance(value, bool):
        raise TypeError(f"{field_name} must be an integer")
        
    if value < minimum or value > maximum:
        raise ValueError(f"{field_name} is out of range")


# ============================================================
# Public metadata
# ============================================================

def encode_public(metadata: dict) -> bytes:
    """
    Encode public dictionary fields into byte sequence.
    Used as AAD header for GCM mode.
    """
    # Check input is dictionary
    if not isinstance(metadata, dict):
        raise TypeError("Metadata must be a dictionary")
        
    # Check dict keys exactly equal public fields set
    if set(metadata.keys()) != PUBLIC_FIELDS:
        raise ValueError("Missing or unexpected public metadata fields")
        
    # Validate version (4 bytes limit) and file size (8 bytes limit)
    check_integer(metadata["version"], "version", 1, 2**32 - 1)
    check_integer(metadata["file_size"], "file_size", 0, 2**64 - 1)
    
    # Pack all text and integer fields
    document_id_bytes = pack_string(metadata["document_id"], "document_id")
    owner_id_bytes = pack_string(metadata["owner_id"], "owner_id")
    version_bytes = struct.pack(">I", metadata["version"])
    filename_bytes = pack_string(metadata["filename"], "filename")
    file_size_bytes = struct.pack(">Q", metadata["file_size"])
    timestamp_bytes = pack_string(metadata["timestamp"], "timestamp")
    
    return (
        document_id_bytes
        + owner_id_bytes
        + version_bytes
        + filename_bytes
        + file_size_bytes
        + timestamp_bytes
    )


def decode_public(data: bytes) -> dict:
    """Read public metadata bytes and construct dictionary again."""
    if not isinstance(data, bytes):
        raise TypeError("Public metadata must be bytes")
        
    position = 0
    
    # Read string fields and advance pointer position
    document_id, position = read_string(data, position)
    owner_id, position = read_string(data, position)
    
    # Must have 12 bytes minimum left for version (4) + file_size (8)
    if position + 12 > len(data):
        raise ValueError("Public metadata is incomplete")
        
    version = struct.unpack_from(">I", data, position)[0]
    position += 4
    
    filename, position = read_string(data, position)
    
    if position + 8 > len(data):
        raise ValueError("Public metadata is incomplete")
        
    file_size = struct.unpack_from(">Q", data, position)[0]
    position += 8
    
    timestamp, position = read_string(data, position)
    
    # Check no remaining extra bytes at the end
    if position != len(data):
        raise ValueError("Public metadata contains extra data")
        
    metadata = {
        "document_id": document_id,
        "owner_id": owner_id,
        "version": version,
        "filename": filename,
        "file_size": file_size,
        "timestamp": timestamp,
    }
    
    # Re-encode to verify format matches canonical byte output
    if encode_public(metadata) != data:
        raise ValueError("Invalid public metadata")
        
    return metadata


# ============================================================
# Private metadata and document contents
# ============================================================

def encode_private(file_type: str, content: bytes) -> bytes:
    """
    Pack private payload before encrypting with AES-GCM.
    Format: [file_type string][raw content bytes]
    """
    if not isinstance(content, bytes):
        raise TypeError("Document content must be bytes")
        
    file_type_bytes = pack_string(file_type, "file_type")
    return file_type_bytes + content


def decode_private(payload: bytes) -> tuple[str, bytes]:
    """
    Unpack decrypted payload back into file type string and raw content.
    Note: Call this only after tag verification success.
    """
    if not isinstance(payload, bytes):
        raise TypeError("Private payload must be bytes")
        
    position = 0
    file_type, position = read_string(payload, position)
    
    # Double check file type isn't blank
    if file_type.strip() == "":
        raise ValueError("File type must not be empty")
        
    # All leftover bytes belong to file content
    content = payload[position:]
    return file_type, content
