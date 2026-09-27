from dataclasses import dataclass
import secrets
from argon2.low_level import hash_secret_raw, Type
from crypto.ecc import n
from crypto.gcm import GCMProtectedData,encrypt_gcm, decrypt_gcm
# Argon2id and AES-GCM parameters
ARGON2_MEMORY_COST = 131072    # 128 MiB
ARGON2_TIME_COST = 3
ARGON2_PARALLELISM = 1
SALT_SIZE = 16                 # 128-bit salt
AES_KEY_SIZE = 16              # AES-128 key
PRIVATE_KEY_SIZE = 32          # P-256 private key size
GCM_NONCE_SIZE = 12
GCM_TAG_SIZE = 16
#  Protected private-key record

@dataclass(frozen=True)
class ProtectedPrivateKey:
    key_type: str
    salt: bytes
    nonce: bytes
    ciphertext: bytes
    tag: bytes


#Validation functions


def validate_key_type(key_type: str):
    """
    Accept only the two private-key purposes used by SecureVault.
    """

    if key_type not in ("ECDH", "ECDSA"):
        raise ValueError("key_type must be 'ECDH' or 'ECDSA'")


def validate_private_key(private_key: int):
    """
    Validate a P-256 private key.

    A valid private key must be an integer in the range:
    1 <= private_key < n
    """

    if not isinstance(private_key, int):
        raise TypeError("private key must be an integer")

    # bool is considered an int in Python, so reject it explicitly
    if isinstance(private_key, bool):
        raise TypeError( "private key must be an integer")

    if not (1 <= private_key < n):
        raise ValueError( "private key must satisfy 1 <= key < n")


#  Private-key conversion


def private_key_to_bytes(private_key: int) :
    """
    Convert the P-256 private-key integer into exactly 32 bytes.
    """

    validate_private_key(private_key)

    return private_key.to_bytes( PRIVATE_KEY_SIZE,byteorder="big")


def bytes_to_private_key(data: bytes) :
    """
    Convert 32 bytes back into a P-256 private-key integer.
    """

    if not isinstance(data, bytes):
        raise TypeError( "private key data must be bytes" )

    if len(data) != PRIVATE_KEY_SIZE:
        raise ValueError("private key must be exactly 32 bytes")

    private_key = int.from_bytes(  data, byteorder="big")

    validate_private_key(private_key)

    return private_key
#  Derive AES key from password


def derive_private_key_encryption_key(password: str,salt: bytes) :
    """
    Derive a 16-byte AES-128 key from the user's password.

    This key is used only to protect private keys.
    """

    if not isinstance(password, str):
        raise TypeError("password must be a string")

    if password == "":raise ValueError("password must not be empty")

    if not isinstance(salt, bytes):
        raise TypeError("salt must be bytes")

    if len(salt) != SALT_SIZE:
        raise ValueError("salt must be exactly 16 bytes")

    password_bytes = password.encode("utf-8")

    encryption_key = hash_secret_raw(
        secret=password_bytes,
        salt=salt,
        time_cost=ARGON2_TIME_COST,
        memory_cost=ARGON2_MEMORY_COST,
        parallelism=ARGON2_PARALLELISM,
        hash_len=AES_KEY_SIZE,
        type=Type.ID
    )

    return encryption_key


# Build Additional Authenticated Data


def build_aad(key_type: str) :
    """
    Create AAD that binds the ciphertext to its key purpose.

    This prevents an encrypted ECDH key from being treated as
    an encrypted ECDSA key, or the opposite.
    """

    validate_key_type(key_type)

    return (b"SecureVault/PrivateKeyProtection/v1/"+ key_type.encode("ascii"))


# Protect private key


def protect_private_key(
    password: str,
    private_key: int,
    key_type: str) :
    """
    Encrypt and authenticate one private key using AES-GCM.
    """

    if not isinstance(password, str):
        raise TypeError("password must be a string")

    if password == "":
        raise ValueError("password must not be empty")

    validate_key_type(key_type)
    validate_private_key(private_key)

    # Create a fresh salt for deriving the AES key
    salt = secrets.token_bytes(SALT_SIZE)

    # Password + salt -> AES-128 key
    encryption_key = derive_private_key_encryption_key(password,salt)

    # Convert private-key integer into 32 bytes
    plaintext = private_key_to_bytes(private_key)

    # Bind the encrypted key to its purpose
    aad = build_aad(key_type)

    # gcm.py automatically generates a fresh 12-byte nonce
    protected_data = encrypt_gcm(plaintext=plaintext,aad=aad,key=encryption_key)

    # Store only the protected form of the private key
    return ProtectedPrivateKey(
        key_type=key_type,
        salt=salt,
        nonce=protected_data.nonce,
        ciphertext=protected_data.ciphertext,
        tag=protected_data.tag
    )


# Recover private key


def recover_private_key(password: str,protected: ProtectedPrivateKey) :
    """
    Verify the AES-GCM tag and recover the original private key.

    A wrong password or modified ciphertext/tag causes
    decrypt_gcm to reject the data.
    """

    if not isinstance(password, str):
        raise TypeError("password must be a string")

    if password == "":
        raise ValueError("password must not be empty")

    if not isinstance(protected, ProtectedPrivateKey):
        raise TypeError( "protected must be a ProtectedPrivateKey")

    validate_key_type(protected.key_type)

    if not isinstance(protected.salt, bytes):
        raise TypeError( "salt must be bytes" )

    if len(protected.salt) != SALT_SIZE:
        raise ValueError( "salt must be exactly 16 bytes" )

    if not isinstance(protected.nonce, bytes):
        raise TypeError("nonce must be bytes")

    if len(protected.nonce) != GCM_NONCE_SIZE:
        raise ValueError(  "nonce must be exactly 12 bytes")

    if not isinstance(protected.ciphertext, bytes):
        raise TypeError( "ciphertext must be bytes")

    if len(protected.ciphertext) != PRIVATE_KEY_SIZE:
        raise ValueError( "private-key ciphertext must be exactly 32 bytes")

    if not isinstance(protected.tag, bytes):
        raise TypeError("tag must be bytes")

    if len(protected.tag) != GCM_TAG_SIZE:
        raise ValueError( "tag must be exactly 16 bytes")

    # Derive the same AES key using the entered password
    encryption_key = derive_private_key_encryption_key( password,protected.salt)

    # Rebuild the same AAD
    aad = build_aad(protected.key_type)

    # Build the object expected by decrypt_gcm
    gcm_protected_data = GCMProtectedData(nonce=protected.nonce,ciphertext=protected.ciphertext,tag=protected.tag)

    # decrypt_gcm verifies the tag before returning plaintext
    plaintext = decrypt_gcm(protected=gcm_protected_data,aad=aad, key=encryption_key )

    # Convert the recovered bytes back into an integer
    return bytes_to_private_key(plaintext)

