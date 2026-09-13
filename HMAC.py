from SHA_256 import * 
def HMAC_SHA256(key, message):
    # SHA-256 block size = 64 bytes
    block_size = 64

    # Convert strings to bytes
    if isinstance(key, str):
        key = key.encode("utf-8")

    if isinstance(message, str):
        message = message.encode("utf-8")

    # If the key is longer than 64 bytes,hash it to produce a 32-byte key
    if len(key) > block_size:
        key = pad_message(key)

    # If the key is shorter than 64 bytes,pad it with zeros
    if len(key) < block_size:
        key = key + bytes(block_size - len(key))

    # Create ipad and opad
    ipad = bytes([0x36] * block_size)
    opad = bytes([0x5C] * block_size)

    # XOR the key with ipad
    inner_key = bytes( key[i] ^ ipad[i]for i in range(block_size)) 

    # XOR the key with opad
    outer_key = bytes( key[i] ^ opad[i] for i in range(block_size) )

    # Inner hash
    inner_hash = hash_data(inner_key + message)

    # Outer hash
    final_hash =hash_data(outer_key + inner_hash)

    return final_hash

def hmac_verify(key, message, received_tag):
    expected_tag = HMAC_SHA256(key, message)
    if(expected_tag == received_tag):
        return True
    else: return False
#test case 
key = "my-secret-key"
message = "mayar"

received_tag = bytes.fromhex(
    "36636012fdb78cbc11a0a009f9475ef108d2ee88c233932ae310150d3b59a87d")

print("Original message:", hmac_verify(key, message, received_tag))

tampered_message = "mayar1"

print("Modified message:", hmac_verify(key, tampered_message, received_tag))

# Test

tag = HMAC_SHA256("my-secret-key", "mayar")

print("HMAC-SHA256:0x", tag.hex())