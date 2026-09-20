"""SHA-256 implemented from scratch for the secure-document project.

This version keeps the partner-compatible ``hash_data`` name while also
providing ``sha256`` for the HMAC and HKDF modules.
"""


# SHA-256 processes the message in 64-byte (512-bit) blocks.
BLOCK_SIZE = 64
DIGEST_SIZE = 32
WORD_MASK = 0xFFFFFFFF

# Initial hash values: the first 32 bits of the fractional parts of the
# square roots of the first eight prime numbers.
INITIAL_HASH_VALUES = [
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
    0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
]

# Round constants: the first 32 bits of the fractional parts of the cube
# roots of the first 64 prime numbers.
ROUND_CONSTANTS = [
    0x428A2F98,0x71374491,0xB5C0FBCF,0xE9B5DBA5,
    0x3956C25B,0x59F111F1,0x923F82A4,0xAB1C5ED5,
    0xD807AA98,0x12835B01,0x243185BE,0x550C7DC3,
    0x72BE5D74,0x80DEB1FE,0x9BDC06A7,0xC19BF174,
    0xE49B69C1,0xEFBE4786,0x0FC19DC6,0x240CA1CC,
    0x2DE92C6F,0x4A7484AA,0x5CB0A9DC,0x76F988DA,
    0x983E5152,0xA831C66D,0xB00327C8,0xBF597FC7,
    0xC6E00BF3,0xD5A79147,0x06CA6351,0x14292967,
    0x27B70A85,0x2E1B2138,0x4D2C6DFC,0x53380D13,
    0x650A7354,0x766A0ABB,0x81C2C92E,0x92722C85,
    0xA2BFE8A1,0xA81A664B,0xC24B8B70,0xC76C51A3,
    0xD192E819,0xD6990624,0xF40E3585,0x106AA070,
    0x19A4C116,0x1E376C08,0x2748774C,0x34B0BCB5,
    0x391C0CB3,0x4ED8AA4A,0x5B9CCA4F,0x682E6FF3,
    0x748F82EE,0x78A5636F,0x84C87814,0x8CC70208,
    0x90BEFFFA,0xA4506CEB,0xBEF9A3F7,0xC67178F2,
]

#ROTR
def rotate_right(value: int, amount: int) -> int:
    """Rotate one 32-bit word to the right."""
    value &= WORD_MASK
    return ((value >> amount) | (value << (32 - amount))) & WORD_MASK


def pad_message(message: bytes) -> bytes:
    """Add SHA-256 padding so the result is a multiple of 64 bytes."""
    if not isinstance(message, bytes):
        raise TypeError("SHA-256 input must be bytes")
    #message || 1||zeroes || message_length_in_bits
    message_length_bits = len(message) * 8
    if message_length_bits >= 1 << 64:
        raise OverflowError("Message is too long for SHA-256")

    # Append one bit. Because input is bytes, this is 10000000 in binary.
    padded_message = message + b"\x80"

    # Leave exactly eight bytes at the end for the original bit length.
    number_of_zero_bytes = (56 - len(padded_message) % BLOCK_SIZE) % BLOCK_SIZE
    padded_message += b"\x00" * number_of_zero_bytes
    padded_message += message_length_bits.to_bytes(8, "big")
    return padded_message



def create_message_schedule(block: bytes) -> list[int]:
    """Expand one 64-byte block into the 64 SHA-256 schedule words."""
    if len(block) != BLOCK_SIZE:
        raise ValueError("SHA-256 block must be exactly 64 bytes")

    schedule = []

    # The first 16 words come directly from the block.
    for start in range(0, BLOCK_SIZE, 4):
        schedule.append(int.from_bytes(block[start:start + 4], "big"))

    # Words 16 through 63 are calculated from earlier words.
    for index in range(16, 64):
        #σ0 -> ROTR7(Wj−15) ⊕ ROTR18(Wj−15) ⊕ SHR3(Wj−15)
        word_15 = schedule[index - 15]
        sigma_0 = (
            rotate_right(word_15, 7)
            ^ rotate_right(word_15, 18)
            ^ (word_15 >> 3)
        )
        #σ1 -> ROTR17(Wj−2) ⊕ ROTR19(Wj−2) ⊕ SHR10(Wj−2)
        word_2 = schedule[index - 2]
        sigma_1 = (
            rotate_right(word_2, 17)
            ^ rotate_right(word_2, 19)
            ^ (word_2 >> 10)
        )
        #Wj -> Wj−16 + σ0 + Wj−7 + σ1
        new_word = (
            schedule[index - 16]
            + sigma_0
            + schedule[index - 7]
            + sigma_1
        ) & WORD_MASK
        schedule.append(new_word)

    return schedule


def compress_block(block: bytes, hash_values: list[int]) -> None:
    """Compress one message block and update the eight hash values."""
    schedule = create_message_schedule(block)
    a, b, c, d, e, f, g, h = hash_values
##Σ(AΣ1​(E)=ROTR6(E)⊕ROTR11(E)⊕ROTR25(E)
    for round_number in range(64):
        capital_sigma_1 = (
            rotate_right(e, 6)
            ^ rotate_right(e, 11)
            ^ rotate_right(e, 25)
        )
        #Ch(E,F,G)=(E∧F)⊕(¬E∧G)
        # Choose: select f where e has 1 bits, otherwise select g.
        choose = (e & f) ^ ((~e) & g)
        
        temporary_1 = (
            h
            + capital_sigma_1
            + choose
            + ROUND_CONSTANTS[round_number]
            + schedule[round_number]
        ) & WORD_MASK
        #Σ0​(A)=ROTR2(A)⊕ROTR13(A)⊕ROTR22(A)
       
        capital_sigma_0 = (
            rotate_right(a, 2)
            ^ rotate_right(a, 13)
            ^ rotate_right(a, 22)
        )
        #Maj(A,B,C)=(A∧B)⊕(A∧C)⊕(B∧C)
        # Majority: a bit is 1 when at least two inputs have that bit set.
        majority = (a & b) ^ (a & c) ^ (b & c)
       
        temporary_2 = (capital_sigma_0 + majority) & WORD_MASK

        h = g
        g = f
        f = e
        e = (d + temporary_1) & WORD_MASK
        d = c
        c = b
        b = a
        a = (temporary_1 + temporary_2) & WORD_MASK

    working_values = [a, b, c, d, e, f, g, h]
    for index in range(8):
        hash_values[index] = (
            hash_values[index] + working_values[index]
        ) & WORD_MASK


def sha256(message: bytes) -> bytes:
    """Return the 32-byte SHA-256 digest of message."""
    padded_message = pad_message(message)
    hash_values = INITIAL_HASH_VALUES.copy()

    for start in range(0, len(padded_message), BLOCK_SIZE):
        block = padded_message[start:start + BLOCK_SIZE]
        compress_block(block, hash_values)

    return b"".join(value.to_bytes(4, "big") for value in hash_values)


def sha256_hexdigest(message: bytes) -> str:
    """Return the SHA-256 digest as 64 hexadecimal characters."""
    return sha256(message).hex()

