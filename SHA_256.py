def pad_message(message: bytes):
   
    message = bytearray(message)

    original_length = len(message) * 8 

    message.append(0x80)#Message|| 1

    while len(message) % 64 != 56: #input SHA-2 512 64 byte
        message.append(0x00) #Message|| 1||000...

    for shift in range(56, -1, -8):
        message.append((original_length >> shift) & 0xFF)#Message || 1|| 0*|| original_length(Message)
    return bytes(message)

def right_rotate(value, amount):
    value &= 0xFFFFFFFF

    return ((value >> amount)| (value << (32 - amount))) & 0xFFFFFFFF

def hash_data(message: bytes):
    K = [
    0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5,
    0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
    0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3,
    0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
    0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC,
    0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
    0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7,
    0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
    0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13,
    0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
    0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3,
    0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
    0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5,
    0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
    0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208,
    0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2
]
    if not isinstance(message, bytes):
        raise TypeError("message must be bytes")

    message = pad_message(message)
    # Initial hash values
    A0 = 0x6A09E667
    B0 = 0xBB67AE85
    C0 = 0x3C6EF372
    D0 = 0xA54FF53A
    E0 = 0x510E527F
    F0 = 0x9B05688C
    G0 = 0x1F83D9AB
    H0 = 0x5BE0CD19
     # Process each 512-bit block
    for block_start in range(0, len(message), 64):
        block = message[block_start:block_start + 64]

        # Message schedule
        words = [0] * 64

        # First 16 words come from the block
        for i in range(16):
            start = i * 4

            words[i] = ((block[start] << 24)| (block[start + 1] << 16)| (block[start + 2] << 8)| block[start + 3])

        # Generate words 16 to 63
        for i in range(16, 64):
            s0 = (right_rotate(words[i - 15], 7)^ right_rotate(words[i - 15], 18)^ (words[i - 15] >> 3))
            

            s1 = (right_rotate(words[i - 2], 17)^ right_rotate(words[i - 2], 19)^ (words[i - 2] >> 10))

            words[i] = (words[i - 16]+ s0+ words[i - 7]+ s1) & 0xFFFFFFFF

        # Working variables
        a = A0
        b = B0
        c = C0
        d = D0
        e = E0
        f = F0
        g = G0
        h = H0

        # 64 compression rounds
        for i in range(64):
            sigma1 = (right_rotate(e, 6)^ right_rotate(e, 11)^ right_rotate(e, 25))

            choice = (e & f) ^ (((~e) & 0xFFFFFFFF) & g)

            temp1 = (h+ sigma1+ choice+ K[i]+ words[i]) & 0xFFFFFFFF

            sigma0 = (right_rotate(a, 2)^ right_rotate(a, 13)^ right_rotate(a, 22))

            majority = (a & b) ^ (a & c) ^ (b & c)

            temp2 = (sigma0 + majority) & 0xFFFFFFFF

            h = g
            g = f
            f = e
            e = (d + temp1) & 0xFFFFFFFF
            d = c
            c = b
            b = a
            a = (temp1 + temp2) & 0xFFFFFFFF

        # Update hash values
        A0 = (A0 + a) & 0xFFFFFFFF
        B0 = (B0 + b) & 0xFFFFFFFF
        C0 = (C0 + c) & 0xFFFFFFFF
        D0 = (D0 + d) & 0xFFFFFFFF
        E0 = (E0 + e) & 0xFFFFFFFF
        F0 = (F0 + f) & 0xFFFFFFFF
        G0 = (G0 + g) & 0xFFFFFFFF
        H0 = (H0 + h) & 0xFFFFFFFF

    # Eight 32-bit words = 32 bytes
    return b"".join(value.to_bytes(4, "big") for value in (A0, B0, C0, D0, E0, F0, G0, H0))

#result = hash_data(b"mayar")
#print(result.hex())