BLOCK_SIZE =16 #16 bytes
KEY_SIZE = 16 #16 bytes
NUMBER_OF_ROUNDS = 10 #for AES-128


#SBOX 
S_BOX = [
    [0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76],
    [0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0],
    [0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15],
    [0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75],
    [0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84],
    [0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf],
    [0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8],
    [0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2],
    [0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73],
    [0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb],
    [0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79],
    [0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08],
    [0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a],
    [0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e],
    [0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf],
    [0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16],
]


# This function turn the block in to state , B[i] = S i/4 , i mod 4
#INPUT: PLAIN TEXT BLOCK (16 bytes) -> STATE (4x4 matrix)
def bytes_to_state(block: bytes) -> list[list[int]]:
    if len(block) != 16:
        raise ValueError("AES block must be exactly 16 bytes")
    return [list(block[i::4]) for i in range(4)]

#This function turn the state in to block , Si,j -> B[i+j*4]
#INPUT: STATE (4x4 matrix) -> CIPHER TEXT BLOCK
def state_to_bytes(state: list[list[int]]) -> bytes:
    block = [0] * 16
    for column in range(4):
        for row in range(4):
            block[row + 4 * column] = state[row][column]
    return bytes(block)


#passing through 10 rounds 
def aes_round(state: list[list[int]], round_key: list[list[int]], round_number: int) -> None:
    # Round 0 only adds the first round key.
    if round_number == 0:
        add_round_key(state, round_key)
        return
    # Every regular round starts with byte substitution and row shifting.
    sub_bytes(state)
    shift_rows(state)
    # The last round does not use MixColumns.
    if round_number != NUMBER_OF_ROUNDS:
        mix_columns(state)
    add_round_key(state, round_key)



#change the postion of the bytes in the state matrix ->premutaion of the bytes in the state matrix
def shift_rows(state: list[list[int]]) -> None:
    for i in range(4):
        state[i] = state[i][i:] + state[i][:i]
    
#This function performs Galois multiplication in GF(2^8) for AES MixColumns.
def galois_mult(value: int, multiplier: int) -> int:
    #value. 02 shift left by 1 bit, if the most significant bit is 1, XOR with 0x1b
    if multiplier == 2:
        if (value & 0x80):
            return ((value << 1) ^ 0x1b) & 0xff #& 0xFF=keep the result inside one byte​
        return (value << 1) & 0xff
     #value. 03 turn into 02 and then XOR with 01
    if multiplier == 3:
        return galois_mult(value, 2) ^ value
    raise ValueError("Multiplier must be 2 or 3")
#spread the change in message to all the bytes in the state matrix, so that if one byte is changed, it will affect all the bytes in the state matrix
def mix_columns(state: list[list[int]]) -> None:
    #iterate over each column 
    for i in range(4):
        a = state[0][i]
        b = state[1][i]
        c = state[2][i]
        d = state[3][i]
        # Row 1 =  (02a)⊕(03b)⊕c⊕d
        # Row 2 =  a⊕(02b)⊕(03c)⊕d
        # Row 3 =  a⊕b⊕(02c)⊕(03d)
        # Row 4 =  (03a)⊕b⊕c⊕(02d)
        state[0][i] = galois_mult(a, 2) ^ galois_mult(b, 3) ^ c ^ d
        state[1][i] = a ^ galois_mult(b, 2) ^ galois_mult(c, 3) ^ d
        state[2][i] = a ^ b ^ galois_mult(c, 2) ^ galois_mult(d, 3)
        state[3][i] = galois_mult(a, 3) ^ b ^ c ^ galois_mult(d, 2)

#return the S-Box value for a given byte and provide confusion
def sub_bytes(state: list[list[int]]) -> None:
    for row in range(4):
        for column in range(4):
            value = state[row][column]
            state[row][column] = S_BOX[value >> 4][value & 0x0F]


# introduce the key into the state matrix 
def add_round_key(state: list[list[int]], round_key: list[list[int]]) -> None:
    for row in range(4):
        for column in range(4):
            state[row][column] ^= round_key[row][column]


#the g function is used in the key expansion process of AES to generate new words from the previous word. 
# It performs a series of transformations on a 4-byte word, including rotation, substitution using the S-Box, 
# and XOR with a round constant. This function is called every fourth word during key expansion to ensure that 
# the generated round keys are sufficiently different from each other, enhancing the security of the AES encryption process.
def g_function(word: list[int], round_number: int) -> list[int]:
    # rotate the word by one byte to left 
    word = word[1:] + word[:1]
    # substitute each byte using the S-Box
    for i in range(4):
        value = word[i]
        word[i] = S_BOX[value >> 4][value & 0x0F]
    # XOR the first byte with the round constant , include all the possible round coefficient (RC)
    round_constant = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]
    word[0] ^= round_constant[round_number - 1]#x^(round_number-1)
    return word



def key_expansion(key: bytes) -> list[list[list[int]]]:
    if len(key) != KEY_SIZE:
        raise ValueError("AES-128 key must be exactly 16 bytes")

    # Split the 16-byte key into four 4-byte words.
    words = [
        list(key[0:4]),
        list(key[4:8]),
        list(key[8:12]),
        list(key[12:16])
    ]

    # AES-128 needs 44 words: 4 words for each of 11 round keys.
    for word_number in range(4, 44):
      #making a copy of the previous word to avoid modifying the original word in the list
        previous_word = words[word_number - 1][:]

        # Every fourth word is rotated, substituted, and XORed with Rcon.
        if word_number % 4 == 0:
            previous_word = g_function(previous_word, word_number // 4)

        new_word = []
        old_word = words[word_number - 4]
        for byte_number in range(4):
            new_byte = previous_word[byte_number] ^ old_word[byte_number]
            new_word.append(new_byte)
        words.append(new_word)

    # Turn every group of four words back into a 4x4 state matrix.
    round_keys = []
    for round_number in range(11):
        round_key = []
        first_word = round_number * 4
        for row in range(4):
            row_values = []
            for column in range(4):
                row_values.append(words[first_word + column][row])
            round_key.append(row_values)
        round_keys.append(round_key)

    return round_keys


def aes_encrypt_block(block: bytes, key: bytes) -> bytes:
    if len(block) != BLOCK_SIZE:
        raise ValueError("AES block must be exactly 16 bytes")
    if len(key) != KEY_SIZE:
        raise ValueError("AES-128 key must be exactly 16 bytes")

    state = bytes_to_state(block)
    round_keys = key_expansion(key)

    for round_number in range(NUMBER_OF_ROUNDS + 1):
        aes_round(state, round_keys[round_number], round_number)

    return state_to_bytes(state)
     