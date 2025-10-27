# Owen Hartzell ohartzel@charlotte.edu

# ITIS 6200 Course Project: Implementing AES-CBC Mode encryption from scratch

'''
REFERENCES
    General Research
    - NIST Advanced Encryption Standards (AES): https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf
    - NIST Cryptographic Standards and Guidelines: https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines/example-values

    From Professor Cyrill Gössi's cryptography with python lectures on YouTube
    - Professor Gössi's personal website: https://goescy.ch/
    - Professor Gössi's YouTube channel: https://www.youtube.com/@cyrillgossi

    - AES implementation in python
        - Part 1: https://www.youtube.com/watch?v=1gCD1pZKc04
        - Part 2: https://www.youtube.com/watch?v=kZv7S9mNXDk
        - Part 3: https://www.youtube.com/watch?v=blCA51nsVk8
        - Part 4: https://www.youtube.com/watch?v=hXFhi2zD_W4
        - Part 5: https://www.youtube.com/watch?v=tyhl7EYmJoM
'''

# === Implementing an AES encryption scheme that follows NIST standards ===
# Note: This implementation is not cryptographically secure and is for demonstration purposes only (Side channel attacks, cold boot attacks, key erasure)


# === This file is a copy of the AES.py file that retains all logic for testing separately to show functionality ===


'''
NIST standard non-linear byte substitution table 
    - Substitution-Permutation cipher
    - To be used for sub bytes and key expansion functions
    - Performs a one to one substitution of a byte value
    - In hexadecimal format
'''
s_box_string = '63 7c 77 7b f2 6b 6f c5 30 01 67 2b fe d7 ab 76' \
                'ca 82 c9 7d fa 59 47 f0 ad d4 a2 af 9c a4 72 c0' \
                'b7 fd 93 26 36 3f f7 cc 34 a5 e5 f1 71 d8 31 15' \
                '04 c7 23 c3 18 96 05 9a 07 12 80 e2 eb 27 b2 75' \
                '09 83 2c 1a 1b 6e 5a a0 52 3b d6 b3 29 e3 2f 84' \
                '53 d1 00 ed 20 fc b1 5b 6a cb be 39 4a 4c 58 cf' \
                'd0 ef aa fb 43 4d 33 85 45 f9 02 7f 50 3c 9f a8' \
                '51 a3 40 8f 92 9d 38 f5 bc b6 da 21 10 ff f3 d2' \
                'cd 0c 13 ec 5f 97 44 17 c4 a7 7e 3d 64 5d 19 73' \
                '60 81 4f dc 22 2a 90 88 46 ee b8 14 de 5e 0b db' \
                'e0 32 3a 0a 49 06 24 5c c2 d3 ac 62 91 95 e4 79' \
                'e7 c8 37 6d 8d d5 4e a9 6c 56 f4 ea 65 7a ae 08' \
                'ba 78 25 2e 1c a6 b4 c6 e8 dd 74 1f 4b bd 8b 8a' \
                '70 3e b5 66 48 03 f6 0e 61 35 57 b9 86 c1 1d 9e' \
                'e1 f8 98 11 69 d9 8e 94 9b 1e 87 e9 ce 55 28 df' \
                '8c a1 89 0d bf e6 42 68 41 99 2d 0f b0 54 bb 16'.replace(" ", "")

# Converting the hex string into an array of bytes
s_box = bytearray.fromhex(s_box_string)

# === Helper Functions ===
'''
Converts a flat 16 byte input from the plaintext and converts it to a 4x4 matrix
    - Column major order as specified by NIST
    - i % 4 is the row index 0-3
    - i // 4 is the column index 0-3
'''
def state_from_bytes(data: bytes) -> list[list[int]]:
    state = [[0] * 4 for _ in range(4)]
    for i in range(16):
        state[i % 4][i // 4] = data[i]
    return state

'''
Converts a 4x4 matrix into a flat 16 byte output of ciphertext
    - Reverse of state from bytes
'''
def bytes_from_state(state: list[list[int]]) -> bytes:
    data = bytearray(16)
    for i in range(16):
        data[i] = state[i % 4][i // 4]
    return bytes(data)

# Printing the state to identify order, remove after completing testing
def print_state(state, label="state"):
    print(f"\n{label}:")
    for r in range(4):
        print(" ".join(f"{state[r][c]:02x}" for c in range(4)))
    print()

'''
Transformation of bytes
    - Applies the bitwise XOR operation
    - Takes in two values and uses them to perform the XOR operation
'''
def xor_bytes(a: list[int], b: list[int]) -> list[int]: 
    return [x ^ y for (x, y) in zip(a, b)]

'''
Transformation of bytes
    - Polynomial representation of the input byte is multiplied by x mod m(x)
    - Produces the polynomial representation of the output byte
    - Left shifting of bits
'''
def xtime(a: int) -> int:
    if a & 0x80:
        return ((a << 1) ^ 0x1b) & 0xff
    return a << 1

'''
Transformation of words
    - Each of the four bytes of the word are permuted cyclically
    - Moves the first byte to the end and left shifts the other bytes
    - Used for key expansion to generate a new 4 byte word at each step
    - Ensures each round key is different
'''
def rot_word(word: list[int]) -> list[int]: 
    return word[1:] + word[:1]

'''
Transformation of words
    - S-box is applied to each of the four bytes of the word
    - Used during key expansion
    - Applies non-linear substitution on a single 4 byte word
    - Part of generating new round keys from the original key and previous words
    - Makes the new key bytes non-linear in respect to the old ones
'''
def sub_word(word: list[int]) -> list[int]: 
    return [s_box[b] for b in word]

'''
Word array for the round constant
    - NIST standard value
    - Used in key expansion
    - Ensures each round key is unique
    - Prevents each key being a predictable function of the previous key
    - Only affects the first byte of the word
'''
def rcon(i: int) -> list[int]: 
    rcon_lookup = bytearray.fromhex('01020408102040801B36') 
    return [rcon_lookup[i-1], 0, 0, 0]

'''
Routine that is applied to the key to generate 4*(Nr + 1) words
    - Four words are generated for each of the Nr + 1 applications of add round key
    - Output is a linear array of words
    - Used to generate a set of round keys, one for each AES round plus the initial key
'''
def key_expansion(key: bytes, nb: int = 4) -> list[list[list[int]]]:
    nk = len(key) // 4
    key_bit_length = len(key) * 8
    nr = {128: 10, 192: 12, 256: 14}[key_bit_length]

    w = [list(key[i*4:(i+1)*4]) for i in range(nk)]

    for i in range(nk, nb * (nr + 1)):
        temp = w[i-1][:]
        if i % nk == 0:
            temp = xor_bytes(sub_word(rot_word(temp)), rcon(i // nk))
        elif nk > 6 and i % nk == 4:
            temp = sub_word(temp)
        w.append(xor_bytes(w[i - nk], temp))

    key_schedule = []
    for r in range(0, len(w), nb):
        round_key = [[w[r + c][r_] for c in range(nb)] for r_ in range(4)]
        key_schedule.append(round_key)

    return key_schedule

'''
Transformation of the state in which a round key is combined with the state
    - Applies the bitwise XOR operation
    - Each round key consists of four words from the key schedule
    - Each round key is combined with a column of the state
'''
def add_round_key(state: list[list[int]], key_schedule: list[list[list[int]]], round: int):
    round_key = key_schedule[round]
    for r in range(len(state)):
        state[r] = [state[r][c] ^ round_key[r][c] for c in range(len(state[0]))]

'''
Invertible and non-linear transformation of the state
    - The substitution table S-box is applied independently to each byte in the state
    - Each byte is replaced by its multiplicative inverse except 0x00
    - Occurs once per round after shift rows but before mix columns
'''
def sub_bytes(state: list[list[int]]):
    for r in range(len(state)):
        state[r] = [s_box[state[r][c]] for c in range(len(state[0]))]

'''
Transformation of the state in which bytes in the last three rows of the state are cyclically shifted
    - The number of positions shifted depends on the row index r where 0 <= r < 4
    - Moves each byte by r positions to the left in the row
    - Left most r bytes are cycled around to the right end
    - The first row where r = 0 remains unchanged by this function
'''
def shift_rows(state: list[list[int]]):
    for r in range(1, 4):
        state[r] = state[r][r:] + state[r][:r]

'''
Transformation of the state that multiplies each of the four columns of the state by a fixed matrix
    - Matrix multiplication for one 4 byte column
    - Mutates col by replacing the 4 bytes with transformed values
    - Follows NIST guidelines on calculations for correct matrix multiplication
'''
def mix_column(col: list[int]):
    c_0 = col[0]
    all_xor = col[0] ^ col[1] ^ col[2] ^ col[3]
    col[0] ^= xtime(col[0] ^ col[1]) ^ all_xor
    col[1] ^= xtime(col[1] ^ col[2]) ^ all_xor
    col[2] ^= xtime(col[2] ^ col[3]) ^ all_xor
    col[3] ^= xtime(c_0 ^ col[3]) ^ all_xor

# Loops through all 4 columns of the state to apply mix_column for correct transformation
def mix_columns(state: list[list[int]]):
    for c in range(4):
        col = [state[r][c] for r in range(4)]
        mix_column(col)
        for r in range(4):
            state[r][c] = col[r]

# === AES Encryption Function ===
'''
Performing AES encryption on a block of data
    - Uses a block of plaintext and a key to perform encryption
    - Implements the AES encryption process defined by NIST
    - Expands the key into round keys
    - Applies the transformations specified over multiple rounds
'''
def aes_encryption(data: bytes, key: bytes) -> bytes:
    # Getting the current state as a 4x4 matrix for transformations
    state = state_from_bytes(data)
    # Checking the order of the state, remove after completing testing
    print_state(state, "Initial state after state_from_bytes")

    # Expanding the key into a full key schedule containing each round key
    key_schedule = key_expansion(key)
    # Applies first round key by XORing plaintext with round key
    add_round_key(state, key_schedule, round = 0)
    # Checking the key size to determine how many rounds are needed per NIST standards
    key_bit_length = len(key) * 8
    nr = {128: 10, 192: 12, 256: 14}[key_bit_length]

    # Loop for the rounds which apply the 4 transformations outlined by NIST
    for round in range (1, nr):
        sub_bytes(state)
        shift_rows(state)
        mix_columns(state)
        add_round_key(state, key_schedule, round)

    # Final round of transformations, mix columns is omitted per NIST standards
    sub_bytes(state)
    shift_rows(state)
    add_round_key(state, key_schedule, round=nr)

    # Returning the ciphertext in bytes from the array after transformations
    ciphertext = bytes_from_state(state)
    return ciphertext

# === Implementing an AES decryption scheme that follows NIST standards ===

'''
NIST standard non-linear byte substitution table 
    - Inverse byte substitution table for decryption
    - Bytes are mapped back to their original values
    - Used for reversing the byte substitution done during encryption
'''
inv_s_box = bytearray(256)
for i, val in enumerate(s_box):
    inv_s_box[val] = i

'''
Inverse of sub bytes transformation
    - Applies the inverse S-box to each byte of the state
    - Reverses the byte substitution performed during encryption
'''
def inv_sub_bytes(state: list[list[int]]):
    for r in range(len(state)):
        state[r] = [inv_s_box[state[r][c]] for c in range(len(state[0]))]

'''
Inverse of shift rows transformation
    - Cyclically shifts the last three rows of the state to the right
    - Reverses the left shift performed during encryption
    - Still maintains the first row as specified by NIST
'''
def inv_shift_rows(state: list[list[int]]):
    for r in range(1, 4):
        state[r] = state[r][-r:] + state[r][:-r]

'''
Galois Field Multiplication
    - Performs multiplication of two bytes in GF(2^8) as specified by NIST
    - Used for inverse mix columns to correctly reverse column mixing
    - Implements finite field arithmetic for correct AES decryption as specified by NIST
'''
def gf_mul(a: int, b: int) -> int:
    res = 0
    aa = a
    bb = b
    for _ in range(8):
        if bb & 1:
            res ^= aa
        carry = aa & 0x80
        aa = (aa << 1) & 0xFF
        if carry:
            aa ^= 0x1B
        bb >>= 1
    return res & 0xFF

'''
Inverse mix column transformation
    - Reverses the mix column transformation performed during encryption
    - Each byte is multiplied by a fixed value in GF(2^8) and XORed
    - Uses GF arithmetic to correctly reverse each column
'''
def inv_mix_column(col: list[int]):
    a0, a1, a2, a3 = col[0], col[1], col[2], col[3]
    col[0] = gf_mul(a0, 14) ^ gf_mul(a1, 11) ^ gf_mul(a2, 13) ^ gf_mul(a3, 9)
    col[1] = gf_mul(a0, 9)  ^ gf_mul(a1, 14) ^ gf_mul(a2, 11) ^ gf_mul(a3, 13)
    col[2] = gf_mul(a0, 13) ^ gf_mul(a1, 9)  ^ gf_mul(a2, 14) ^ gf_mul(a3, 11)
    col[3] = gf_mul(a0, 11) ^ gf_mul(a1, 13) ^ gf_mul(a2, 9)  ^ gf_mul(a3, 14)

# Loops through all 4 columns of the state to apply inv_mix_column for correct transformation
def inv_mix_columns(state: list[list[int]]):
    for c in range(4):
        col = [state[r][c] for r in range(4)]
        inv_mix_column(col)
        for r in range(4):
            state[r][c] = col[r]

'''
Performing AES decryption on a block of data
    - Uses a block of ciphertext and a key to perform decryption
    - Implements the AES decryption process defined by NIST
    - Expands the key into round keys
    - Applies the inverse transformations specified over multiple rounds
'''
def aes_decryption(data: bytes, key: bytes) -> bytes:
    # Getting the current state as a 4x4 matrix for transformations
    state = state_from_bytes(data)
    # Checking the order of the state, remove after completing testing
    print_state(state, "Initial state in decryption after state_from_bytes")

    # Expanding the key into a full key schedule containing each round key
    key_schedule = key_expansion(key)
        # Checking the key size to determine how many rounds are needed per NIST standards
    key_bit_length = len(key) * 8
    nr = {128: 10, 192: 12, 256: 14}[key_bit_length]

    # Applies final round key first by XORing plaintext with round key
    add_round_key(state, key_schedule, nr)

    # Loop for the rounds in reverse order applying the inverse transformations
    for round in range(nr - 1, 0, -1):
        inv_shift_rows(state)
        inv_sub_bytes(state)
        add_round_key(state, key_schedule, round)
        inv_mix_columns(state)

    # Applies the initial round (nr = 0)
    inv_shift_rows(state)
    inv_sub_bytes(state)
    add_round_key(state, key_schedule, 0)

    # Returning the plaintext in bytes from the array after transformations
    plaintext = bytes_from_state(state)
    return plaintext

# === NIST tests for AES encryption implementation ===
if __name__ == "__main__":

    # NIST AES-128 test vector 1
    plaintext = bytearray.fromhex('00112233445566778899aabbccddeeff')
    key = bytearray.fromhex('000102030405060708090a0b0c0d0e0f')
    expected_ciphertext = bytearray.fromhex('69c4e0d86a7b0430d8cdb78070b4c55a')
    ciphertext = aes_encryption(plaintext, key)
    recovered_plaintext = aes_decryption(ciphertext, key)

    print(ciphertext == expected_ciphertext)
    print(recovered_plaintext == plaintext)

    # NIST AES-192 test vector 2
    plaintext = bytearray.fromhex('00112233445566778899aabbccddeeff')
    key = bytearray.fromhex('000102030405060708090a0b0c0d0e0f1011121314151617')
    expected_ciphertext = bytearray.fromhex('dda97ca4864cdfe06eaf70a0ec0d7191')
    ciphertext = aes_encryption(plaintext, key)
    recovered_plaintext = aes_decryption(ciphertext, key)

    print(ciphertext == expected_ciphertext)
    print(recovered_plaintext == plaintext)

    # NIST AES-256 test vector 3
    plaintext = bytearray.fromhex('00112233445566778899aabbccddeeff')
    key = bytearray.fromhex('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f')
    expected_ciphertext = bytearray.fromhex('8ea2b7ca516745bfeafc49904b496089')
    ciphertext = aes_encryption(plaintext, key)
    recovered_plaintext = aes_decryption(ciphertext, key)

    print(ciphertext == expected_ciphertext)
    print(recovered_plaintext == plaintext)