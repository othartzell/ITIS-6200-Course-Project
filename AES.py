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

s_box = bytearray.fromhex(s_box_string)

# Returning the state as a 2D array from the byte string
def state_from_bytes(data: bytes) -> list[list[int]]: 
    state = [list(data[i*4:(i+1)*4]) for i in range(len(data) // 4)] 
    return state

# Takes a word as input and performs a cyclic permutation and returns the word
def rot_word(word: list[int]) -> list[int]: 
    return word[1:] + word[:1]

# Takes a four byte input word and applies the S-box to each of the four bytes to produce an output word
def sub_word(word: list[int]) -> list[int]: 
    return [s_box[b] for b in word]

# Round constant
def rcon(i: int) -> list[int]: 
    rcon_lookup = bytearray.fromhex('01020408102040801B36') 
    return [rcon_lookup[i-1], 0, 0, 0]

# XOR helper function
def xor_bytes(a: list[int], b: list[int]) -> list[int]: 
    return [x ^ y for (x, y) in zip(a, b)]

# A routine applied to the key to generate round keys for each round
def key_expansion(key: bytes, nb: int = 4) -> list[list[list[int]]]:
    nk = len(key) // 4
    key_bit_length = len(key) * 8
    nr = {128: 10, 192: 12, 256: 14}[key_bit_length]

    w = state_from_bytes(key)

    for i in range(nk, nb * (nr + 1)):
        temp = w[i-1]
        if i % nk == 0:
            temp = xor_bytes(sub_word(rot_word(temp)), rcon(i // nk))
        elif nk > 6 and i % nk == 4:
            temp = sub_word(temp)
        w.append(xor_bytes(w[i - nk], temp))

    return [w[i*4:(i+1)*4] for i in range(len(w) // 4)]

# Transformation of the state in which a round key is combined with the state by applying the bitwise XOR operation
def add_round_key(state: list[list[int]], key_schedule: list[list[list[int]]], round: int):
    round_key = key_schedule[round]
    for r in range(len(state)):
        state[r] = [state[r][c] ^ round_key[r][c] for c in range(len(state[0]))]

# An invertible non linear transformation of the state in which a substitution table S-box is applied to each byte in the state
def sub_bytes(state: list[list[int]]):
    for r in range(len(state)):
        state[r] = [s_box[state[r][c]] for c in range(len(state[0]))]

# The bytes in the last 3 rows of the state are cyclically shifted over different number of bytes, first row is not shifted
def shift_rows(state: list[list[int]]):
    state[0][1], state[1][1], state[2][1], state[3][1] = state[1][1], state[2][1], state[3][1], state[0][1]
    state[0][2], state[1][2], state[2][2], state[3][2] = state[2][2], state[3][2], state[0][2], state[1][2]
    state[0][3], state[1][3], state[2][3], state[3][3] = state[3][3], state[0][3], state[1][3], state[2][3]

# Multiplication by x (left shift)
def xtime(a: int) -> int:
    if a & 0x80:
        return ((a << 1) ^ 0x1b) & 0xff
    return a << 1

# Performing matrix multiplication to sift the columns
def mix_column(col: list[int]):
    c_0 = col[0]
    all_xor = col[0] ^ col[1] ^ col[2] ^ col[3]
    col[0] ^= xtime(col[0] ^ col[1]) ^ all_xor
    col[1] ^= xtime(col[1] ^ col[2]) ^ all_xor
    col[2] ^= xtime(col[2] ^ col[3]) ^ all_xor
    col[3] ^= xtime(c_0 ^ col[3]) ^ all_xor

# Transformation that operates on the state column by column considered as polynomials over GF(2^8) and multiplied modulo x^4 + 1 (matrix multiplication)
def mix_columns(state: list[list[int]]):
    for r in state:
        mix_column(r)

# Returning the state in bytes from a 2D array
def bytes_from_state(state: list[list[int]]) -> bytes:
    return bytes(state[0] + state[1] + state[2] + state[3])
    

def aes_encryption(data: bytes, key: bytes) -> bytes:
    state = state_from_bytes(data)
    key_schedule = key_expansion(key)
    add_round_key(state, key_schedule, round = 0)
    key_bit_length = len(key) * 8

    nr = {128: 10, 192: 12, 256: 14}[key_bit_length]

    # Loop for the rounds which apply the 4 transformations outlined by NIST
    for round in range (1, nr):
        # Non-linear byte substitution that operates on each byte independently using a substitution table
        sub_bytes(state)
        # Transformation of the state in which the bytes in the last three rows of the state are cyclically shifted
        shift_rows(state)
        # Transformation of the state that multiplies each of the four columns of the state by a fixed matrix
        mix_columns(state)
        # Transformation of the state where a round key is combined with the state by applying bitwise XOR
        add_round_key(state, key_schedule, round)

    # Final round of transformations
    sub_bytes(state)
    shift_rows(state)
    add_round_key(state, key_schedule, round=nr)

    cipher = bytes_from_state(state)
    return cipher

if __name__ == "__main__":

    # NIST AES-128 test vector C.1 (p.35)
    plaintext = bytearray.fromhex('00112233445566778899aabbccddeeff')
    key = bytearray.fromhex('000102030405060708090a0b0c0d0e0f')
    expected_ciphertext = bytearray.fromhex('69c4e0d86a7b0430d8cdb78070b4c55a')
    ciphertext = aes_encryption(plaintext, key)

    print(ciphertext == expected_ciphertext)

    # NIST AES-192 test vector C.2 (p.38)
    plaintext = bytearray.fromhex('00112233445566778899aabbccddeeff')
    key = bytearray.fromhex('000102030405060708090a0b0c0d0e0f1011121314151617')
    expected_ciphertext = bytearray.fromhex('dda97ca4864cdfe06eaf70a0ec0d7191')
    ciphertext = aes_encryption(plaintext, key)

    print(ciphertext == expected_ciphertext)

    # NIST AES-256 test vector 3 (Ch. C.3, p. 42)
    plaintext = bytearray.fromhex('00112233445566778899aabbccddeeff')
    key = bytearray.fromhex('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f')
    expected_ciphertext = bytearray.fromhex('8ea2b7ca516745bfeafc49904b496089')
    ciphertext = aes_encryption(plaintext, key)

    print(ciphertext == expected_ciphertext)