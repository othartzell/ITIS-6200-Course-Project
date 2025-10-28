# Owen Hartzell ohartzel@charlotte.edu

# ITIS 6200 Course Project: Implementing AES-CBC Mode encryption from scratch

'''
REFERENCES
    General Research
    - NIST Advanced Encryption Standards (AES): https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf
    - NIST Cryptographic Standards and Guidelines: https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines/example-values
    - NIST Block Cipher Modes of Operation, Cipher Block Chaining (CBC): https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/TDES_CBC.pdf

    From Professor Cyrill Gössi's cryptography with python lectures on YouTube
    - Professor Gössi's personal website: https://goescy.ch/
    - Professor Gössi's YouTube channel: https://www.youtube.com/@cyrillgossi

    - AES-ECB/CBC Implementation in Python
        - Part 2: https://www.youtube.com/watch?v=UAod6uRzxZM&t=31s
'''

# === Implementing an AES-CBC encryption scheme that follows NIST standards ===

# === Imports ===
from AES import aes_encryption, aes_decryption, xor_bytes

# === Constants ===
block_size = 16

# === PKCS7 Padding Functions ===
'''
Function to pad data
    - Calculates how many bytes are needed
    - Adds padding bytes to plaintext
'''
def pad(data: bytes) -> bytes:
    padding_length = block_size - (len(data) % block_size)
    return data + bytes([padding_length] * padding_length)

'''
Function to unpad data
    - Checks the last byte for padding length
    - Verifies the padding bytes are all the same
'''
def unpad(data: bytes) -> bytes:
    if not data or len(data) % block_size != 0:
        raise ValueError("Ciphertext data is not valid")
    
    padding_length = data[-1]
    if padding_length < 1 or padding_length > block_size:
        raise ValueError("Invalid padding length")

    if data[-padding_length:] != bytes([padding_length] * padding_length):
        raise ValueError("Invalid padding")
    
    return data[:-padding_length]
'''
Encrypts plaintext using AES-CBC Mode
    - Takes in the plaintext data, an encryption key, and initialization vector
    - Returns ciphertext as bytes
'''
def cbc_encrypt(plaintext: bytes, key: bytes, iv: bytes):
    plaintext = pad(plaintext)
    ciphertext = bytearray()
    previous_block = iv

    # Looping through every 16 byte block to perform encryption
    for j in range(0, len(plaintext), block_size):
        block = plaintext[j:j+block_size]
        # Performing XOR operation with previous ciphertext or IV for first block to add entrophy
        xored_bytes = bytes(xor_bytes(list(block), list(previous_block)))
        # Encrypting the block
        encrypted_block = aes_encryption(xored_bytes, key)
        ciphertext.extend(encrypted_block)
        previous_block = encrypted_block

    return bytes(ciphertext)

'''
Decrypts plaintext using AES-CBC Mode
    - Takes in the ciphertext data, encryption key, and initialization vector
    - Returns the plaintext as bytes
'''
def cbc_decrypt(ciphertext: bytes, key: bytes, iv: bytes):
    plaintext = bytearray()
    previous_block = iv

    # Looping through every 16 byte block to perform decryption
    for j in range(0, len(ciphertext), block_size):
        block = ciphertext[j:j+block_size]
        # Decrypt block
        decrypted_block = aes_decryption(block, key)
        # XOR with previous ciphertext (or IV for first block)
        plain_block = bytes(xor_bytes(list(decrypted_block), list(previous_block)))
        plaintext.extend(plain_block)
        previous_block = block

    return unpad(bytes(plaintext))