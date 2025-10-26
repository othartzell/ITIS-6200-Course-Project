# Owen Hartzell ohartzel@charlotte.edu

# ITIS 6200 Course Project: Implementing AES-CBC Mode encryption from scratch

# AES encryption scheme from scratch
def aes_encryption(data: bytes, key: bytes) -> bytes:

    return b''


if __name__ == "__main__":

    # NIST AES-128 test vector C.1 (p.35)
    plaintext = bytearray.fromhex('00112233445566778899aabbccddeeff')
    key = bytearray.fromhex('000102030405060708090a0b0c0d0e0f')
    expected_ciphertext = bytearray.fromhex('69c4e0d86a7b0430d8cdb78070b4c55a')
    ciphertext = aes_encryption(plaintext, key)

    assert (ciphertext == expected_ciphertext)

    # NIST AES-192 test vector C.2 (p.38)
    plaintext = bytearray.fromhex('00112233445566778899aabbccddeeff')
    key = bytearray.fromhex('000102030405060708090a0b0c0d0e0f1011121314151617')
    expected_ciphertext = bytearray.fromhex('dda97ca4864cdfe06eaf70a0ec0d7191')
    ciphertext = aes_encryption(plaintext, key)

    assert (ciphertext == expected_ciphertext)

    # NIST AES-256 test vector 3 (Ch. C.3, p. 42)
    plaintext = bytearray.fromhex('00112233445566778899aabbccddeeff')
    key = bytearray.fromhex('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f')
    expected_ciphertext = bytearray.fromhex('8ea2b7ca516745bfeafc49904b496089')
    ciphertext = aes_encryption(plaintext, key)

    assert (ciphertext == expected_ciphertext)