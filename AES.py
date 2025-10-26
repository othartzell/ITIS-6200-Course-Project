# Owen Hartzell ohartzel@charlotte.edu

# ITIS 6200 Course Project: Implementing AES-CBC Mode encryption from scratch

# AES encryption scheme from scratch
def aes_encryption(plaintext, key):
    pass


if __name__ == "__main__":

    # NIST AES-128 test vector C.1 (p.35)
    plaintext = bytearray.fromhex('00112233445566778899aabbccddeeff')
    key = bytearray.fromhex('000102030405060708090a0b0c0d0e0f')
    expected_ciphertext = bytearray.fromhex('69c4e0d86a7b0430d8cdb78070b4c55a')
    ciphertext = aes_encryption(plaintext, key)