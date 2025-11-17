# ITIS-6200-Course-Project
This project demonstrates understanding of symmetric cryptography by implementing AES-CBC Mode from scratch in Python to encrypt and decrypt files locally on a machine. This project includes three major components. 

1. AES Block Cipher
A NIST compliant from scratch implementation of AES encryption and decryption in python, includes the following functions outlined by NIST:
- State matrix construction
- SubBytes
- Shift Rows
- MixColumns and InvMixColumns
- AddRoundKey
- Key expansion with Rcon, RotWord, and SubWord
- S-box and inverse S-box lookup tables
This AES implementation is the ECB primitive for CBC mode.

2. AES-CBC Mode Encryption
A NIST compliant from scratch implementation of Cipher Block Chaining, includes the following functions outlined by NIST:
- PKCS#7 padding
- XOR with previous ciphertext block or IV
- Block by block AES encryption
- CBC decrypting with unpadding
CBC mode is used to introduce randomness and diffusion to the AES block cipher.

3. SHA-256 Hash Function
A NIST compliant from scratch implementation of SHA-256 cryptographic hashing, includes the following functions outlined by NIST:
- Message preprocessing for byte conversion, padding, and length encoding
- Message schedule construction
- Choose
- Majority
- Little sigma 0 and 1
- Big sigma 0 and 1
- 64 rounds of mixing
- Final 256 bit digest construction
This hash function is used to generate secret values for encryption/decryption and securely storing the password with salt to decrypt a file. 

Code Breakdown

AES Module Key Functions:
- state_from_bytes() Converts 16 bytes into a 4x4 AES state matrix
- bytes_from_state() Converts an AES state matrix into 16 bytes
- xor_bytes() XOR function to be used in AES operations
- xtime() Finite-field multiplication by x for AES primitive
- rot_word() Rotates a word for key expansion
- sub_word() Applies S-box substitution to a word
- rcon() Produces round constants
- key_expansion() Generates all AES round keys
- sub_bytes() and inv_sub_bytes() Performs byte substitution for encryption or decryption
- shift_rows() and inv_shift_rows() Performs a row permutation for encryption or decryption
- mix_columns() and inv_mix_columns() Performs Galois-field column mixing for encryption or decryption
- aes_encryption() AES encryption for a single block
- aes_decryption() AES decryption for a single block

AES-CBC Module Key Functions:
- pad() Applies PKCS#7 padding to plaintext
- unpad() Validates and removes padding from ciphertext
- cbc_encrypt() XOR + AES encryption in CBC mode
- cbc_decrypt() AES decrypt + XOR + unpad
CBC mode requires a key, IV, and plaintext/ciphertext

SHA-256 Module Key Functions:
- H_0_words The eight 32-bit initial hash state defined by NIST
- H_0() Returns a copy of the initial state for each hash computation
- SHA256_Pad_Parse(message) Implements the required preprocessing steps of padding, parsing, and splitting the message into words
- rotr(x, n) Circular right rotation
- shr(x, n) Logical right shift
- sig_1(x) Small sigma-1 as defined by NIST
- sig_0(x) Small sigma-0 as defined by NIST
- Sig_1(x) Big sigma-1 as defined by NIST
- Sig_0(x) Big sigma-0 as defined by NIST
- Ch(x, y, z) Choose function that selects bits from y or z based on x
- Maj(x, y, z) Majority function which mixes the working variables
- K NIST 64 predefined 32-bit constants as a 256 byte table
- K256 NIST 64 constants converted to Python integers
- SHA256(message) Full SHA-256 implementation

Testing and Validation
All AES round transformations, CBC and padding behavior, and the SHA-256 hash function were validated using NIST test vectors. These test vectors are seen within the Testing directory

How to use this program
encryptonator9000.py is the main program file. In this file there is a simple GUI implementation using tkinter. By running this file, the program will allow a user to select a file to encrypt or decrypt on their machine. The user inputs a password before encryption and must enter the same password for decryption. Passwords are processes through the from scratch SHA-256 implementation to derive encryption keys and are stored as salted hashes.

Repository Structure
/ITIS-6200-COURSE-PROJECT
├── Testing/    Test files to show NIST test vectors
├── AES.py  AES Block cipher implementation
├── CBC.py  CBC Mode implementation
├── Encryptonator9000.py    Main program
└── Hash.py     SHA-256 Hash implementation

References:
General Research
- NIST Advanced Encryption Standards (AES): https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf
- NIST Cryptographic Standards and Guidelines: https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines/example-values
- NIST Block Cipher Modes of Operation, Cipher Block Chaining (CBC): https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/TDES_CBC.pdf
- NIST Secure Hash Standard (SHS): https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf
- Basic implementation of AES encryption with padding in python: https://www.askpython.com/python/examples/implementing-aes-with-padding
- PKCS7 padding in python: https://stackoverflow.com/questions/43199123/encrypting-with-aes-256-and-pkcs7-padding
- XOR operator in python: https://docs.python.org/3/reference/expressions.html

From Professor Cyrill Gössi's cryptography with python lectures on YouTube
- Professor Gössi's personal website: https://goescy.ch/
- Professor Gössi's YouTube channel: https://www.youtube.com/@cyrillgossi

- AES implementation in python
    - Part 1: https://www.youtube.com/watch?v=1gCD1pZKc04
    - Part 2: https://www.youtube.com/watch?v=kZv7S9mNXDk
    - Part 3: https://www.youtube.com/watch?v=blCA51nsVk8
    - Part 4: https://www.youtube.com/watch?v=hXFhi2zD_W4
    - Part 5: https://www.youtube.com/watch?v=tyhl7EYmJoM

- AES-ECB/CBC Implementation in Python
    - Part 2: https://www.youtube.com/watch?v=UAod6uRzxZM&t=31s

- Implementing SHA-256 in Python
    - Part 1: https://www.youtube.com/watch?v=U3jEmc-L58Y
    - Part 2: https://www.youtube.com/watch?v=dNX3MSJnuPw


Security Disclaimer:
This code is not cryptographically secure for real world implementations. This project is to show proof of concept and understanding by implementing the logic for AES-CBC and Hashing from scratch. Vulnerabilities to timing attacks, side channel attacks, weak randomness, and more may be exploitable.
