# Owen Hartzell ohartzel@charlotte.edu

# ITIS 6200 Course Project: Implementing AES-CBC Mode encryption from scratch

'''
REFERENCES
    General Research
    - Basic implementation of AES encryption with padding in python: https://www.askpython.com/python/examples/implementing-aes-with-padding
    - PKCS7 padding in python: https://stackoverflow.com/questions/43199123/encrypting-with-aes-256-and-pkcs7-padding
    - XOR operator in python: https://docs.python.org/3/reference/expressions.html
    - NIST Advanced Encryption Standard (AES) Publication: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf
'''

# === Imports ===
import os
import tkinter as tk
from tkinter import filedialog, messagebox
from AES import aes_encryption, aes_decryption, xor_bytes
from CBC import cbc_encrypt, cbc_decrypt

# === Constants ===

# 16 byte blocks for AES
block_size = 16
# 16 bytes of salt to add to user inputted password
salt_size = 16

# === AES-CBC Mode helper functions ===

'''
To do: Implement KDF to generate key and iv
'''
def get_secrets(password: str):
    pass
'''
To do: Implement a hash function to hash password + salt
'''
def hash_password(password: str, salt: bytes):
    pass

# === Wrappers for CBC encryption/decryption ===
def encrypt(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    return cbc_encrypt(plaintext, key, iv)

def decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    return cbc_decrypt(ciphertext, key, iv)

# === Simple GUI to demonstrate encrypting and decrypting files ===
class Encryptonator9000:
    def __init__(self, root):
        self.root = root
        self.root.title("Encryptonator 9000")
        self.root.geometry("500x250")
        self.filepath = None

        # === UI setup ===
        tk.Label(root, text="No file selected", wraplength=400)\
            .grid(row=0, column=0, columnspan=2, pady=5)
        self.file_label = tk.Label(root, text="")
        tk.Button(root, text="Select File", command=self.select_file)\
            .grid(row=1, column=0, columnspan=2, pady=5)

        tk.Label(root, text="Password:").grid(row=2, column=0, pady=5)
        self.password_entry = tk.Entry(root, show="*", width=40)
        self.password_entry.grid(row=2, column=1, pady=5)

        tk.Button(root, text="Encrypt", command=self.encrypt_file)\
            .grid(row=3, column=0, padx=10, pady=10)
        tk.Button(root, text="Decrypt", command=self.decrypt_file)\
            .grid(row=3, column=1, padx=10, pady=10)

    def select_file(self):
        path = filedialog.askopenfilename()
        if path:
            self.filepath = path
            self.file_label.config(text=path)

    def encrypt_file(self):
        if not self.filepath:
            messagebox.showerror("Error", "Please select a file.")
            return
        password = self.password_entry.get()
        if not password:
            messagebox.showerror("Error", "Please enter a password.")
            return

        with open(self.filepath, "rb") as f:
            plaintext = f.read()

        # === derive secrets ===
        key, iv, salt = get_secrets(password)
        password_hash = hash_password(password, salt)

        ciphertext = cbc_encrypt(plaintext, key, iv)

        # prepend salt + hash to ciphertext for storage
        encrypted = salt + password_hash + ciphertext
        with open(self.filepath + ".enc", "wb") as f:
            f.write(encrypted)

        messagebox.showinfo("Success", "File encrypted successfully!")

    def decrypt_file(self):
        if not self.filepath:
            messagebox.showerror("Error", "Please select a file.")
            return
        password = self.password_entry.get()
        if not password:
            messagebox.showerror("Error", "Please enter a password.")
            return

        with open(self.filepath, "rb") as f:
            data = f.read()

        salt = data[:16]
        stored_hash = data[16:48]
        ciphertext = data[48:]

        if hash_password(password, salt) != stored_hash:
            messagebox.showerror("Error", "Invalid password.")
            return

        key, iv, _ = get_secrets(password, salt)
        plaintext = cbc_decrypt(ciphertext, key, iv)

        with open(self.filepath.replace(".enc", ".dec"), "wb") as f:
            f.write(plaintext)

        messagebox.showinfo("Success", "File decrypted successfully!")

# === Run ===
if __name__ == "__main__":
    root = tk.Tk()
    app = Encryptonator9000(root)
    root.mainloop()