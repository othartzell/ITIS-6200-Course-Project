# Owen Hartzell ohartzel@charlotte.edu

# ITIS 6200 Course Project: Implementing AES-CBC Mode encryption from scratch

'''
REFERENCES
    General Research
    - Basic implementation of AES encryption with padding in python: https://www.askpython.com/python/examples/implementing-aes-with-padding
    - PKCS7 padding in python: https://stackoverflow.com/questions/43199123/encrypting-with-aes-256-and-pkcs7-padding
    - XOR operator in python: https://docs.python.org/3/reference/expressions.html
    - NIST Advanced Encryption Standard (AES) Publication: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf
    - NIST Secure Hash Standard (SHS): https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf
'''

# === Imports ===
from typing import Optional, Tuple
import os
import tkinter as tk
from tkinter import filedialog, messagebox

from CBC import cbc_encrypt, cbc_decrypt
from Hash import SHA256

# === Constants ===

# 16 byte blocks for AES
block_size = 16
# 16 bytes of salt to add to user inputted password
salt_size = 16

# === AES-CBC Mode helper functions ===

'''
Simple KDF function to generate secret values for encryption and decryption
'''
def get_secrets(password: str, salt: Optional[bytes] = None) -> Tuple[bytes, bytes, bytes]:
    if salt is None:
        salt = os.urandom(salt_size)

    key_material = password.encode() + salt
    for _ in range(10000):
        key_material = SHA256(key_material)

    key = key_material[:32]
    iv = SHA256(key_material + salt)[:16]

    return key, iv, salt

# Using from scratch SHA256 hash function to hash the inputted password
def hash_password(password: str, salt: bytes):
        return SHA256(password.encode() + salt)

# === Wrappers for CBC encryption/decryption ===
def encrypt(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    return cbc_encrypt(plaintext, key, iv)

def decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    return cbc_decrypt(ciphertext, key, iv)

# === Simple GUI to demonstrate encrypting and decrypting files ===
class Encryptonator9000:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("Encryptonator 9000")
        self.root.geometry("500x250")
        self.filepath: Optional[str] = None

        self.file_label = tk.Label(root, text="No file selected", wraplength=400)
        self.file_label.grid(row=0, column=0, columnspan=2, pady=5)
        tk.Button(root, text="Select File", command=self.select_file).grid(row=1, column=0, columnspan=2, pady=5)

        tk.Label(root, text="Password:").grid(row=2, column=0, pady=5)
        self.password_entry = tk.Entry(root, show="*", width=40)
        self.password_entry.grid(row=2, column=1, pady=5)

        tk.Button(root, text="Encrypt", command=self.encrypt_file).grid(row=3, column=0, padx=10, pady=10)
        tk.Button(root, text="Decrypt", command=self.decrypt_file).grid(row=3, column=1, padx=10, pady=10)

    def select_file(self) -> None:
        path = filedialog.askopenfilename()
        if path:
            self.filepath = path
            self.file_label.config(text=os.path.basename(path))
        else:
            self.filepath = None
            self.file_label.config(text="No file selected")

    def encrypt_file(self) -> None:
        if not self.filepath:
            messagebox.showerror("Error", "Please select a file.")
            return
        password = self.password_entry.get()
        if not password:
            messagebox.showerror("Error", "Please enter a password.")
            return

        try:
            with open(self.filepath, "rb") as f:
                plaintext = f.read()

            key, iv, salt = get_secrets(password)
            password_hash = hash_password(password, salt)
            ciphertext = cbc_encrypt(plaintext, key, iv)

            with open(self.filepath, "wb") as f:
                f.write(salt + password_hash + ciphertext)
            messagebox.showinfo("Success", f"File overwritten:\n{os.path.basename(self.filepath)}")

        except Exception as e:
            messagebox.showerror("Encryption Error", str(e))
        finally:
            self.file_label.config(text="No file selected")
            self.password_entry.delete(0, tk.END)

    def decrypt_file(self) -> None:
        if not self.filepath:
            messagebox.showerror("Error", "Please select a file.")
            return
        password = self.password_entry.get()
        if not password:
            messagebox.showerror("Error", "Please enter a password.")
            return

        try:
            with open(self.filepath, "rb") as f:
                data = f.read()

            salt = data[:salt_size]
            stored_hash = data[salt_size:salt_size + 32]
            ciphertext = data[salt_size + 32:]

            if hash_password(password, salt) != stored_hash:
                messagebox.showerror("Error", "Invalid password.")
                return

            key, iv, _ = get_secrets(password, salt)
            plaintext = cbc_decrypt(ciphertext, key, iv)

            output_path = self.filepath
            with open(output_path, "wb") as f:
                f.write(plaintext)

            messagebox.showinfo("Success", f"File decrypted successfully:\n{os.path.basename(output_path)}")

        except Exception as e:
            messagebox.showerror("Decryption Error", f"Failed to decrypt: {e}")
        finally:
            self.file_label.config(text="No file selected")
            self.password_entry.delete(0, tk.END)

# === Run ===
if __name__ == "__main__":
    root = tk.Tk()
    app = Encryptonator9000(root)
    root.mainloop()