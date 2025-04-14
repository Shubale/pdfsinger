import tkinter as tk
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

BLOCK_SIZE = 32

def validate_pin(s):
    return len(s.encode('utf-8')) == 16

def generate_rsa_pair(s):
    if not validate_pin(s):
        print('You PIN number has to have 16 bytes; currently ' + str(len(s.encode('utf-8'))))
        return
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096
    )
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_key = private_key.public_key()
    digest = hashes.Hash(hashes.SHA256())
    digest.update(s.encode('utf-8'))
    key = digest.finalize()

    cipher = AES.new(key, AES.MODE_ECB)
    ciphertext = cipher.encrypt(pad(pem, BLOCK_SIZE))
    f = open("encrypted", "w")
    f.write(str(ciphertext))
    f.close()
    f = open("encrypted.pub", "w")
    f.write(str(public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )))
    f.close()
    decrypt_cipher = AES.new(key, AES.MODE_ECB)
    decrypted = (unpad(decrypt_cipher.decrypt(ciphertext), BLOCK_SIZE))
    return decrypted

def main():
    root = tk.Tk()
    root.geometry("300x600")
    root.columnconfigure(0, weight=1)
    root.columnconfigure(1, weight=1)
    root.columnconfigure(2, weight=1)

    label = tk.Label(root, text='Hello, Tkinter!')
    pin_entry = tk.Entry(root)
    generate_rsa_button = tk.Button(
        root,
        text="Generate RSA Key pair",
        command=lambda: generate_rsa_pair(pin_entry.get())
    )
    pin_entry.grid(row=0, column=1)
    generate_rsa_button.grid(row=1, column=1)

    root.mainloop()


if __name__ == "__main__":
    main()