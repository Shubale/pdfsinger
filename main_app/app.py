import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

class App():
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("BSK")
        self.root.geometry("200x150")
        self.mainframe = tk.Frame(self.root, bg="white")
        self.mainframe.pack(fill=tk.BOTH, expand=True)
        
        self.sign_button = tk.Button(self.mainframe, text="Sign PDF", command=self.sign_pdf)
        self.sign_button.pack(pady=20)
        
        self.verify_button = tk.Button(self.mainframe, text="Verify Signature", command=self.verify_pdf)
        self.verify_button.pack(pady=20)
        
        self.root.mainloop()
        
    def open_file(self):
        file_path = filedialog.askopenfilename(filetypes=[("PDF files", "*.pdf")])
        return file_path
    
    def decrypt_private_key(self, pin, encrypted_key):
        try:
            if not len(pin.encode('utf-8')) == 16:
                messagebox.showerror("Error", f"PIN number has to have 16 bytes")
                return None
        
            digest = hashes.Hash(hashes.SHA256())
            digest.update(pin.encode('utf-8'))
            key = digest.finalize()
        
            cipher = AES.new(key, AES.MODE_ECB)
        
            decrypted_pem = unpad(cipher.decrypt(encrypted_key), 32)  # BLOCK_SIZE = 32
        
            private_key = serialization.load_pem_private_key(
                decrypted_pem,
                password=None
            )
            print("Debug: PIN is correct!")
            return private_key
        except Exception as e:
            messagebox.showerror("Error", f"Failed to decrypt private key: {e}")
            return None
    
    def get_pin(self):
        pin = simpledialog.askstring("PIN", "Enter pin:", show="*")
        return pin
    
    def read_private_key(self, pin):
        usb_path = "G:\\encrypted"
        try:
            with open(usb_path, "rb") as f:
                key = f.read()
                return self.decrypt_private_key(pin, key)
        except:
            messagebox.showerror("Error", "Failed to read private key file")
            return None
    
    def sign_pdf(self):
        file_path = self.open_file()
        
        if not file_path:
            messagebox.showerror("Error", "No file selected")
            return

        pin = self.get_pin()
        if not pin:
            return

        private_key = self.read_private_key(pin)
        if not private_key:
            return

        with open(file_path, "rb") as f:
            pdf_data = f.read()

        digest = hashes.Hash(hashes.SHA256())
        digest.update(pdf_data)
        hash_bytes = digest.finalize()

        signature = private_key.sign(
            hash_bytes,
            padding.PKCS1v15(),
            hashes.SHA256()
        )

        with open(file_path, "ab") as f:
            f.write(signature)

        messagebox.showinfo("Success", "PDF file signed!")
    
    def get_pub_key(self):
        try:
            with open("encrypted.pub", "rb") as pub_file:
                pub_data = pub_file.read()
                pub_key = serialization.load_pem_public_key(pub_data)
                return pub_key
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load public key! {e}")
            return
        
    def verify_pdf(self):
        try:
            file_path = self.open_file()
            if not file_path:
                messagebox.showerror("Error", "No file selected")
                return

            with open(file_path, "rb") as f:
                full_data = f.read()
                
            pub_key = self.get_pub_key()
            if not pub_key:
                return
            
            SIGNATURE_LENGTH = pub_key.key_size // 8

            pdf_data = full_data[:-SIGNATURE_LENGTH]
            signature = full_data[-SIGNATURE_LENGTH:]

            digest = hashes.Hash(hashes.SHA256())
            digest.update(pdf_data)
            expected_hash = digest.finalize()
            
            pub_key.verify(
                signature,
                expected_hash,
                padding.PKCS1v15(),
                hashes.SHA256()
            )
            messagebox.showinfo("Success", "Signature is valid!")
        except Exception as e:
            messagebox.showerror("Error", f"Signature is invalid! {e}")
        
        