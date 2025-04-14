import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog
from cryptography.hazmat.primitives import serialization, hashes
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
    
    def decrypt_private_key(self, pin):
        try:
            if not len(pin.encode('utf-8')) == 16:
                messagebox.showerror("Error", f"PIN number has to have 16 bytes")
                return None
        
            with open("encrypted", "rb") as key_file:
                encrypted_key = eval(key_file.read())
        
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
    
    def sign_pdf(self):
        file = self.open_file()
        if file:
            pin = self.get_pin()
            private_key = self.decrypt_private_key(pin)
            
            print("Debug: <<pdf sign>>")
            
        else:
            messagebox.showerror("Error", "No file selected")
        return
    
    def verify_pdf(self):
        file = self.open_file()
        if file:
            loading_window = tk.Toplevel(self.root)
            loading_window.geometry("200x50")
            tk.Label(loading_window, text="Reading file").pack(pady=10)
            loading_window.update()
            
            self.root.after(1000, loading_window.destroy)
        
            pub_key = self.get_pub_key()
            messagebox.showinfo("Info", f"File: {file}\nPin: {pub_key}")
        else:
            messagebox.showerror("Error", "No file selected")
        return