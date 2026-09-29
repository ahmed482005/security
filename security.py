import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import base64
import hashlib
import random
import math

# ===================== VIGENERE CIPHER =====================
class VigenereCipher:
    @staticmethod
    def encrypt(plaintext, key):
        if not key:
            return "Error: Key required"
        plaintext = plaintext.upper()
        key = key.upper()
        ciphertext = ""
        key_index = 0
        for ch in plaintext:
            if ch.isalpha():
                shift = ord(key[key_index % len(key)]) - ord('A')
                encrypted_char = chr((ord(ch) - ord('A') + shift) % 26 + ord('A'))
                ciphertext += encrypted_char
                key_index += 1
            else:
                ciphertext += ch
        return ciphertext

    @staticmethod
    def decrypt(ciphertext, key):
        if not key:
            return "Error: Key required"
        ciphertext = ciphertext.upper()
        key = key.upper()
        plaintext = ""
        key_index = 0
        for ch in ciphertext:
            if ch.isalpha():
                shift = ord(key[key_index % len(key)]) - ord('A')
                decrypted_char = chr((ord(ch) - ord('A') - shift) % 26 + ord('A'))
                plaintext += decrypted_char
                key_index += 1
            else:
                plaintext += ch
        return plaintext


# ===================== VERNAM CIPHER (XOR) =====================
class VernamCipher:
    @staticmethod
    def encrypt(plaintext, key):
        if len(key) < len(plaintext):
            return "Error: Key must be at least as long as plaintext"
        result = []
        for i in range(len(plaintext)):
            result.append(chr(ord(plaintext[i]) ^ ord(key[i])))
        return base64.b64encode(''.join(result).encode()).decode()

    @staticmethod
    def decrypt(ciphertext, key):
        try:
            decoded = base64.b64decode(ciphertext).decode()
        except:
            return "Error: Invalid ciphertext"
        if len(key) < len(decoded):
            return "Error: Key too short"
        result = []
        for i in range(len(decoded)):
            result.append(chr(ord(decoded[i]) ^ ord(key[i])))
        return ''.join(result)


# ===================== PLAYFAIR CIPHER =====================
class PlayfairCipher:
    def __init__(self):
        self.matrix = [['' for _ in range(5)] for _ in range(5)]

    def _prepare_key(self, key):
        key = key.upper().replace('J', 'I')
        processed_key = []
        seen = set()
        for ch in key:
            if ch.isalpha() and ch not in seen:
                seen.add(ch)
                processed_key.append(ch)
        for ch in 'ABCDEFGHIKLMNOPQRSTUVWXYZ':
            if ch not in seen:
                processed_key.append(ch)
        return processed_key

    def _build_matrix(self, key):
        prepared = self._prepare_key(key)
        for i in range(5):
            for j in range(5):
                self.matrix[i][j] = prepared[i * 5 + j]

    def _find_position(self, ch):
        for i in range(5):
            for j in range(5):
                if self.matrix[i][j] == ch:
                    return i, j
        return None

    def _prepare_text(self, text):
        text = text.upper().replace('J', 'I')
        text = ''.join([ch for ch in text if ch.isalpha()])
        result = []
        i = 0
        while i < len(text):
            if i + 1 < len(text):
                if text[i] == text[i + 1]:
                    result.append(text[i] + 'X')
                    i += 1
                else:
                    result.append(text[i] + text[i + 1])
                    i += 2
            else:
                result.append(text[i] + 'X')
                i += 1
        return result

    def encrypt(self, plaintext, key):
        if not key:
            return "Error: Key required"
        self._build_matrix(key)
        pairs = self._prepare_text(plaintext)
        ciphertext = ""
        for pair in pairs:
            a, b = pair[0], pair[1]
            r1, c1 = self._find_position(a)
            r2, c2 = self._find_position(b)
            if r1 == r2:
                ciphertext += self.matrix[r1][(c1 + 1) % 5]
                ciphertext += self.matrix[r2][(c2 + 1) % 5]
            elif c1 == c2:
                ciphertext += self.matrix[(r1 + 1) % 5][c1]
                ciphertext += self.matrix[(r2 + 1) % 5][c2]
            else:
                ciphertext += self.matrix[r1][c2]
                ciphertext += self.matrix[r2][c1]
        return ciphertext

    def decrypt(self, ciphertext, key):
        if not key:
            return "Error: Key required"
        self._build_matrix(key)
        pairs = self._prepare_text(ciphertext)
        plaintext = ""
        for pair in pairs:
            a, b = pair[0], pair[1]
            r1, c1 = self._find_position(a)
            r2, c2 = self._find_position(b)
            if r1 == r2:
                plaintext += self.matrix[r1][(c1 - 1) % 5]
                plaintext += self.matrix[r2][(c2 - 1) % 5]
            elif c1 == c2:
                plaintext += self.matrix[(r1 - 1) % 5][c1]
                plaintext += self.matrix[(r2 - 1) % 5][c2]
            else:
                plaintext += self.matrix[r1][c2]
                plaintext += self.matrix[r2][c1]
        # Remove padding X if present
        if plaintext.endswith('X'):
            plaintext = plaintext[:-1]
        return plaintext


# ===================== DES SIMULATION (using pycryptodome if available, else fallback) =====================
try:
    from Crypto.Cipher import DES, AES
    from Crypto.Util.Padding import pad, unpad
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False
    # Fallback simulation for DES/AES if pycryptodome not installed
    print("Warning: pycryptodome not installed. Using simulated DES/AES (insecure, for demo only).")
    print("Install with: pip install pycryptodome")


class DESCipher:
    @staticmethod
    def encrypt(plaintext, key):
        if not CRYPTO_AVAILABLE:
            return "Error: Install pycryptodome for real DES. Using fallback."
        if len(key) != 8:
            return "Error: DES key must be exactly 8 bytes (56-bit effective)"
        try:
            key_bytes = key.encode('utf-8')[:8].ljust(8, b'0')
            cipher = DES.new(key_bytes, DES.MODE_ECB)
            padded = pad(plaintext.encode(), 8)
            encrypted = cipher.encrypt(padded)
            return base64.b64encode(encrypted).decode()
        except Exception as e:
            return f"DES Error: {str(e)}"

    @staticmethod
    def decrypt(ciphertext, key):
        if not CRYPTO_AVAILABLE:
            return "Error: Install pycryptodome for real DES. Using fallback."
        if len(key) != 8:
            return "Error: DES key must be exactly 8 bytes"
        try:
            key_bytes = key.encode('utf-8')[:8].ljust(8, b'0')
            cipher = DES.new(key_bytes, DES.MODE_ECB)
            decoded = base64.b64decode(ciphertext)
            decrypted = cipher.decrypt(decoded)
            return unpad(decrypted, 8).decode()
        except Exception as e:
            return f"DES Decryption Error: {str(e)}"


class AESCipher:
    @staticmethod
    def encrypt(plaintext, key):
        if not CRYPTO_AVAILABLE:
            return "Error: Install pycryptodome for real AES. Using fallback."
        if len(key) != 16:
            return "Error: AES-128 key must be exactly 16 bytes (128-bit)"
        try:
            key_bytes = key.encode('utf-8')[:16].ljust(16, b'0')
            cipher = AES.new(key_bytes, AES.MODE_ECB)
            padded = pad(plaintext.encode(), 16)
            encrypted = cipher.encrypt(padded)
            return base64.b64encode(encrypted).decode()
        except Exception as e:
            return f"AES Error: {str(e)}"

    @staticmethod
    def decrypt(ciphertext, key):
        if not CRYPTO_AVAILABLE:
            return "Error: Install pycryptodome for real AES. Using fallback."
        if len(key) != 16:
            return "Error: AES key must be exactly 16 bytes"
        try:
            key_bytes = key.encode('utf-8')[:16].ljust(16, b'0')
            cipher = AES.new(key_bytes, AES.MODE_ECB)
            decoded = base64.b64decode(ciphertext)
            decrypted = cipher.decrypt(decoded)
            return unpad(decrypted, 16).decode()
        except Exception as e:
            return f"AES Decryption Error: {str(e)}"


# ===================== RC4 STREAM CIPHER =====================
class RC4Cipher:
    @staticmethod
    def _ksa(key):
        key_length = len(key)
        S = list(range(256))
        j = 0
        for i in range(256):
            j = (j + S[i] + key[i % key_length]) % 256
            S[i], S[j] = S[j], S[i]
        return S

    @staticmethod
    def _prga(S, data_length):
        i = j = 0
        keystream = []
        for _ in range(data_length):
            i = (i + 1) % 256
            j = (j + S[i]) % 256
            S[i], S[j] = S[j], S[i]
            keystream.append(S[(S[i] + S[j]) % 256])
        return keystream

    @staticmethod
    def encrypt(plaintext, key):
        if not key:
            return "Error: Key required"
        key_bytes = [ord(c) for c in key]
        S = RC4Cipher._ksa(key_bytes)
        keystream = RC4Cipher._prga(S[:], len(plaintext))
        result = []
        for i, ch in enumerate(plaintext):
            result.append(chr(ord(ch) ^ keystream[i]))
        return base64.b64encode(''.join(result).encode()).decode()

    @staticmethod
    def decrypt(ciphertext, key):
        try:
            decoded = base64.b64decode(ciphertext).decode()
        except:
            return "Error: Invalid ciphertext"
        return RC4Cipher.encrypt(decoded, key)


# ===================== RSA SIMULATION =====================
class RSACipher:
    @staticmethod
    def _generate_keys(key_size):
        # Simplified RSA for demonstration (small primes for performance)
        # Real RSA would use much larger primes
        p = 61 if key_size <= 1024 else 101
        q = 53 if key_size <= 1024 else 103
        n = p * q
        phi = (p - 1) * (q - 1)
        e = 65537
        d = pow(e, -1, phi)
        return (e, n), (d, n)

    @staticmethod
    def encrypt(plaintext, key):
        # key is (e, n) for encryption
        if not key:
            return "Error: RSA key required (use format: e,n)"
        try:
            parts = key.split(',')
            e = int(parts[0])
            n = int(parts[1])
        except:
            return "Error: Key must be in format 'e,n' (e.g., 65537,3233)"
        result = []
        for ch in plaintext:
            m = ord(ch)
            c = pow(m, e, n)
            result.append(str(c))
        return ','.join(result)

    @staticmethod
    def decrypt(ciphertext, key):
        # key is (d, n) for decryption
        if not key:
            return "Error: RSA key required (use format:d,n)"
        try:
            parts = key.split(',')
            d = int(parts[0])
            n = int(parts[1])
        except:
            return "Error: Key must be in format 'd,n'"
        try:
            numbers = [int(x) for x in ciphertext.split(',')]
            result = []
            for c in numbers:
                m = pow(c, d, n)
                result.append(chr(m))
            return ''.join(result)
        except:
            return "Error: Invalid ciphertext format"


# ===================== HASHING =====================
class Hashing:
    @staticmethod
    def compute_hash(text, algorithm):
        text_bytes = text.encode('utf-8')
        if algorithm == "MD5 (128-bit)":
            return hashlib.md5(text_bytes).hexdigest()
        elif algorithm == "SHA-1 (160-bit)":
            return hashlib.sha1(text_bytes).hexdigest()
        elif algorithm == "SHA-256 (256-bit)":
            return hashlib.sha256(text_bytes).hexdigest()
        return "Unknown algorithm"


# ===================== MAIN GUI APPLICATION =====================
class SecurityApp:
    def __init__(self, root):
        self.root = root
        root.title("Security Project 2026 - Encryption/Decryption Tool")
        root.geometry("900x700")
        root.resizable(True, True)

        # Available algorithms
        self.algorithms = [
            "Vigenère Cipher",
            "Vernam Cipher",
            "Playfair Cipher",
            "DES (64-bit block, 56-bit key)",
            "AES (128-bit block, 128-bit key)",
            "RC4 Stream Cipher",
            "RSA (1024/2048-bit)",
            "Hashing (MD5/SHA-1/SHA-256)"
        ]

        # For hash sub-algorithm selection
        self.hash_algorithms = ["MD5 (128-bit)", "SHA-1 (160-bit)", "SHA-256 (256-bit)"]

        self.create_widgets()

    def create_widgets(self):
        # Main frame
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        # Algorithm Selection
        ttk.Label(main_frame, text="Select Algorithm:", font=('Arial', 10, 'bold')).grid(row=0, column=0, sticky=tk.W, pady=5)
        self.algo_var = tk.StringVar()
        self.algo_combo = ttk.Combobox(main_frame, textvariable=self.algo_var, values=self.algorithms, width=35, state="readonly")
        self.algo_combo.grid(row=0, column=1, sticky=tk.W, pady=5, padx=5)
        self.algo_combo.bind('<<ComboboxSelected>>', self.on_algo_change)
        self.algo_combo.current(0)

        # Hash sub-algorithm selection (initially hidden)
        self.hash_frame = ttk.Frame(main_frame)
        self.hash_frame.grid(row=1, column=0, columnspan=2, sticky=tk.W, pady=5)
        ttk.Label(self.hash_frame, text="Hash Type:").pack(side=tk.LEFT, padx=5)
        self.hash_var = tk.StringVar()
        self.hash_combo = ttk.Combobox(self.hash_frame, textvariable=self.hash_var, values=self.hash_algorithms, width=20, state="readonly")
        self.hash_combo.pack(side=tk.LEFT, padx=5)
        self.hash_combo.current(0)
        self.hash_frame.grid_remove()

        # Key Info Label
        self.key_info_label = ttk.Label(main_frame, text="Key Requirements:", foreground="blue")
        self.key_info_label.grid(row=2, column=0, columnspan=2, sticky=tk.W, pady=5)

        # Plain Text
        ttk.Label(main_frame, text="Plain Text:", font=('Arial', 10, 'bold')).grid(row=3, column=0, sticky=tk.NW, pady=5)
        self.plain_text = scrolledtext.ScrolledText(main_frame, width=70, height=6, wrap=tk.WORD)
        self.plain_text.grid(row=3, column=1, padx=5, pady=5, sticky=(tk.W, tk.E))

        # Key
        ttk.Label(main_frame, text="Key:", font=('Arial', 10, 'bold')).grid(row=4, column=0, sticky=tk.W, pady=5)
        self.key_entry = ttk.Entry(main_frame, width=70)
        self.key_entry.grid(row=4, column=1, padx=5, pady=5, sticky=(tk.W, tk.E))

        # Cipher Text
        ttk.Label(main_frame, text="Cipher Text:", font=('Arial', 10, 'bold')).grid(row=5, column=0, sticky=tk.NW, pady=5)
        self.cipher_text = scrolledtext.ScrolledText(main_frame, width=70, height=6, wrap=tk.WORD)
        self.cipher_text.grid(row=5, column=1, padx=5, pady=5, sticky=(tk.W, tk.E))

        # Buttons Frame
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=6, column=0, columnspan=2, pady=15)

        self.encrypt_btn = ttk.Button(button_frame, text="ENCRYPT", command=self.encrypt, width=15)
        self.encrypt_btn.pack(side=tk.LEFT, padx=10)

        self.decrypt_btn = ttk.Button(button_frame, text="DECRYPT", command=self.decrypt, width=15)
        self.decrypt_btn.pack(side=tk.LEFT, padx=10)

        self.clear_btn = ttk.Button(button_frame, text="CLEAR ALL", command=self.clear_all, width=15)
        self.clear_btn.pack(side=tk.LEFT, padx=10)

        # Status Bar
        self.status_var = tk.StringVar()
        self.status_var.set("Ready")
        status_bar = ttk.Label(self.root, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        status_bar.grid(row=1, column=0, sticky=(tk.W, tk.E))

        # Configure grid weights
        self.root.columnconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)

        self.update_key_info()

    def on_algo_change(self, event=None):
        self.update_key_info()
        if self.algo_var.get().startswith("Hashing"):
            self.hash_frame.grid()
        else:
            self.hash_frame.grid_remove()

    def update_key_info(self):
        algo = self.algo_var.get()
        if "Vigenère" in algo:
            self.key_info_label.config(text="Key: Any length of alphabetic characters (case-insensitive)")
        elif "Vernam" in algo:
            self.key_info_label.config(text="Key: Must be at least as long as plaintext")
        elif "Playfair" in algo:
            self.key_info_label.config(text="Key: Any alphabetic string (J becomes I)")
        elif "DES" in algo:
            self.key_info_label.config(text="Key: Exactly 8 characters (64-bit, 56-bit effective)")
        elif "AES" in algo:
            self.key_info_label.config(text="Key: Exactly 16 characters (128-bit)")
        elif "RC4" in algo:
            self.key_info_label.config(text="Key: Any length (variable key stream cipher)")
        elif "RSA" in algo:
            self.key_info_label.config(text="Key: Use 'e,n' for encryption or 'd,n' for decryption (e.g., 65537,3233)")
        elif "Hashing" in algo:
            self.key_info_label.config(text="Hashing: No key required (select hash type below)")
        else:
            self.key_info_label.config(text="Key requirements vary by algorithm")

    def get_current_hash_type(self):
        return self.hash_var.get()

    def encrypt(self):
        plain = self.plain_text.get("1.0", tk.END).strip()
        key = self.key_entry.get().strip()
        algo = self.algo_var.get()

        if not plain:
            messagebox.showwarning("Input Error", "Please enter plain text")
            return

        result = ""
        try:
            if "Vigenère" in algo:
                result = VigenereCipher.encrypt(plain, key)
            elif "Vernam" in algo:
                if len(key) < len(plain):
                    messagebox.showerror("Key Error", "Vernam cipher requires key at least as long as plaintext")
                    return
                result = VernamCipher.encrypt(plain, key)
            elif "Playfair" in algo:
                result = PlayfairCipher().encrypt(plain, key)
            elif "DES" in algo:
                if len(key) != 8:
                    messagebox.showerror("Key Error", "DES requires exactly 8-character key")
                    return
                result = DESCipher.encrypt(plain, key)
            elif "AES" in algo:
                if len(key) != 16:
                    messagebox.showerror("Key Error", "AES-128 requires exactly 16-character key")
                    return
                result = AESCipher.encrypt(plain, key)
            elif "RC4" in algo:
                result = RC4Cipher.encrypt(plain, key)
            elif "RSA" in algo:
                result = RSACipher.encrypt(plain, key)
            elif "Hashing" in algo:
                hash_type = self.get_current_hash_type()
                result = Hashing.compute_hash(plain, hash_type)
                self.cipher_text.delete("1.0", tk.END)
                self.cipher_text.insert("1.0", result)
                self.status_var.set(f"Hash computed: {hash_type}")
                return
            else:
                result = "Algorithm not implemented"

            self.cipher_text.delete("1.0", tk.END)
            self.cipher_text.insert("1.0", result)
            self.status_var.set(f"Encrypted using {algo}")
        except Exception as e:
            messagebox.showerror("Encryption Error", str(e))
            self.status_var.set("Encryption failed")

    def decrypt(self):
        cipher = self.cipher_text.get("1.0", tk.END).strip()
        key = self.key_entry.get().strip()
        algo = self.algo_var.get()

        if not cipher:
            messagebox.showwarning("Input Error", "Please enter cipher text")
            return

        if "Hashing" in algo:
            messagebox.showinfo("Info", "Hashing is one-way. Decryption not available.")
            return

        result = ""
        try:
            if "Vigenère" in algo:
                result = VigenereCipher.decrypt(cipher, key)
            elif "Vernam" in algo:
                result = VernamCipher.decrypt(cipher, key)
            elif "Playfair" in algo:
                result = PlayfairCipher().decrypt(cipher, key)
            elif "DES" in algo:
                if len(key) != 8:
                    messagebox.showerror("Key Error", "DES requires exactly 8-character key")
                    return
                result = DESCipher.decrypt(cipher, key)
            elif "AES" in algo:
                if len(key) != 16:
                    messagebox.showerror("Key Error", "AES-128 requires exactly 16-character key")
                    return
                result = AESCipher.decrypt(cipher, key)
            elif "RC4" in algo:
                result = RC4Cipher.decrypt(cipher, key)
            elif "RSA" in algo:
                result = RSACipher.decrypt(cipher, key)
            else:
                result = "Algorithm not implemented"

            self.plain_text.delete("1.0", tk.END)
            self.plain_text.insert("1.0", result)
            self.status_var.set(f"Decrypted using {algo}")
        except Exception as e:
            messagebox.showerror("Decryption Error", str(e))
            self.status_var.set("Decryption failed")

    def clear_all(self):
        self.plain_text.delete("1.0", tk.END)
        self.key_entry.delete(0, tk.END)
        self.cipher_text.delete("1.0", tk.END)
        self.status_var.set("Cleared all fields")


if __name__ == "__main__":
    root = tk.Tk()
    app = SecurityApp(root)
    root.mainloop()