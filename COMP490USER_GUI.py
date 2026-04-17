import os
import base64
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog

import requests
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

SERVER_URL = os.environ.get("SERVER_URL", "http://127.0.0.1:5000")
KEY_DIR = "client_keys"
os.makedirs(KEY_DIR, exist_ok=True)


def private_key_path_for_user(username):
    return os.path.join(KEY_DIR, f"{username}_private.pem")


def resolve_private_key_path(username):
    preferred = private_key_path_for_user(username)
    legacy = f"{username}_private.pem"
    if os.path.exists(preferred):
        return preferred
    if os.path.exists(legacy):
        return legacy
    return preferred


def encrypt_with_rsa(public_pem, data):
    public_key = serialization.load_pem_public_key(public_pem.encode())
    encrypted = public_key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return base64.b64encode(encrypted).decode()


def decrypt_with_rsa(private_key_path, encrypted_data, passphrase):
    with open(private_key_path, "rb") as f:
        key_bytes = f.read()

    password_bytes = passphrase.encode() if passphrase else None
    private_key = serialization.load_pem_private_key(key_bytes, password=password_bytes)

    decoded = base64.b64decode(encrypted_data)
    return private_key.decrypt(
        decoded,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def encrypt_message(aes_key, plaintext):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext.encode()) + encryptor.finalize()
    return base64.b64encode(iv + ciphertext).decode()


def decrypt_message(aes_key, encrypted_data):
    raw = base64.b64decode(encrypted_data)
    iv = raw[:16]
    ciphertext = raw[16:]
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv))
    decryptor = cipher.decryptor()
    return (decryptor.update(ciphertext) + decryptor.finalize()).decode()


class SecureMessagingDesktop:
    def __init__(self, root):
        self.root = root
        self.root.title("COMP490 Secure Messaging Desktop")
        self.root.geometry("980x650")

        self.session = requests.Session()
        self.current_user = None
        self.passphrase = ""
        self.active_chat_user = None
        self.aes_keys = {}

        self._build_ui()

    def _build_ui(self):
        top = ttk.Frame(self.root, padding=10)
        top.pack(fill=tk.X)

        ttk.Label(top, text="Username:").grid(row=0, column=0, padx=4)
        self.username_var = tk.StringVar()
        ttk.Entry(top, textvariable=self.username_var, width=20).grid(row=0, column=1, padx=4)

        ttk.Label(top, text="Password:").grid(row=0, column=2, padx=4)
        self.password_var = tk.StringVar()
        ttk.Entry(top, textvariable=self.password_var, show="*", width=20).grid(row=0, column=3, padx=4)

        ttk.Label(top, text="Key Passphrase:").grid(row=0, column=4, padx=4)
        self.passphrase_var = tk.StringVar()
        ttk.Entry(top, textvariable=self.passphrase_var, show="*", width=20).grid(row=0, column=5, padx=4)

        ttk.Button(top, text="Sign Up", command=self.signup).grid(row=0, column=6, padx=4)
        ttk.Button(top, text="Login", command=self.login).grid(row=0, column=7, padx=4)
        ttk.Button(top, text="Logout", command=self.logout).grid(row=0, column=8, padx=4)

        self.status_var = tk.StringVar(value="Not logged in")
        ttk.Label(self.root, textvariable=self.status_var, padding=(10, 0)).pack(fill=tk.X)

        main = ttk.Frame(self.root, padding=10)
        main.pack(fill=tk.BOTH, expand=True)

        left = ttk.Frame(main)
        left.pack(side=tk.LEFT, fill=tk.Y)

        ttk.Label(left, text="Conversations").pack(anchor="w")
        self.conversation_list = tk.Listbox(left, width=28, height=26)
        self.conversation_list.pack(fill=tk.Y, pady=6)
        self.conversation_list.bind("<<ListboxSelect>>", self.open_selected_chat)

        buttons = ttk.Frame(left)
        buttons.pack(fill=tk.X, pady=4)
        ttk.Button(buttons, text="Refresh", command=self.refresh_conversations).pack(side=tk.LEFT, padx=2)
        ttk.Button(buttons, text="Start Chat", command=self.start_chat_dialog).pack(side=tk.LEFT, padx=2)

        right = ttk.Frame(main)
        right.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(10, 0))

        self.chat_title_var = tk.StringVar(value="No chat selected")
        ttk.Label(right, textvariable=self.chat_title_var).pack(anchor="w")

        self.chat_text = tk.Text(right, wrap=tk.WORD, state=tk.DISABLED, height=25)
        self.chat_text.pack(fill=tk.BOTH, expand=True, pady=6)

        bottom = ttk.Frame(right)
        bottom.pack(fill=tk.X)
        self.message_var = tk.StringVar()
        ttk.Entry(bottom, textvariable=self.message_var).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 6))
        ttk.Button(bottom, text="Send", command=self.send_message).pack(side=tk.LEFT)
        ttk.Button(bottom, text="Reload Chat", command=self.refresh_active_chat).pack(side=tk.LEFT, padx=4)

    def api(self, method, path, payload=None):
        url = f"{SERVER_URL}{path}"
        response = self.session.request(method, url, json=payload)
        try:
            return response.status_code, response.json()
        except Exception:
            return response.status_code, {"status": "fail", "message": response.text}

    def signup(self):
        username = self.username_var.get().strip()
        password = self.password_var.get()
        passphrase = self.passphrase_var.get().strip()

        if not username or not password or not passphrase:
            messagebox.showerror("Missing data", "Username, password, and key passphrase are required.")
            return

        if len(passphrase) < 6:
            messagebox.showerror("Weak passphrase", "Use at least 6 characters for key passphrase.")
            return

        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = private_key.public_key()

        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(passphrase.encode()),
        )
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        key_path = private_key_path_for_user(username)
        with open(key_path, "wb") as f:
            f.write(private_pem)

        code, data = self.api("POST", "/signup", {
            "username": username,
            "password": password,
            "public_key": public_pem.decode(),
        })

        if code >= 400 or data.get("status") != "success":
            messagebox.showerror("Signup failed", data.get("message", "Unknown error"))
            return

        messagebox.showinfo("Signup", f"{data.get('message')}\nPrivate key saved to {key_path}")

    def login(self):
        username = self.username_var.get().strip()
        password = self.password_var.get()
        self.passphrase = self.passphrase_var.get()

        if not username or not password:
            messagebox.showerror("Missing data", "Username and password required.")
            return

        code, data = self.api("POST", "/login", {"username": username, "password": password})
        if code >= 400 or data.get("status") != "success":
            messagebox.showerror("Login failed", data.get("message", "Unknown error"))
            return

        self.current_user = username
        self.status_var.set(f"Logged in as {username}")

        key_path = resolve_private_key_path(username)
        if not os.path.exists(key_path):
            messagebox.showwarning(
                "Missing key",
                f"Private key not found. Expected {private_key_path_for_user(username)}\n"
                f"Also checked legacy {username}_private.pem",
            )

        self.refresh_conversations()

    def logout(self):
        self.api("GET", "/logout")
        self.current_user = None
        self.active_chat_user = None
        self.aes_keys.clear()
        self.status_var.set("Not logged in")
        self.chat_title_var.set("No chat selected")
        self.conversation_list.delete(0, tk.END)
        self._set_chat_text("")

    def refresh_conversations(self):
        if not self.current_user:
            return
        code, data = self.api("GET", "/conversations")
        if code >= 400 or data.get("status") != "success":
            messagebox.showerror("Error", data.get("message", "Unable to load conversations"))
            return

        self.conversation_list.delete(0, tk.END)
        for user in data.get("conversations", []):
            self.conversation_list.insert(tk.END, user)

    def start_chat_dialog(self):
        if not self.current_user:
            messagebox.showwarning("Not logged in", "Login first.")
            return

        other = simpledialog.askstring("Start chat", "Enter username to start chat:", parent=self.root)
        if not other:
            return

        code, data = self.api("POST", "/get_public_keys", {"username": other.strip()})
        if code >= 400 or data.get("status") != "success":
            messagebox.showerror("Error", data.get("message", "Could not fetch keys"))
            return

        aes_key = os.urandom(32)
        try:
            encrypted_for_me = encrypt_with_rsa(data["my_public_key"], aes_key)
            encrypted_for_them = encrypt_with_rsa(data["their_public_key"], aes_key)
        except ValueError:
            messagebox.showerror("Error", "One of the users has an invalid public key format.")
            return

        code, create_data = self.api("POST", "/start_chat", {
            "username": other.strip(),
            "aes_key_user1": encrypted_for_me,
            "aes_key_user2": encrypted_for_them,
        })
        if code >= 400 or create_data.get("status") != "success":
            messagebox.showerror("Start chat failed", create_data.get("message", "Unknown error"))
            return

        self.refresh_conversations()

    def open_selected_chat(self, _event=None):
        sel = self.conversation_list.curselection()
        if not sel:
            return
        self.active_chat_user = self.conversation_list.get(sel[0])
        self.chat_title_var.set(f"Chat with {self.active_chat_user}")
        self.refresh_active_chat()

    def _get_aes_key_for_active_chat(self):
        if not self.active_chat_user:
            return None
        if self.active_chat_user in self.aes_keys:
            return self.aes_keys[self.active_chat_user]

        key_path = resolve_private_key_path(self.current_user)
        if not os.path.exists(key_path):
            messagebox.showerror("Missing key", "Your private key file is missing on this machine.")
            return None

        code, data = self.api("POST", "/get_aes_key", {"username": self.active_chat_user})
        if code >= 400 or data.get("status") != "success":
            messagebox.showerror("Error", data.get("message", "Unable to load chat key"))
            return None

        try:
            aes_key = decrypt_with_rsa(key_path, data["aes_key"], self.passphrase)
        except Exception:
            messagebox.showerror("Passphrase error", "Unable to decrypt chat key. Check passphrase.")
            return None

        self.aes_keys[self.active_chat_user] = aes_key
        return aes_key

    def refresh_active_chat(self):
        if not self.active_chat_user:
            return

        aes_key = self._get_aes_key_for_active_chat()
        if aes_key is None:
            return

        code, data = self.api("POST", "/get_messages", {"username": self.active_chat_user})
        if code >= 400 or data.get("status") != "success":
            messagebox.showerror("Error", data.get("message", "Unable to load messages"))
            return

        lines = []
        for msg in data.get("messages", []):
            try:
                plain = decrypt_message(aes_key, msg["message"])
            except Exception:
                plain = "<unable to decrypt>"
            lines.append(f"{msg['sender']}: {plain}")

        self._set_chat_text("\n".join(lines))

    def send_message(self):
        if not self.active_chat_user:
            messagebox.showwarning("No chat", "Select a chat first.")
            return
        text = self.message_var.get().strip()
        if not text:
            return

        aes_key = self._get_aes_key_for_active_chat()
        if aes_key is None:
            return

        encrypted = encrypt_message(aes_key, text)
        code, data = self.api("POST", "/send_message", {
            "username": self.active_chat_user,
            "message": encrypted,
        })
        if code >= 400 or data.get("status") != "success":
            messagebox.showerror("Send failed", data.get("message", "Unknown error"))
            return

        self.message_var.set("")
        self.refresh_active_chat()

    def _set_chat_text(self, text):
        self.chat_text.configure(state=tk.NORMAL)
        self.chat_text.delete("1.0", tk.END)
        self.chat_text.insert(tk.END, text)
        self.chat_text.configure(state=tk.DISABLED)


def main():
    root = tk.Tk()
    style = ttk.Style()
    if "clam" in style.theme_names():
        style.theme_use("clam")
    SecureMessagingDesktop(root)
    root.mainloop()


if __name__ == "__main__":
    main()
