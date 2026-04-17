import os
import base64
import requests
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

SERVER_URL = os.environ.get("SERVER_URL", "http://127.0.0.1:5000")
#source venv/bin/activate
#https://corinna-hymnological-unlearnedly.ngrok-free.dev
#ngrok http 5000
#source venv/bin/activate
# Shared session so cookies persist between requests
session = requests.Session()
CURRENT_USER = None
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


#Login Page (signup)
def signup():
    username = input("Enter username: ")
    password = input("Enter password: ")

    print("Generating RSA keys...")
    
    
    
    #Generating keys and turning them into PEM becuse thats better for storing
    #and required to send accross HTTP
    #-----------------------------------------------------------------------------------
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    public_key = private_key.public_key()

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    #-------------------------------------------------------------------------------------
    
    
    

    # Save private key locally in a .pem file (not secure yet)
    key_path = private_key_path_for_user(username)
    with open(key_path, "w") as f:
        f.write(private_pem.decode())

    print(f"Private key saved to: {key_path}")

    # Send username, password, and public_key public key to server
    response = session.post(
        f"{SERVER_URL}/signup",
        json={
            "username": username,
            "password": password,
            "public_key": public_pem.decode()
        }
    )
    print(response.json()["message"])

#Login Page (login)
def login():
    global CURRENT_USER
    username = input("Enter username: ")
    password = input("Enter password: ")

    response = session.post(
        f"{SERVER_URL}/login",
        json={
            "username": username,
            "password": password
        }
    )

    data = response.json()
    print(data["message"])

    if data["status"] == "success":
        CURRENT_USER = username

        key_path = resolve_private_key_path(username)
        if not os.path.exists(key_path):
            print(
                "WARNING: Your local private key file is missing. "
                "You can log in, but encrypted chats cannot be opened without it."
            )
            print(f"Expected key path: {private_key_path_for_user(username)}")
            print(f"Legacy key path also checked: {username}_private.pem")

        # send to home page if login successful
        home_page()
        
        
        
    



#home page
def home_page():
    while True:
        response = session.get(f"{SERVER_URL}/conversations")
        data = response.json()

        if data["status"] == "fail":
            print("Not logged in")
            return

        print("\n=== Your Conversations ===")

        if not data["conversations"]:
            print("No conversations yet.")
        else:
            for user in data["conversations"]:
                print("-", user)

        print("\nOptions:")
        print("1. Open chat")
        print("2. Start new chat")
        print("3. Logout")

        choice = input("Choose: ")

        if choice == "1":
            other = input("Enter username: ")
            chat(other)

        elif choice == "2":
            new_chat()

        elif choice == "3":
            res = session.get(f"{SERVER_URL}/logout")
            print(res.json()["message"])
            return  # exit home page → back to main menu

        else:
            print("Not a valid option")
        
        
        


#home page
#makeing an new chat
def new_chat():
    other = input("Enter username to start chat: ")



    # Step 1: Get public keys
    res = session.post(f"{SERVER_URL}/get_public_keys", json={"username": other})
    data = res.json()
    
    # Step 2: Check user exists
    if data["status"] == "fail":
        print(data["message"])
        return

    my_pub = data["my_public_key"]
    their_pub = data["their_public_key"]

    # Step 3: Generate AES key
    aes_key = os.urandom(32)





    # Step 4: duplicate AES key and encrypt with both public keys here
    encrypted_for_me = encrypt_with_rsa(my_pub, aes_key)
    encrypted_for_them = encrypt_with_rsa(their_pub, aes_key)

    # Step 5: Send to server
    res = session.post(f"{SERVER_URL}/start_chat", json={
        "username": other,
        "aes_key_user1": encrypted_for_me,
        "aes_key_user2": encrypted_for_them
    })

    print(res.json()["message"])
    
    
    
    
    
    
#home page
#for start new chat
#encrypts aes key with public key
def encrypt_with_rsa(public_pem, data):
    # Load public key from PEM string
    public_key = serialization.load_pem_public_key(
        public_pem.encode()
    )

    # Encrypt data (AES key)
    encrypted = public_key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Convert to base64 so it can be sent over JSON
    return base64.b64encode(encrypted).decode()
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    


def chat(other):

    # Step 1: Get AES key
    res = session.post(f"{SERVER_URL}/get_aes_key", json={"username": other})
    data = res.json()

    if data["status"] == "fail":
        print("Error getting AES key")
        return

    encrypted_aes = data["aes_key"]

    key_path = resolve_private_key_path(CURRENT_USER)

    if not os.path.exists(key_path):
        print(
            "Error: private key file not found for this account. "
            "If this account was created on another machine, copy that key file first."
        )
        print(f"Expected key path: {private_key_path_for_user(CURRENT_USER)}")
        print(f"Legacy key path also checked: {CURRENT_USER}_private.pem")
        return

    try:
        aes_key = decrypt_with_rsa(key_path, encrypted_aes)
    except ValueError:
        print("Error: could not decrypt chat key with your private key. You may be using the wrong key file.")
        return

    while True:
        # Step 2: Get messages
        res = session.post(f"{SERVER_URL}/get_messages", json={"username": other})
        messages = res.json()["messages"]

        print("\n=== Chat ===")
        for msg in messages:
            decrypted = decrypt_message(aes_key, msg["message"])
            print(f"{msg['sender']}: {decrypted}")

        print("\n1. Send message")
        print("2. Refresh")
        print("3. Back")

        choice = input("Choose: ")

        if choice == "1": #send message
            text = input("Enter message: ")

            encrypted = encrypt_message(aes_key, text)

            session.post(f"{SERVER_URL}/send_message", json={
                "username": other,
                "message": encrypted
            })

        elif choice == "2":
            continue

        elif choice == "3":
            return

        else:
            print("Invalid option")









    
#chat page
#encrypt the message with decrypted aes key
def encrypt_message(aes_key, plaintext):
    iv = os.urandom(16)

    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv))
    encryptor = cipher.encryptor()

    ciphertext = encryptor.update(plaintext.encode()) + encryptor.finalize()

    return base64.b64encode(iv + ciphertext).decode()




#chat page
#decrypt the message with decrypted aes key
def decrypt_message(aes_key, encrypted_data):
    raw = base64.b64decode(encrypted_data)

    iv = raw[:16]
    ciphertext = raw[16:]

    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv))
    decryptor = cipher.decryptor()

    return (decryptor.update(ciphertext) + decryptor.finalize()).decode()



#chat page
#decrypt the aes key with private key
def decrypt_with_rsa(private_key_path, encrypted_data):
    from cryptography.hazmat.primitives.asymmetric import padding

    with open(private_key_path, "rb") as f:
        private_key = serialization.load_pem_private_key(
            f.read(),
            password=None
        )

    decoded = base64.b64decode(encrypted_data)

    return private_key.decrypt(
        decoded,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )







def main():
    while True:
        print("\n1. Login")
        print("2. Sign Up")
        print("3. Exit")

        choice = input("Choose: ")

        if choice == "1":
            login()
        elif choice == "2":
            signup()
        elif choice == "3":
            break
        else:
            print("Invalid option")


if __name__ == "__main__":
    main()