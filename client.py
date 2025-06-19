import re
import socket
import ssl
import threading
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
import base64
import config
import sys
import hmac
import hashlib

username = ""

def check_password_strength(password):
    if len(password) < 8:
        return "Weak"
    elif (re.search(r'[A-Z]', password) and
          re.search(r'[a-z]', password) and
          re.search(r'[0-9]', password) and
          re.search(r'[@$!%*?&#]', password)):
        return "Strong"
    else:
        return "Medium"

def authentication(client):
    global username
    print("Please select action")
    print("1. Login")
    print("2. Signup")
    action = input('')
    if action == "1":
        username = input("Username: ")
        password = input("Password: ")
        client.send(f"login:{username}:{password}".encode('utf-8'))
    elif action == "2":
        username = input("Username: ")
        while True:
            password = input("Password: ")
            strength = check_password_strength(password)
            if strength == "Weak":
                continue_choice = input("Your password is weak. Do you want to continue with this password? (yes/no): ").lower()
                if continue_choice == 'yes':
                    break
                else:
                    print("Please enter a stronger password.")
            else:
                break
        client.send(f"signup:{username}:{password}".encode('utf-8'))
    else:
        print("Exiting...")
        sys.exit(0)

    response = client.recv(1024).decode('utf-8')
    if response == "Authentication successful":
        print("************** you can now start chatting *************")
        return True
    else:
        print(response)
        sys.exit(0)

def generate_rsa_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

class AESCipher:
    def __init__(self, key):
        self.key = key

    def encrypt(self, data):
        cipher = AES.new(self.key, AES.MODE_EAX)
        ciphertext, tag = cipher.encrypt_and_digest(data)
        return base64.b64encode(cipher.nonce + tag + ciphertext)

    def decrypt(self, data):
        raw = base64.b64decode(data)
        nonce, tag, ciphertext = raw[:16], raw[16:32], raw[32:]
        cipher = AES.new(self.key, AES.MODE_EAX, nonce)
        return cipher.decrypt_and_verify(ciphertext, tag)

def generate_mac(data, key):
    return hmac.new(key, data, hashlib.sha256).digest()

def setup_client():
    print("*************** Welcome to our chat app ***************")

    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ssl_context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    ssl_context.load_verify_locations(cafile="server_certificate.pem")
    server_hostname = config.SERVER
    client = ssl_context.wrap_socket(client, server_hostname=server_hostname)
    client.connect((config.SERVER, config.PORT))

    if not authentication(client):
        sys.exit(0)

    private_key, public_key = generate_rsa_keys()
    client.send(public_key)

    encrypted_aes_key = client.recv(1024)
    private_key_rsa = RSA.import_key(private_key)
    cipher_rsa = PKCS1_OAEP.new(private_key_rsa)
    aes_key = cipher_rsa.decrypt(encrypted_aes_key)

    aes_cipher = AESCipher(aes_key)
    return client, aes_cipher

def receive_messages(client, aes_cipher):
    while True:
        try:
            encrypted_message = client.recv(1024)
            message_with_mac = aes_cipher.decrypt(encrypted_message)
            mac = message_with_mac[:32]
            message = message_with_mac[32:]
            print(message.decode('utf-8'))
        except Exception as e:
            print(f"An error occurred: {e}")
            client.close()
            break

def send_messages(client, aes_cipher):
    while True:
        message = input('')
        if message:
            mac = generate_mac(f'{username}: {message}'.encode('utf-8'), aes_cipher.key)
            message_with_mac = mac + f'{username}: {message}'.encode('utf-8')
            encrypted_message = aes_cipher.encrypt(message_with_mac)
            client.send(encrypted_message)

def start_chat(client, aes_cipher):
    receive_thread = threading.Thread(target=receive_messages, args=(client, aes_cipher))
    receive_thread.start()

    send_thread = threading.Thread(target=send_messages, args=(client, aes_cipher))
    send_thread.start()

if __name__ == "__main__":
    client, aes_cipher = setup_client()
    start_chat(client, aes_cipher)
