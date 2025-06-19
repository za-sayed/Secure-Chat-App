import socket
import threading
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
import base64
import config
import database
import ssl
import hmac
import hashlib

clients = []
client_keys = {}

def broadcast(message, mac, sender):
    for client in clients:
        if client != sender:
            client_aes_key = client_keys[client]['aes_key']
            message_with_mac = mac + message
            encrypted_msg = client_aes_key.encrypt(message_with_mac)
            client.sendall(encrypted_msg)

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

def verify_mac(data, mac, key):
    expected_mac = generate_mac(data, key)
    return hmac.compare_digest(expected_mac, mac)

def handle_client(client, addr):
    global clients, client_keys

    try:
        # Authentication
        auth_data = client.recv(1024).decode('utf-8')
        action, username, password = auth_data.split(':')

        if action == "login":
            if not database.user_login(username, password):
                client.send("Authentication failed".encode('utf-8'))
                client.close()
                return
        elif action == "signup":
            if not database.register_user(username, password):
                client.send("Signup failed".encode('utf-8'))
                client.close()
                return

        client.send("Authentication successful".encode('utf-8'))

        # Key Exchange
        client_rsa_public_key = RSA.import_key(client.recv(1024))
        aes_key = AESCipher(AES.get_random_bytes(32))
        client_keys[client] = {'rsa_key': client_rsa_public_key, 'aes_key': aes_key}

        rsa_cipher = PKCS1_OAEP.new(client_rsa_public_key)
        encrypted_aes_key = rsa_cipher.encrypt(aes_key.key)
        client.sendall(encrypted_aes_key)

        clients.append(client)
        print(f"{str(addr)} Authentication successful")

        while True:
            encrypted_message = client.recv(1024)
            aes_key = client_keys[client]['aes_key']
            message_with_mac = aes_key.decrypt(encrypted_message)
            mac = message_with_mac[:32]
            message = message_with_mac[32:]
            if verify_mac(message, mac, aes_key.key):
                broadcast(message, mac, client)
            else:
                print("Warning: Message integrity check failed!")
    except:
        clients.remove(client)
        del client_keys[client]
        client.close()
        print(f"Client {addr} disconnected")

def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((config.SERVER, config.PORT))
    server.listen()
    ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ssl_context.load_cert_chain(certfile="server_certificate.pem", keyfile="server_private_key.pem")
    server = ssl_context.wrap_socket(server, server_side=True)

    print(f"Server started on {config.SERVER}:{config.PORT}")

    while True:
        client, addr = server.accept()
        print(f"Connected with {str(addr)}")
        thread = threading.Thread(target=handle_client, args=(client, addr))
        thread.start()

if __name__ == "__main__":
    start_server()
