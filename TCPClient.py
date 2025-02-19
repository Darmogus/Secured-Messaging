# --- External Libraries ---
import os
import socket
import threading
import sys
from dotenv import load_dotenv

# --- Cryptography for ECDH ---
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# --- Internal Libraries ---
from encrypt import Encrypt, Decrypt, DecryptAES


class Client:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.clientSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.clientSocket.connect((self.host, self.port))

        self.username = input("Enter your username: ")
        self.clientSocket.send(self.username.encode())

        self.symetricKey = None
        self.generate_symetric_key()

        threading.Thread(target=self.receive_messages, daemon=True).start()

    def generate_symetric_key(self):
        """Trade DH keys with the server and generate the symetric key."""
        # Receiving server public key
        server_public_bytes = self.clientSocket.recv(1024)
        server_public_key = serialization.load_pem_public_key(server_public_bytes)

        # Private key generation
        client_private_key = ec.generate_private_key(ec.SECP384R1())
        client_public_key = client_private_key.public_key()
        client_public_bytes = client_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        self.clientSocket.send(client_public_bytes)

        # Calculating shared key and deriving session key
        shared_key = client_private_key.exchange(ec.ECDH(), server_public_key)
        session_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'handshake data'
        ).derive(shared_key)
        session_key_hex = session_key.hex()

        # Receiving encrypted symetric key
        encrypted_sym_key = self.clientSocket.recv(1024).decode()
        self.symetricKey = DecryptAES.aes(encrypted_sym_key, session_key_hex)

    def receive_messages(self):
        """Receive messages from the server."""
        try:
            while True:
                data = self.clientSocket.recv(4096)
                if not data:
                    break
                encryptedMessage = data.decode()
                message = Decrypt.vigenere(encryptedMessage, self.symetricKey)
                print("\n" + message)
        except ConnectionResetError:
            print("\nConnection lost with the server.")
        except Exception as e:
            print(f"\nError receiving message: {e}")
        finally:
            self.clientSocket.close()
            sys.exit(0)

    def send_message(self):
        """Send messages to the server."""
        try:
            while True:
                message = input(f"{self.username}: ")
                encryptedMessage = Encrypt.vigenere(message, self.symetricKey)
                self.clientSocket.send(encryptedMessage.encode())
        except KeyboardInterrupt:
            print("\nDisconnecting...")
        finally:
            self.clientSocket.close()
            sys.exit(0)

    def run(self):
        """Start the client."""
        try:
            sendThread = threading.Thread(target=self.send_message, daemon=True)
            sendThread.start()
            sendThread.join()
        except KeyboardInterrupt:
            print("\nForced disconnection.")
        finally:
            self.clientSocket.close()
            sys.exit(0)


# --- Exécution du client ---
if __name__ == "__main__":
    load_dotenv()
    try:
        client = Client(host=os.getenv("HOST"), port=int(os.getenv("PORT")))
        client.run()
    except KeyboardInterrupt:
        print("\nClient stopped.")
        sys.exit(0)
