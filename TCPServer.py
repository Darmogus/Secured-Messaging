# --- External Libraries ---
import os
import socket
import threading
from dotenv import load_dotenv
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# --- Internal Libraries ---
from encrypt import EncryptAES


class Server:
    def __init__(self, host, port):
        self.host: str = host
        self.port: int = port
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)
        self.server_socket.settimeout(1)
        self.clients: dict[str, socket.socket] = {}
        self.running = False

        self.symetricKey: str = os.getenv("SYMETRIC_KEY")

    def generate_symetric_key(self, clientSocket: socket.socket):
        """Trade DH keys with the client and generate the symetric key."""
        # Key pair generation
        server_private_key = ec.generate_private_key(ec.SECP384R1())
        server_public_key = server_private_key.public_key()
        server_public_bytes = server_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        # Public key sending
        clientSocket.send(server_public_bytes)

        # Receiving client public key
        client_public_bytes = clientSocket.recv(1024)
        client_public_key = serialization.load_pem_public_key(client_public_bytes)

        # Calculating shared key and deriving session key
        shared_key = server_private_key.exchange(ec.ECDH(), client_public_key)
        session_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'handshake data'
        ).derive(shared_key)
        session_key_hex = session_key.hex()

        # Encrypting symetric key with session key
        encrypted_sym_key = EncryptAES.aes(self.symetricKey, session_key_hex)
        
        clientSocket.send(encrypted_sym_key.encode())

    def get_clientName(self, clientSocket: socket.socket, clientAddress) -> str | None:
        """Récupère le nom du client depuis la socket."""
        try:
            clientName = clientSocket.recv(1024).decode().strip()
            return clientName
        except ConnectionResetError:
            print(f"Connection lost with {clientAddress}.")
            clientSocket.close()
            return None

    def broadcast_message(self, sender_name: str, encryptedMessage: str):
        """Diffuse un message à tous les clients (sauf l'expéditeur)."""
        print("Broadcasting message:", encryptedMessage)
        for clientName, client in self.clients.items():
            if clientName != sender_name:
                try:
                    client.send(encryptedMessage.encode())
                except Exception as e:
                    print(f"Error sending message to {clientName}: {e}")

    def remove_client(self, clientName: str, clientSocket: socket.socket):
        """Supprime un client du serveur."""
        if clientName in self.clients:
            del self.clients[clientName]
        clientSocket.close()
        print(f"{clientName} disconnected.")

    def handle_client(self, clientSocket: socket.socket, clientAddress):
        """Gère la connexion d'un client."""
        clientName = self.get_clientName(clientSocket, clientAddress)
        if clientName is None:
            return

        self.clients[clientName] = clientSocket
        print(f"{clientName} ({clientAddress}) connected.")

        self.generate_symetric_key(clientSocket)

        self.broadcast_message(clientName, "joined the chat.")

        try:
            while True:
                data = clientSocket.recv(4096)
                if not data:
                    break
                encryptedMessage = data.decode()
                self.broadcast_message(clientName, encryptedMessage)
        except ConnectionResetError:
            print(f"{clientName} ({clientAddress}) disconnected unexpectedly.")
        finally:
            self.broadcast_message(clientName, "left the chat.")
            self.remove_client(clientName, clientSocket)

    def accept_clients(self):
        """Accepte les connexions clients et les gère dans des threads séparés."""
        while self.running:
            try:
                clientSocket, clientAddress = self.server_socket.accept()
            except socket.timeout:
                continue
            except KeyboardInterrupt:
                break

            threading.Thread(
                target=self.handle_client, args=(clientSocket, clientAddress), daemon=True
            ).start()

    def run(self):
        """Lance le serveur et commence à accepter les clients."""
        try:
            print(f"Server started on {self.host}:{self.port}")
            self.running = True
            self.accept_clients()
        except KeyboardInterrupt:
            print("\nServer stopping...")
        finally:
            self.running = False
            self.server_socket.close()
            print("Server stopped.")


# --- Exécution du serveur ---
if __name__ == "__main__":
    load_dotenv()
    server = Server(host='0.0.0.0', port=int(os.getenv("PORT")))
    server.run()
