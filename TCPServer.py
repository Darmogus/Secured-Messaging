# --- External Libraries ---
import os
import socket
import threading
from dotenv import load_dotenv


# --- Server Class ---
class Server:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)  # Max 5 connexions simultanées
        self.clients = {}  # Dictionnaire pour stocker les connexions des clients
        print(f"Serveur en écoute sur {self.host}:{self.port}")

    def handle_client(self, client_socket, client_address):
        """Gère la communication avec un client."""
        client_name = client_socket.recv(1024).decode()  # Récupérer le pseudo du client
        self.clients[client_name] = client_socket
        print(f"{client_name} ({client_address}) connecté.")

        try:
            while True:
                message = client_socket.recv(1024).decode()
                if not message:
                    break
                
                print(f"{client_name}: {message}")
                
                _, msg = message.split(":", 1)  # Format: "destinataire:message"
                for client in self.clients.values():
                    client.send(f"{client_name}: {msg}".encode())

        except ConnectionResetError:
            print(f"{client_name} s'est déconnecté.")
        finally:
            del self.clients[client_name]
            client_socket.close()

    def run(self):
        """Démarre le serveur."""
        try:
            while True:
                client_socket, client_address = self.server_socket.accept()
                threading.Thread(target=self.handle_client, args=(client_socket, client_address)).start()
        finally:
            self.server_socket.close()


# --- Tests ---
if __name__ == "__main__":
    load_dotenv()
    server = Server(host=os.getenv("HOST"), port=int(os.getenv("PORT")))
    server.run()
