# --- External Libraries ---
import os
import socket
import threading
from dotenv import load_dotenv

# --- Internal Libraries ---
from encrypt import Encrypt, Decrypt


# --- Server Class ---
class Server:
    def __init__(self, host, port):
        self.host: str = host
        self.port: int = port
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)                # 5 clients maximum
        
        self.server_socket.settimeout(1)            # Timeout
        
        self.clients: dict[str, socket.socket] = {} # Connected clients
        self.running = True                         # Server status

        print(f"Server started on {self.host}:{self.port}")

    def get_clientName(self, clientSocket: socket.socket, clientAddress) -> str | None:
        """Get the client's name from the socket."""
        try:
            clientName = clientSocket.recv(1024).decode().strip()
            return clientName
        except ConnectionResetError:
            print(f"Connection lost with {clientAddress}.")
            clientSocket.close()
            return None

    def broadcast_message(self, sender_name: str, encryptedMessage: str):
        """Broadcast a message to all clients."""
        print("Broadcasting message:", encryptedMessage)
        for clientName, client in self.clients.items():
            try:
                if clientName != sender_name:
                    client.send(encryptedMessage.encode())
            except Exception as e:
                print(f"Error sending message to {client.username}: {e}")

    def remove_client(self, clientName: str, clientSocket: socket.socket):
        """Remove a client from the server."""
        if clientName in self.clients:
            del self.clients[clientName]
        clientSocket.close()
        print(f"{clientName} disconnected.")

    def handle_client(self, clientSocket: socket.socket, clientAddress):
        """Handle a client connection."""
        clientName = self.get_clientName(clientSocket, clientAddress)
        if clientName is None:
            return

        self.clients[clientName] = clientSocket
        print(f"{clientName} ({clientAddress}) connected.")
        
        self.clients[clientName].send(self.symetricKey.encode())
        
        self.broadcast_message(clientName, "joined the chat.")
        try:
            while True:
                encryptedMessage = clientSocket.recv(1024).decode()
                if not encryptedMessage:
                    break
                
                self.broadcast_message(clientName, encryptedMessage)
        except ConnectionResetError:
            print(f"{clientName} ({clientAddress}) disconnected unexpectedly.")
        finally:
            self.broadcast_message(clientName, "left the chat.")
            self.remove_client(clientName, clientSocket)

    def accept_clients(self):
        """Accept clients and handle them in separate threads."""
        while self.running:
            try:
                clientSocket, clientAddress = self.server_socket.accept()
            except socket.timeout:
                # Timeout : aucune connexion, on peut vérifier si le serveur doit s'arrêter
                continue
            except KeyboardInterrupt:
                # Ce bloc est rarement atteint grâce au timeout, mais c'est une sécurité
                break

            threading.Thread(
                target=self.handle_client, args=(clientSocket, clientAddress), daemon=True
            ).start()

    def run(self):
        """Démarre le serveur et commence à accepter les clients."""
        try:
            self.accept_clients()
        except KeyboardInterrupt:
            print("\nServer stopping...")
        finally:
            self.running = False
            self.server_socket.close()
            print("Server stopped.")


# --- Tests ---
if __name__ == "__main__":
    load_dotenv()
    server = Server(host='0.0.0.0', port=int(os.getenv("PORT")))
    server.run()