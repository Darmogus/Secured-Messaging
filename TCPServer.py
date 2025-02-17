# --- External Libraries ---
import os
import socket
import threading
from dotenv import load_dotenv


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

    def get_client_name(self, client_socket: socket.socket, client_address) -> str | None:
        """Get the client's name from the socket."""
        try:
            client_name = client_socket.recv(1024).decode().strip()
            return client_name
        except ConnectionResetError:
            print(f"Connection lost with {client_address}.")
            client_socket.close()
            return None

    def broadcast_message(self, sender_name: str, message: str):
        """Broadcast a message to all clients."""
        full_message = f"{sender_name}: {message}"
        print(full_message)
        for client in self.clients.values():
            try:
                client.send(full_message.encode())
            except Exception as e:
                print(f"Error sending message to {client.username}: {e}")

    def remove_client(self, client_name: str, client_socket: socket.socket):
        """Remove a client from the server."""
        if client_name in self.clients:
            del self.clients[client_name]
        client_socket.close()
        print(f"{client_name} disconnected.")

    def handle_client(self, client_socket: socket.socket, client_address):
        """Handle a client connection."""
        client_name = self.get_client_name(client_socket, client_address)
        if client_name is None:
            return

        self.clients[client_name] = client_socket
        print(f"{client_name} ({client_address}) connected.")

        try:
            while True:
                message = client_socket.recv(1024).decode()
                if not message:
                    break
                self.broadcast_message(client_name, message)
        except ConnectionResetError:
            print(f"{client_name} ({client_address}) disconnected unexpectedly.")
        finally:
            self.remove_client(client_name, client_socket)

    def accept_clients(self):
        """Accept clients and handle them in separate threads."""
        while self.running:
            try:
                client_socket, client_address = self.server_socket.accept()
            except socket.timeout:
                # Timeout : aucune connexion, on peut vérifier si le serveur doit s'arrêter
                continue
            except KeyboardInterrupt:
                # Ce bloc est rarement atteint grâce au timeout, mais c'est une sécurité
                break

            threading.Thread(
                target=self.handle_client, args=(client_socket, client_address), daemon=True
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
