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
        self.server_socket.listen(5)  # 5 clients maximum
        
        # Pour éviter que accept() bloque indéfiniment, on définit un timeout
        self.server_socket.settimeout(1)
        
        self.clients: dict[str, socket.socket] = {}  # Dictionnaire des clients connectés
        self.running = True  # Contrôle l'état du serveur
        print(f"Serveur en écoute sur {self.host}:{self.port}")

    def get_client_name(self, client_socket: socket.socket, client_address) -> str | None:
        """Récupère le pseudo du client. Retourne None en cas d'erreur."""
        try:
            client_name = client_socket.recv(1024).decode().strip()
            return client_name
        except ConnectionResetError:
            print(f"Connexion de {client_address} fermée prématurément lors de la récupération du pseudo.")
            client_socket.close()
            return None

    def broadcast_message(self, sender_name: str, message: str):
        """Envoie un message à tous les clients connectés."""
        full_message = f"{sender_name}: {message}"
        print(full_message)
        for client in self.clients.values():
            try:
                client.send(full_message.encode())
            except Exception as e:
                print(f"Erreur lors de l'envoi à un client: {e}")

    def remove_client(self, client_name: str, client_socket: socket.socket):
        """Supprime un client de la liste et ferme sa socket."""
        if client_name in self.clients:
            del self.clients[client_name]
        client_socket.close()
        print(f"{client_name} a été retiré.")

    def handle_client(self, client_socket: socket.socket, client_address):
        """Gère la connexion et la communication avec un client."""
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
            print(f"{client_name} s'est déconnecté de manière inattendue.")
        finally:
            self.remove_client(client_name, client_socket)

    def accept_clients(self):
        """Accepte en continu les connexions entrantes tant que le serveur est actif."""
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
        """Démarre le serveur et commence à accepter les clients.
           CTRL+C permet d'arrêter proprement le serveur.
        """
        try:
            self.accept_clients()
        except KeyboardInterrupt:
            print("\nArrêt du serveur demandé par l'utilisateur.")
        finally:
            self.running = False
            self.server_socket.close()
            print("Serveur arrêté.")


# --- Tests ---
if __name__ == "__main__":
    load_dotenv()
    server = Server(host=os.getenv("HOST"), port=int(os.getenv("PORT")))
    server.run()
