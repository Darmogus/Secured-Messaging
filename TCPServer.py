# --- External Libraries ---
import os
import socket
from dotenv import load_dotenv


# --- Classes ---
class TCPServer:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)  # Jusqu'à 5 connexions en attente
        print(f"Serveur en écoute sur {self.host}:{self.port}")

    def handle_client(self, client_socket, address):
        """Gère la communication avec un client."""
        print(f"Connexion établie avec {address}")
        
        data = client_socket.recv(1024).decode()
        print(f"Message reçu : {data}")
        
        response = "Message bien reçu !"
        client_socket.send(response.encode())  # Envoyer une réponse
        
        client_socket.close()
        print(f"Connexion fermée avec {address}")

    def run(self):
        """Démarre le serveur et gère les connexions clients."""
        try:
            while True:
                client_socket, address = self.server_socket.accept()  # Accepter un client
                self.handle_client(client_socket, address)  # Gérer la communication
        except KeyboardInterrupt:
            print("\nArrêt du serveur.")
        finally:
            self.server_socket.close()

# Lancer le serveur
if __name__ == "__main__":
    load_dotenv()
    server = TCPServer(host=os.getenv("HOST"), port=int(os.getenv("PORT")))
    server.run()
