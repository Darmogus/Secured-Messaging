# --- External Libraries ---
import os
import socket
import threading
import json
from dotenv import load_dotenv

# --- Server Class ---
class Server:
    def __init__(self, host, port):
        self.host: str = host
        self.port: int = port
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)  # Jusqu'à 5 clients connectés
        self.server_socket.settimeout(1)
        
        self.clients: dict[str, socket.socket] = {}  # Dictionnaire des clients connectés
        self.keys: dict[str, str] = {}              # Dictionnaire des clés publiques (format PEM)
        self.running = True
        print(f"Server started on {self.host}:{self.port}")

    def get_client_name(self, client_socket: socket.socket) -> str | None:
        """Récupère le pseudo envoyé par le client."""
        try:
            client_name = client_socket.recv(1024).decode().strip()
            return client_name
        except Exception as e:
            print(f"Erreur lors de la récupération du pseudo: {e}")
            client_socket.close()
            return None

    def broadcast_message(self, sender_name: str, message: str):
        """Diffuse un message en clair à tous les clients (si besoin)."""
        fullMessage = f"{sender_name}: {message}"
        print(fullMessage)
        for clientName, client in self.clients.items():
            if clientName != sender_name:
                try:
                    client.send(fullMessage.encode())
                except Exception as e:
                    print(f"Erreur d'envoi vers {clientName}: {e}")

    def remove_client(self, client_name: str):
        """Supprime un client et sa clé du serveur."""
        if client_name in self.clients:
            self.clients[client_name].close()
            del self.clients[client_name]
        if client_name in self.keys:
            del self.keys[client_name]
        print(f"{client_name} disconnected.")

    def handle_client(self, client_socket: socket.socket, client_address):
        """Gère la connexion d'un client."""
        client_name = self.get_client_name(client_socket)
        if client_name is None:
            return

        # Lecture de la clé publique envoyée par le client
        try:
            public_key_pem = client_socket.recv(4096).decode()
            self.keys[client_name] = public_key_pem
        except Exception as e:
            print(f"Erreur lors de la réception de la clé publique de {client_name}: {e}")
            client_socket.close()
            return

        self.clients[client_name] = client_socket
        print(f"{client_name} ({client_address}) connected with public key.")

        try:
            while True:
                data = client_socket.recv(4096)
                if not data:
                    break
                text = data.decode()
                # Si le client demande les clés publiques
                if text.strip() == "/get_public_keys":
                    response = {
                        "type": "keys_response",
                        "keys": self.keys
                    }
                    client_socket.send(json.dumps(response).encode())
                else:
                    try:
                        # Tentative d'interpréter le message comme JSON
                        payload = json.loads(text)
                        if payload.get("type") == "encrypted_message" and "sender" in payload and "messages" in payload:
                            sender = payload["sender"]
                            messages = payload["messages"]
                            # Pour chaque destinataire, transmettre le message chiffré
                            for target, encrypted_message in messages.items():
                                if target in self.clients:
                                    out_payload = {
                                        "type": "encrypted_message",
                                        "sender": sender,
                                        "message": encrypted_message
                                    }
                                    self.clients[target].send(json.dumps(out_payload).encode())
                                else:
                                    print(f"Le client {target} n'est pas connecté.")
                        else:
                            # Sinon, diffusion en clair
                            self.broadcast_message(client_name, text)
                    except json.JSONDecodeError:
                        # Message non-JSON → diffusion en clair
                        self.broadcast_message(client_name, text)
        except Exception as e:
            print(f"Erreur avec {client_name}: {e}")
        finally:
            self.remove_client(client_name)

    def accept_clients(self):
        """Accepte les connexions et démarre un thread pour chaque client."""
        while self.running:
            try:
                client_socket, client_address = self.server_socket.accept()
            except socket.timeout:
                continue
            except KeyboardInterrupt:
                break

            threading.Thread(
                target=self.handle_client, args=(client_socket, client_address), daemon=True
            ).start()

    def run(self):
        """Démarre le serveur."""
        try:
            self.accept_clients()
        except KeyboardInterrupt:
            print("\nServer stopping...")
        finally:
            self.running = False
            self.server_socket.close()
            print("Server stopped.")


# --- Lancement du Serveur ---
if __name__ == "__main__":
    load_dotenv()
    server = Server(host='0.0.0.0', port=int(os.getenv("PORT")))
    server.run()
