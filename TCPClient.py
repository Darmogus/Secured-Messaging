# --- External Libraries ---
import os
import socket
import threading
import sys
import json
import base64
import queue
from dotenv import load_dotenv
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding

# --- Client Class ---
class Client:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.response_queue = queue.Queue()  # Pour récupérer la réponse aux commandes
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client_socket.connect((self.host, self.port))

        # Envoi du pseudo au serveur
        self.username = input("Entrez votre pseudo : ")
        self.client_socket.send(self.username.encode())

        # Génération et envoi de la clé publique
        self.generate_keys()

        # Lancer le thread de réception
        threading.Thread(target=self.receive_messages, daemon=True).start()

    def generate_keys(self):
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        self.public_key = self.private_key.public_key()
        self.public_pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        # Envoi de la clé publique au serveur (en UTF-8)
        self.client_socket.send(self.public_pem.decode('utf-8').encode())

    def encrypt_message(self, message: str, key_pem: str) -> bytes:
        """Chiffre le message avec la clé publique fournie."""
        public_key = serialization.load_pem_public_key(key_pem.encode())
        encrypted_message = public_key.encrypt(
            message.encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return encrypted_message

    def decrypt_message(self, encrypted_message: bytes) -> str:
        """Déchiffre un message avec la clé privée."""
        decrypted = self.private_key.decrypt(
            encrypted_message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return decrypted.decode()

    def receive_messages(self):
        """Boucle de réception unique pour tous les messages."""
        try:
            while True:
                data = self.client_socket.recv(4096)
                if not data:
                    break
                text = data.decode()
                try:
                    # On essaie d'interpréter le message comme du JSON
                    payload = json.loads(text)
                    msg_type = payload.get("type")
                    if msg_type == "keys_response":
                        # Réponse à la commande /get_public_keys
                        self.response_queue.put(payload)
                    elif msg_type == "encrypted_message":
                        sender = payload.get("sender")
                        enc_b64 = payload.get("message")
                        encrypted_bytes = base64.b64decode(enc_b64)
                        print(f"\nMessage chiffré : {encrypted_bytes}.")
                        decrypted_message = self.decrypt_message(encrypted_bytes)
                        print(f"\n{sender}: {decrypted_message}")
                    else:
                        # Autre type de message
                        print("\n" + text)
                except json.JSONDecodeError:
                    # Message en clair
                    print("\n" + text)
        except ConnectionResetError:
            print("\nConnexion perdue avec le serveur.")
        except Exception as e:
            print(f"\nErreur de réception : {e}")
        finally:
            self.client_socket.close()
            sys.exit(0)

    def send_message(self):
        """Demande les clés publiques, chiffre le message et l'envoie."""
        try:
            while True:
                message = input(f"{self.username}: ")

                # Demander la liste des clés publiques au serveur
                self.client_socket.send("/get_public_keys".encode())
                try:
                    response = self.response_queue.get(timeout=5)
                except queue.Empty:
                    print("Timeout: impossible de récupérer les clés publiques.")
                    continue

                public_keys = response.get("keys", {})
                messages_dict = {}
                for name, key in public_keys.items():
                    if name == self.username:
                        continue  # On ne chiffre pas pour soi-même
                    encrypted = self.encrypt_message(message, key)
                    # Encodage en base64 pour la transmission
                    enc_b64 = base64.b64encode(encrypted).decode('utf-8')
                    messages_dict[name] = enc_b64

                # Constitution de la charge utile à envoyer
                payload = {
                    "type": "encrypted_message",
                    "sender": self.username,
                    "messages": messages_dict
                }
                self.client_socket.send(json.dumps(payload).encode())
        except KeyboardInterrupt:
            print("\nDéconnexion en cours...")
        finally:
            self.client_socket.close()
            sys.exit(0)

    def run(self):
        """Démarre le client (envoi et réception de messages)."""
        try:
            send_thread = threading.Thread(target=self.send_message, daemon=True)
            send_thread.start()
            send_thread.join()
        except KeyboardInterrupt:
            print("\nDéconnexion forcée.")
        finally:
            self.client_socket.close()
            sys.exit(0)


# --- Lancement du Client ---
if __name__ == "__main__":
    load_dotenv()
    try:
        client = Client(host=os.getenv("HOST"), port=int(os.getenv("PORT")))
        client.run()
    except KeyboardInterrupt:
        print("\nArrêt du client.")
        sys.exit(0)
