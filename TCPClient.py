# --- External Libraries ---
import os
import socket
import threading
from dotenv import load_dotenv


# --- Client Class ---
class Client:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client_socket.connect((self.host, self.port))

        self.username = input("Entrez votre pseudo : ")
        self.client_socket.send(self.username.encode())  # Envoi du pseudo au serveur
        
        threading.Thread(target=self.receive_messages, daemon=True).start()

    def receive_messages(self):
        """Reçoit et affiche les messages entrants."""
        while True:
            try:
                message = self.client_socket.recv(1024).decode()
                if not message:
                    break
                print("\n" + message)
            except:
                print("Déconnecté du serveur.")
                break

    def send_message(self):
        """Envoie des messages au serveur."""
        while True:
            recipient = input("Envoyer à : ")
            message = input("Message : ")
            self.client_socket.send(f"{recipient}:{message}".encode())

    def run(self):
        """Lance l'envoi et la réception des messages."""
        try:
            self.send_message()
        except KeyboardInterrupt:
            print("\nDéconnexion.")
        finally:
            self.client_socket.close()


# --- Tests ---
if __name__ == "__main__":
    load_dotenv()
    client = Client(host=os.getenv("HOST"), port=int(os.getenv("PORT")))
    client.run()
