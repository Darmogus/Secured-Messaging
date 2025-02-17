# --- External Libraries ---
import os
import socket
import threading
import sys
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
        
        # Lancer le thread pour la réception des messages
        threading.Thread(target=self.receive_messages, daemon=True).start()

    def receive_messages(self):
        """Reçoit et affiche les messages entrants."""
        try:
            while True:
                message = self.client_socket.recv(1024).decode()
                if not message:
                    break
                print("\n" + message)
        except ConnectionResetError:
            print("\nConnexion perdue avec le serveur.")
        except Exception as e:
            print(f"\nErreur de réception : {e}")
        finally:
            self.client_socket.close()
            sys.exit(0)  # Quitter proprement

    def send_message(self):
        """Envoie des messages au serveur."""
        try:
            while True:
                message = input("Message : ")
                self.client_socket.send(f"{self.username}:{message}".encode())
        except KeyboardInterrupt:
            print("\nDéconnexion en cours...")
        finally:
            self.client_socket.close()
            sys.exit(0)

    def run(self):
        """Lance l'envoi et la réception des messages en parallèle."""
        try:
            # Lancer l'envoi dans un thread
            send_thread = threading.Thread(target=self.send_message, daemon=True)
            send_thread.start()
            send_thread.join()  # Attendre que l'envoi se termine
        except KeyboardInterrupt:
            print("\nDéconnexion forcée.")
        finally:
            self.client_socket.close()
            sys.exit(0)


# --- Tests ---
if __name__ == "__main__":
    load_dotenv()
    try:
        client = Client(host=os.getenv("HOST"), port=int(os.getenv("PORT")))
        client.run()
    except KeyboardInterrupt:
        print("\nArrêt du client.")
        sys.exit(0)
