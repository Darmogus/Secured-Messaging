# --- External Libraries ---
import os
import socket
import threading
import sys
from dotenv import load_dotenv

# --- Internal Libraries ---
from encrypt import Encrypt, Decrypt


# --- Client Class ---
class Client:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.clientSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.clientSocket.connect((self.host, self.port))

        self.username = input("Enter your username : ")
        self.clientSocket.send(self.username.encode())  # Envoi du pseudo au serveur
        
        self.symetricKey = self.clientSocket.recv(1024).decode()
        print(f"Symetric key : {self.symetricKey}")
        
        # Lancer le thread pour la réception des messages
        threading.Thread(target=self.receive_messages, daemon=True).start()

    def receive_messages(self):
        """Receive messages from the server."""
        try:
            while True:
                encryptedMessage = self.clientSocket.recv(1024).decode()
                if not encryptedMessage:
                    break
                
                message = Decrypt.vigenere(encryptedMessage, self.symetricKey)
                print("\n" + message)
        except ConnectionResetError:
            print("\nConnexion perdue avec le serveur.")
        except Exception as e:
            print(f"\nErreur de réception : {e}")
        finally:
            self.clientSocket.close()
            sys.exit(0)  # Quitter proprement

    def send_message(self):
        """Send messages to the server."""
        try:
            while True:
                message = input(f"{self.username}: ")
                encryptedMessage = Encrypt.vigenere(message, self.symetricKey)
                self.clientSocket.send(f"{encryptedMessage}".encode())
        except KeyboardInterrupt:
            print("\nDéconnexion en cours...")
        finally:
            self.clientSocket.close()
            sys.exit(0)

    def run(self):
        """Start the client and send messages."""
        try:
            # Lancer l'envoi dans un thread
            sendThread = threading.Thread(target=self.send_message, daemon=True)
            sendThread.start()
            sendThread.join()  # Attendre que l'envoi se termine
        except KeyboardInterrupt:
            print("\nDéconnexion forcée.")
        finally:
            self.clientSocket.close()
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
