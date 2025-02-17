import socket

class TCPClient:
    def __init__(self, host='127.0.0.1', port=12345):
        self.host = host
        self.port = port
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def send_message(self, message):
        """Envoie un message au serveur et reçoit une réponse."""
        try:
            self.client_socket.connect((self.host, self.port))  # Connexion au serveur
            self.client_socket.send(message.encode())  # Envoyer le message
            
            response = self.client_socket.recv(1024).decode()  # Recevoir la réponse
            print(f"Réponse du serveur : {response}")
        except ConnectionError as e:
            print(f"Erreur de connexion : {e}")
        finally:
            self.client_socket.close()

# Lancer le client
if __name__ == "__main__":
    client = TCPClient()
    client.send_message("Bonjour, serveur !")
