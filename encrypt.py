# --- External librairies ---
import cryptography


# --- Classes ---
# --- External librairies ---
import os
import cryptography
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes

# --- Classes AES ---

class EncryptAES:
    @staticmethod
    def aes(message: str, key: str) -> str:
        """Encrypt a message using AES-256 in CBC mode."""
        # Convertir le message en bytes.
        message_bytes = message.encode('utf-8')
        
        # Dériver une clé de 256 bits à partir de la chaîne key via SHA-256.
        digest = hashes.Hash(hashes.SHA256())
        digest.update(key.encode('utf-8'))
        aes_key = digest.finalize()
        
        # Générer un vecteur d'initialisation (IV) aléatoire de 16 octets.
        iv = os.urandom(16)
        
        # Créer l'objet cipher avec AES en mode CBC.
        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        
        # Appliquer le padding PKCS7 pour que la taille soit un multiple de 16.
        pad_len = 16 - (len(message_bytes) % 16)
        padded_message = message_bytes + bytes([pad_len] * pad_len)
        
        # Chiffrer le message.
        ciphertext = encryptor.update(padded_message) + encryptor.finalize()
        
        # Retourner l'IV concaténé au ciphertext sous forme hexadécimale.
        return (iv + ciphertext).hex()


class DecryptAES:
    @staticmethod
    def aes(ciphertext_hex: str, key: str) -> str:
        """Decrypt a hex-encoded ciphertext (IV + ciphertext) using AES-256 in CBC mode."""
        # Convertir la chaîne hexadécimale en bytes.
        ciphertext = bytes.fromhex(ciphertext_hex)
        
        # Extraire l'IV et le ciphertext.
        iv = ciphertext[:16]
        ct = ciphertext[16:]
        
        # Dériver la clé AES à partir de key via SHA-256.
        digest = hashes.Hash(hashes.SHA256())
        digest.update(key.encode('utf-8'))
        aes_key = digest.finalize()
        
        # Créer l'objet cipher pour déchiffrer.
        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        
        # Déchiffrer le ciphertext.
        padded_plaintext = decryptor.update(ct) + decryptor.finalize()
        
        # Supprimer le padding PKCS7.
        pad_len = padded_plaintext[-1]
        plaintext_bytes = padded_plaintext[:-pad_len]
        
        # Retourner le message déchiffré.
        return plaintext_bytes.decode('utf-8')

class CipherBase:
    ALPHABET: str = "abcdefghijklmnopqrstuvwxyz"
    ALPHABET_DICT: dict[str, int] = {char: idx for idx, char in enumerate(ALPHABET)}

    @staticmethod
    def _shift_char(char: str, shift: int) -> str:
        """Shift a character by a given number of positions in the alphabet."""
        if char.lower() in CipherBase.ALPHABET_DICT:
            is_upper = char.isupper()
            new_char = CipherBase.ALPHABET[(CipherBase.ALPHABET_DICT[char.lower()] + shift) % 26]
            return new_char.upper() if is_upper else new_char
        return char  # Si le caractère n'est pas dans l'alphabet, on le laisse tel quel.


    @staticmethod
    def _generate_vigenere_key(message: str, key: str) -> list[str]:
        """Generate a Vigenère key that matches the length of the message."""
        return [key[i % len(key)] for i in range(len(message))]
    

class Encrypt(CipherBase):
    @staticmethod
    def cesar(message: str, key: str) -> str:
        """Encrypt a message using the Caesar cipher."""
        shift = int(key)
        listMessage = []
        for char in message:
            encrypted_char = CipherBase._shift_char(char, shift)
            listMessage.append(encrypted_char)
        
        encryptedMessage: str = "".join(listMessage)
        return encryptedMessage

    @staticmethod
    def vigenere(message: str, key: str) -> str:
        """Encrypt a message using the Vigenère cipher."""
        vigenere_key = CipherBase._generate_vigenere_key(message, key)
        listMessage = []
        for message_char, key_char in zip(message, vigenere_key):
            shift = CipherBase.ALPHABET_DICT[key_char]
            encrypted_char = CipherBase._shift_char(message_char, shift)
            listMessage.append(encrypted_char)
        
        encryptedMessage: str = "".join(listMessage)
        return encryptedMessage
            
            
class Decrypt(CipherBase):
    @staticmethod        
    def cesar(message: str, key: str) -> str:
        """Decrypt a message using the Caesar cipher."""
        shift: int = int(key)
        listMessage: str = []
        for char in message:
            decryptedChar: str = CipherBase._shift_char(char, -shift)
            listMessage.append(decryptedChar)
        
        decryptedMessage: str = "".join(listMessage)
        return decryptedMessage
    
    @staticmethod
    def vigenere(message: str, key: str) -> str:
        """Decrypt a message using the Vigenère cipher."""
        vigenere_key = CipherBase._generate_vigenere_key(message, key)
        listMessage = []
        for message_char, key_char in zip(message, vigenere_key):
            shift = -CipherBase.ALPHABET_DICT[key_char]
            decrypted_char = CipherBase._shift_char(message_char, shift)
            listMessage.append(decrypted_char)
        
        decryptedMessage: str = "".join(listMessage)
        return decryptedMessage
        