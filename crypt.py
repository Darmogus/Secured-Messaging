# --- External librairies ---
import itertools
import string


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
        if char.lower() == "\\n":
            return char
        if char.lower() in CipherBase.ALPHABET_DICT:
            is_upper = char.isupper()
            new_char = CipherBase.ALPHABET[(CipherBase.ALPHABET_DICT[char.lower()] + shift) % 26]
            return new_char.upper() if is_upper else new_char
        return char  # Si le caractère n'est pas dans l'alphabet, on le laisse tel quel.


    @staticmethod
    def _generate_vigenere_key(message: str, key: str) -> list[str]:
        """Generate a Vigenère key that matches the length of the message."""
        return list(itertools.islice(itertools.cycle(key), len(message)))
    

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
    def vigenere(text: str, key: str) -> str:
        key = key.lower()
        if not all(k in string.ascii_lowercase for k in key):
            raise ValueError(f"Invalid key {key!r}; the key can only consist of English letters.")
        
        key_iter = itertools.cycle(map(ord, key))  # Création d'un itérateur cyclique sur la clé
        result_text = []

        for letter in text:
            if letter.isalpha():  # Vérification si c'est une lettre
                base = ord('a') if letter.islower() else ord('A')
                shift = (next(key_iter) - ord('a') + ord(letter) - base) % 26
                result_text.append(chr(base + shift))
            else:
                result_text.append(letter)  # Conserve les caractères non alphabétiques
        
        return ''.join(result_text)
            
            
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
    def vigenere(ciphertext, key):
        """
        Déchiffrement du texte en utilisant le chiffrement de Vigenère.
        
        :param ciphertext: Texte chiffré.
        :param key: Clé de chiffrement.
        :return: Texte déchiffré.
        """
        # Calcul de la clé inverse pour déchiffrer
        inverse_key = "".join(chr(ord('a') + (26 - (ord(k) - ord('a'))) % 26) for k in key)
        return Encrypt.vigenere(ciphertext, inverse_key)
        
        
if __name__ == "__main__":
    # exemple fonctionnement chiffrement vigenere
    message = "aaaaaaaaaaaaaaaa"
    key = "key"
    encrypted_message = Encrypt.vigenere(message, key)
    print(f"{encrypted_message=}")