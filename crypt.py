# --- External librairies ---
# import cryptography


# --- Classes ---
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
        