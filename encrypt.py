# --- External librairies ---
# import cryptography


# --- Classes ---
class CipherBase:
    ALPHABET: str = "abcdefghijklmnopqrstuvwxyz"
    ALPHABET_DICT: dict[str, int] = {char: idx for idx, char in enumerate(ALPHABET)}

    @staticmethod
    def _shift_char(char: str, shift: int) -> str:
        """Shift a character by a given number of positions in the alphabet."""
        return CipherBase.ALPHABET[(CipherBase.ALPHABET_DICT[char] + shift) % 26]

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
        
        
# --- Main ---
def main():
    message = "hello"
    cesar_key = "3"
    vigenere_key = "key"

    # Encrypt using Caesar cipher
    encrypted_cesar = Encrypt.cesar(message, cesar_key)
    print(f"Encrypted with Caesar: {encrypted_cesar}")

    # Decrypt using Caesar cipher
    decrypted_cesar = Decrypt.cesar(encrypted_cesar, cesar_key)
    print(f"Decrypted with Caesar: {decrypted_cesar}")

    # Encrypt using Vigenère cipher
    encrypted_vigenere = Encrypt.vigenere(message, vigenere_key)
    print(f"Encrypted with Vigenère: {encrypted_vigenere}")

    # Decrypt using Vigenère cipher
    decrypted_vigenere = Decrypt.vigenere(encrypted_vigenere, vigenere_key)
    print(f"Decrypted with Vigenère: {decrypted_vigenere}")

if __name__ == "__main__":
    main()
    