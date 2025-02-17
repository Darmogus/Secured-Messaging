# --- External librairies ---
# import cryptography


# --- Classes ---
class Encrypt:
    ALPHABET: str = "abcdefghijklmnopqrstuvwxyz"
    ALPHABET_DICT: dict[str, int] = {'a': 0, 'b': 1, 'c': 2, 'd': 3, 'e': 4, 'f': 5, 'g': 6, 'h': 7, 'i': 8, 'j': 9, 'k': 10, 'l': 11, 'm': 12, 'n': 13, 'o': 14, 'p': 15, 'q': 16, 'r': 17, 's': 18, 't': 19, 'u': 20, 'v': 21, 'w': 22, 'x': 23, 'y': 24, 'z': 25}
    
    def __init__(self, message: str, key: str):
        self.message = message
        self.key = key
        
    def cesar(self) -> str:
        key: int = int(self.key)
        messageList: list[str] = []
        for char in self.message:
            messageList.append(Encrypt.ALPHABET[(Encrypt.ALPHABET_DICT[char] + key) % 26])
        
        newMessage: str = "".join(messageList)
        return newMessage
    
    def vigenere(self) -> str:
        key: list[int] = []
        for i in range(len(self.message)):
            key.append(self.key[i % len(self.key)])
        
        messageList: list[str] = []
        for messageChar, keyChar in zip(self.message, key):
            messageCharIndex: int = Encrypt.ALPHABET_DICT[messageChar]
            keyCharIndex: int = Encrypt.ALPHABET_DICT[keyChar]
            
            messageList.append(Encrypt.ALPHABET[(messageCharIndex + keyCharIndex) % 26])
          
        newMessage: str = "".join(messageList)
        return newMessage
            
            
        
        
class Decrypt:
    ALPHABET: str = "abcdefghijklmnopqrstuvwxyz"
    ALPHABET_DICT: dict[str, int] = {'a': 0, 'b': 1, 'c': 2, 'd': 3, 'e': 4, 'f': 5, 'g': 6, 'h': 7, 'i': 8, 'j': 9, 'k': 10, 'l': 11, 'm': 12, 'n': 13, 'o': 14, 'p': 15, 'q': 16, 'r': 17, 's': 18, 't': 19, 'u': 20, 'v': 21, 'w': 22, 'x': 23, 'y': 24, 'z': 25}
    
    def __init__(self, message: str, key: str):
        self.message = message
        self.key = key
        
    def cesar(self) -> str:
        key: int = int(self.key)
        newMessage: str = []
        for char in self.message:
            newMessage.append(Decrypt.ALPHABET[(Decrypt.ALPHABET_DICT[char] - key) % 26])
        
        newMessage = "".join(newMessage)
        return newMessage
    
    def vigenere(self) -> str:
        key: list[int] = []
        for i in range(len(self.message)):
            key.append(self.key[i % len(self.key)])
        
        messageList: list[str] = []
        for messageChar, keyChar in zip(self.message, key):
            messageCharIndex: int = Decrypt.ALPHABET_DICT[messageChar]
            keyCharIndex: int = Decrypt.ALPHABET_DICT[keyChar]
            
            messageList.append(Decrypt.ALPHABET[(messageCharIndex - keyCharIndex) % 26])
          
        newMessage: str = "".join(messageList)
        return newMessage
        
        
# --- Main ---
def main():
    pass
    
if __name__ == "__main__":
    main()