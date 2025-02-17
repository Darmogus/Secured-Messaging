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
        newMessage: str = []
        for char in self.message:
            newMessage.append(Encrypt.ALPHABET[(Encrypt.ALPHABET_DICT[char] + key) % 26])
        
        newMessage = "".join(newMessage)
        return newMessage
        
        
class Decrypt:
    def __init__(self, message: str, key: str):
        self.message = message
        self.key = key
        
    def cesar(self) -> str:
        key: int = int(self.key)
        newMessage: str = []
        for char in self.message:
            newMessage.append(Encrypt.ALPHABET[(Encrypt.ALPHABET_DICT[char] - key) % 26])
        
        newMessage = "".join(newMessage)
        return newMessage
        
        
# --- Main ---
def main():
    print(Encrypt("cesar", "3").cesar())
    print(Decrypt("fhvdu", "3").cesar())
    
    
if __name__ == "__main__":
    main()