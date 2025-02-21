# --- External librairies ---
import nltk
from nltk.corpus import words


class Challenge1:
    """Hex to Base64"""
    BASE64_TABLE = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    def __init__(self, hexString: str = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"):
        binList: list[str] = self.convert_to_bin(hexString)
        byteList: list[str] = self.convert_to_bytes(binList)
        base64String: str = self.convert_to_base64(byteList)
        
        print(f"Hex string = {hexString}")
        print(f"Base64 string = {base64String}")

    def convert_to_bin(self, hexString: str) -> list[str]:
        binList: list[str] = []
        for hexChar in hexString:
            binValue = bin(int(hexChar, 16))[2:].zfill(4)
            binList.append(binValue)
        return binList

    def convert_to_bytes(self, binList: list[str]) -> list[str]:
        binString: str = "".join(binList)
        byteList = [binString[i:i+6] for i in range(0, len(binString), 6)]
        
        # Padding
        if len(byteList[-1]) < 6:
            byteList[-1] = byteList[-1].ljust(6, '0')
            
        return byteList

    def convert_to_base64(self, byteList: list[str]) -> str:
        base64String: str = ""
        for byteChar in byteList:
            binValue: int = int(byteChar, 2)
            base64Char: str = Challenge1.BASE64_TABLE[binValue]
            base64String += base64Char
        
        # Ensure the base64 string length is a multiple of 4 by adding '=' padding
        while len(base64String) % 4 != 0:
            base64String = "=" + base64String
        
        return base64String


class Challenge2:
    """Fixed XOR"""
    def __init__(self, hexString1: str = "1c0111001f010100061a024b53535009181c", hexString2: str = "686974207468652062756c6c277320657965"):
        hexOutput = self.xor(self, hexString1, hexString2)
        
        print(hexString1)
        print(hexString2)
        print(hexOutput)
        
    def xor(self, hexString1, hexString2) -> str:
        int1 = int(hexString1, 16)
        int2 = int(hexString2, 16)
        
        xorResult = int1 ^ int2
        
        xorHex = hex(xorResult)[2:]  # Removing 0x
        
        xorHex = xorHex.zfill(len(self.hexString1)) # Padding
        
        return xorHex


class Challenge3:
    def __init__(self, hex_str = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"):
        self.hex_str = hex_str

    def hex_to_bytes(self):
        return bytes.fromhex(self.hex_str)

    def single_byte_xor(self, input_bytes, key):
        return bytes([b ^ key for b in input_bytes])

    def score_text(self, text):
        common_chars = "ETAOIN SHRDLU"
        return sum(text.upper().count(c) for c in common_chars)

    def decrypt_xor_cipher(self):
        ciphertext = self.hex_to_bytes()
        best_score = 0
        best_plaintext = None
        best_key = None

        for key in range(256):
            plaintext = self.single_byte_xor(ciphertext, key)
            try:
                decoded_text = plaintext.decode('utf-8')
                score = self.score_text(decoded_text)
                if score > best_score:
                    best_score = score
                    best_plaintext = decoded_text
                    best_key = key
            except UnicodeDecodeError:
                continue

        return best_key, best_plaintext
               

class Challenge4:
    def __init__(self, data_file: str = "set1_chall4_data.txt"):
        try:
            with open(data_file, 'r') as file:
                for line in file:
                    challenge = Challenge3(line)
                    result = challenge.decrypt_xor_cipher()
                    if result[0] is not None:
                        print(result)
        except FileNotFoundError:
            print(f"Erreur : fichier {data_file} introuvable.")
        


def main():
    print(Challenge3().decrypt_xor_cipher())
    print(Challenge4())

if __name__ == "__main__":
    main()