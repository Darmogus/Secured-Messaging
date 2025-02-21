import base64
from Crypto.Cipher import AES
from collections import Counter

class Challenge:
    def __init__(self, number: int):
        self.number = number
        print(f"\n==================== Challenge {number} ====================")


class Challenge1(Challenge):
    """Hex to Base64"""
    BASE64_TABLE = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    def __init__(self, hexString: str = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"):
        super().__init__(1)
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


class Challenge2(Challenge):
    """Fixed XOR"""
    def __init__(self, hexString1: str = "1c0111001f010100061a024b53535009181c", hexString2: str = "686974207468652062756c6c277320657965"):
        super().__init__(2)
        hexOutput = self.xor(hexString1, hexString2)
        
        print(hexOutput)
        
    def xor(self, hexString1, hexString2) -> str:
        int1 = int(hexString1, 16)
        int2 = int(hexString2, 16)
        
        xorResult = int1 ^ int2
        xorHex = hex(xorResult)[2:]  # Removing 0x
        xorHex = xorHex.zfill(len(hexString1)) # Padding
        
        return xorHex


class Challenge3(Challenge):
    def __init__(self, hexStr = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736", usedElsewhere = False):
        super().__init__(3) if not usedElsewhere else None
        self.hexStr = hexStr
        
        print(self.decrypt_xor_cipher()) if not usedElsewhere else None

    def hex_to_bytes(self):
        return bytes.fromhex(self.hexStr)

    def single_byte_xor(self, input_bytes, key):
        return bytes([b ^ key for b in input_bytes])

    def score_text(self, text):
        common_chars = "ETAOIN SHRDLU"
        return sum(text.upper().count(c) for c in common_chars)

    def decrypt_xor_cipher(self):
        ciphertext = self.hex_to_bytes()
        bestScore = 0
        bestPlaintext = None
        bestKey = None

        for key in range(256):
            plaintext = self.single_byte_xor(ciphertext, key)
            try:
                decodedText = plaintext.decode('utf-8')
                score = self.score_text(decodedText)
                if score > bestScore:
                    bestScore = score
                    bestPlaintext = decodedText
                    bestKey = key
            except UnicodeDecodeError:
                continue

        return bestKey, bestPlaintext
               

class Challenge4(Challenge):
    def __init__(self, dataFile: str = "set1_chall4_data.txt"):
        super().__init__(4)
        try:
            with open(dataFile, 'r') as file:
                for line in file:
                    challenge = Challenge3(line, True)
                    result = challenge.decrypt_xor_cipher()
                    if result[0] is not None:
                        print(result)
        except FileNotFoundError:
            print(f"Erreur : fichier {dataFile} introuvable.")
            

class Challenge5(Challenge):
    def __init__(self, plaintext, key):
        super().__init__(5)
        self.plaintext = plaintext
        self.key = key
        
        print(self.repeating_key_xor())

    def repeating_key_xor(self):
        ciphertext = bytearray()
        keyLength = len(self.key)

        for i, char in enumerate(self.plaintext):
            ciphertext.append(ord(char) ^ ord(self.key[i % keyLength]))  # XOR avec la clé répétée

        return ciphertext.hex()
    

class Challenge6(Challenge):
    def __init__(self, file_path):
        super().__init__(6)
        self.file_path = file_path
        self.ciphertext = self._load_and_decode_file()
        
        self.decrypt()
        
    def _load_and_decode_file(self):
        """Charge le fichier Base64 et le décode en texte chiffré (bytes)."""
        with open(self.file_path, "r") as file:
            base64_encoded_text = file.read().replace("\n", "")
            return base64.b64decode(base64_encoded_text)
    
    def hamming_distance(self, str1, str2):
        """Calcul la distance de Hamming entre deux chaînes de bytes."""
        return sum(bin(a ^ b).count('1') for a, b in zip(str1, str2))
    
    def find_keysize(self):
        """Trouve la taille de clé la plus probable en testant différentes tailles."""
        min_distance = float('inf')
        best_keysize = 0
        for keysize in range(2, 41):
            distances = []
            for i in range(0, len(self.ciphertext), keysize):
                block1 = self.ciphertext[i:i + keysize]
                block2 = self.ciphertext[i + keysize:i + 2 * keysize]
                if len(block1) == keysize and len(block2) == keysize:
                    dist = self.hamming_distance(block1, block2) / keysize
                    distances.append(dist)
            avg_distance = sum(distances) / len(distances)
            if avg_distance < min_distance:
                min_distance = avg_distance
                best_keysize = keysize
        return best_keysize
    
    def decrypt(self):
        """Démarre le processus pour trouver la clé et décrypter le texte chiffré."""
        keysize = self.find_keysize()
        print(f"La meilleure taille de clé estimée est : {keysize}")
        # Ajoutez d'autres étapes ici pour casser le chiffrement avec la clé trouvée.


class Challenge7(Challenge):
    def __init__(self, key):
        super().__init__(7)
        self.key = key.encode()  # Convertir la clé en bytes
        self.cipherText = self.load_base64_file("set1_chall7_data.txt")
        self.plainText = self.decrypt_aes_ecb(self.cipherText)
        
        print(self.plainText)

    def decrypt_aes_ecb(self, ciphertext):
        cipher = AES.new(self.key, AES.MODE_ECB)  # Initialiser AES-ECB
        decrypted = cipher.decrypt(ciphertext)  # Déchiffrement
        return decrypted.decode('utf-8')  # Retour en texte lisible

    @staticmethod
    def load_base64_file(filename):
        with open(filename, 'r') as file:
            base64Content = file.read()
        return base64.b64decode(base64Content)  # Décodage Base64


class Challenge8(Challenge):
    def __init__(self, filePath: str = "set1_chall8_data.txt"):
        super().__init__(8)
        self.filePath = filePath
        
        ciphertexts = self.read_hex_file()
        index, ecb_ciphertext = self.detect_ecb_cipher(ciphertexts)
        
        print(f"ECB détecté dans le texte chiffré à l'index {index}:")
        print(ecb_ciphertext.hex())
    
    def detect_ecb_cipher(self, ciphertexts: list) -> tuple:
        for idx, ciphertext in enumerate(ciphertexts):
            blocks = [ciphertext[i:i+16] for i in range(0, len(ciphertext), 16)]  # Diviser en blocs de 16 bytes
            blockCounts = Counter(blocks)  # Compter les occurrences des blocs
            # Si un bloc apparaît plus d'une fois, c'est probablement du ECB
            if any(count > 1 for count in blockCounts.values()):
                return idx, ciphertext  # Retourne l'index et le texte chiffré

    def safe_hex_decode(self, hexStr: str) -> bytes:
        # Supprimer les espaces et caractères invisibles
        hexStr = ''.join([c for c in hexStr if c in '0123456789abcdefABCDEF'])
        # Vérifier si la longueur est paire avant de décoder
        if len(hexStr) % 2 != 0:
            raise ValueError(f"Invalid hex string: {hexStr} (length must be even)")
        return bytes.fromhex(hexStr)

    def read_hex_file(self) -> list:
        # Lire chaque ligne du fichier et décoder les hex
        ciphertexts = []
        with open(self.filePath, 'r') as file:
            for line in file:
                line = line.strip()  # Enlever les espaces ou les retours à la ligne
                if line:  # Si la ligne n'est pas vide
                    try:
                        ciphertexts.append(self.safe_hex_decode(line))
                    except ValueError as e:
                        print(f"Erreur dans la ligne: {e}")
        return ciphertexts


def main():
    Challenge1()
    Challenge2(hexString1="1c0111001f010100061a024b53535009181c", hexString2="686974207468652062756c6c277320657965")
    Challenge3().decrypt_xor_cipher()
    Challenge4()
    Challenge5("Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal", "ICE").repeating_key_xor()
    Challenge6("set1_chall6_data.txt")
    Challenge7("YELLOW SUBMARINE").decrypt_aes_ecb(Challenge7.load_base64_file("set1_chall7_data.txt"))
    Challenge8()
    

if __name__ == "__main__":
    main()