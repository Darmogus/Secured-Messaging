# --- External Librairies ---
import os
import nltk
import string
import itertools
from nltk.corpus import words

# --- Internal Librairies ---
from crypt import Decrypt


# --- Classes ---
class Cesar:
    def __init__(self, encrypted_text: str):
        self.encrypted_text = encrypted_text
        nltk.download('words')
        self.words = set(words.words())
    
    def is_text_english(self, text: str, treshold: float) -> bool:
        words = text.split(" ")
        return len([word for word in words if word in self.words]) / len(words) >= treshold

    def run(self):
        os.system("cls")
        print("[*] Running Cesar...")
        message_found = False
        for key in range(1, 26):
            decrypted_text = Decrypt.cesar(self.encrypted_text, key)
            words = decrypted_text.split(" ")
            if len([word for word in words if word in self.words]) / len(words) >= 0.7:
                print(f"[+] Key found - Key {key}: {decrypted_text}.")
                message_found = True
        if not message_found:
            print("[-] No key found.")
            

class Vigenere:
    ENGLISH_FREQUENCIES = {'a': 0.0749, 'b': 0.0129, 'c': 0.0354, 'd': 0.0362, 'e': 0.1400, 'f': 0.0218, 
                           'g': 0.0174, 'h': 0.0422, 'i': 0.0665, 'j': 0.0027, 'k': 0.0047, 'l': 0.0357, 
                           'm': 0.0339, 'n': 0.0674, 'o': 0.0737, 'p': 0.0243, 'q': 0.0026, 'r': 0.0614, 
                           's': 0.0695, 't': 0.0985, 'u': 0.0300, 'v': 0.0116, 'w': 0.0169, 'x': 0.0028, 
                           'y': 0.0164, 'z': 0.0004}
    
    def __init__(self, encrypted_text: str):
        self.encrypted_text = encrypted_text
        
    def get_letter_occurences(self, text: str) -> dict[str, int]:
        lower_text: str = [letter for letter in text.lower() if letter in string.ascii_lowercase]
        occurrences: dict[str, int] = {'a': 0, 'b': 0, 'c': 0, 'd': 0, 'e': 0, 'f': 0, 'g': 0, 'h': 0, 'i': 0, 'j': 0, 'k': 0, 'l': 0,
                       'm': 0, 'n': 0, 'o': 0, 'p': 0, 'q': 0, 'r': 0, 's': 0, 't': 0, 'u': 0, 'v': 0, 'w': 0, 'x': 0,
                       'y': 0, 'z': 0}
        
        for letter in lower_text:
            occurrences[letter] += 1
            
        return occurrences
    
    def get_letter_frequencies(self, text: str) -> dict[str, float]:
        occurrences = self.get_letter_occurences(text)
        total_letters = sum(occurrences.values())
        frequencies = {letter: occurrences[letter] / total_letters for letter in occurrences}
        return frequencies

    def get_text_ressamblance(self, text: str) -> float:
        frequencies = self.get_letter_frequencies(text)
        ressamblance = sum(abs(frequencies[letter] - Vigenere.ENGLISH_FREQUENCIES[letter]) for letter in frequencies)
        return ressamblance
        
    def solve_key(self, min_key_size: int, max_key_size: int) -> str:
        best_keys = []
        text_letters = [letter for letter in self.encrypted_text.lower() if letter in string.ascii_lowercase]

        # Tester différentes longueurs de clé
        for key_length in range(min_key_size, max_key_size):
            key = [None] * key_length
            
            for key_index in range(key_length):
                # Extraction des lettres correspondant au même décalage dans la clé
                letters = "".join(itertools.islice(text_letters, key_index, None, key_length))
                shifts: list[dict[str: float]] = []
                
                # Tester chaque lettre de l'alphabet comme possible caractère de clé
                for key_char in string.ascii_lowercase:
                    shifts.append({key_char: self.get_text_ressamblance(Decrypt.vigenere(letters, key_char))})
                
                # Sélectionner la lettre minimisant l'écart de fréquence
                min_value = float('inf')
                min_key = None
                
                for shift in shifts:
                    for letter, freq in shift.items():
                        if freq < min_value:
                            min_value = freq
                            min_key = letter

                key[key_index] = min_key
            
            best_keys.append("".join(key))
        
        # Sélectionner la meilleure clé trouvée en minimisant l'écart de fréquence
        key_successes: dict[str, float] = {}
        for key in best_keys:
            success = self.get_text_ressamblance(Decrypt.vigenere(self.encrypted_text, key))
            key_successes[key] = success
            
        best_keys.sort(key=lambda key: key_successes[key])
        return best_keys
        
    def run(self, min_key_size: int, max_key_size: int):
        os.system("cls")
        print("[*] Running Vigenere...")
        print("============================================")
        keys = self.solve_key(min_key_size, max_key_size)
        print(Decrypt.vigenere(encrypted_text, keys[0]))
        print("============================================")
        print(f"[+] Key found: '{keys[0]}'")
    
if __name__ == "__main__":
    encrypted_text: str = str(input("Entrez votre texte chiffré avec Vigenere : ")
    v = Vigenere(encrypted_text)
    v.run()
