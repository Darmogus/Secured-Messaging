# --- Internal librairies ---
from main import Vigenere

if __name__ == "__main__":
    with open("manifesto.txt", "r", encoding="utf-8") as file:
        encrypted_text = file.read()  # Read the entire content of the file
    vigenere = Vigenere(encrypted_text)
    vigenere.run(1, 19)
