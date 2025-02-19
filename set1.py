
class Challenge1:
    """Hex to Base64"""
    BASE64_TABLE = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    def __init__(self, hexString: str = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"):
        
        print(f"Hex string = {hexString}")
        binList: list[str] = self.convert_to_bin(hexString)
        byteList: list[str] = self.convert_to_bytes(binList)
        base64String: str = self.convert_to_base64(byteList)
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
            base64Char: str = Set1.BASE64_TABLE[binValue]
            base64String += base64Char
        
        # Ensure the base64 string length is a multiple of 4 by adding '=' padding
        while len(base64String) % 4 != 0:
            base64String = "=" + base64String
        
        return base64String


class Set2:
    ...


def main():
    Set1()

if __name__ == "__main__":
    main()