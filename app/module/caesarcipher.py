class Caesar:
    def __init__(self, text, shift):
        self.text = text
        self.shift = shift

    def encrypt(self):
        result = ""

        # traverse text
        for i in range(len(self.text)):
            char = self.text[i]

            # Encrypt uppercase characters
            if (char.isupper()):
                result += chr((ord(char) + self.shift - 65) % 26 + 65)

            # Encrypt lowercase characters
            else:
                result += chr((ord(char) + self.shift - 97) % 26 + 97)

        return result

    def decrypt(self):
        result = ""

        # traverse text
        for i in range(len(self.text)):
            char = self.text[i]

            # Decrypt uppercase characters
            if (char.isupper()):
                result += chr((ord(char) - self.shift - 65) % 26 + 65)

            # Decrypt lowercase characters
            else:
                result += chr((ord(char) - self.shift - 97) % 26 + 97)

        return result


# txt = Caesar("ATTACKATONCE",4).decrypt()
# print(txt)
# txt = Caesar("EXXEGOEXSRGI",4).decrypt()
# print(txt)
