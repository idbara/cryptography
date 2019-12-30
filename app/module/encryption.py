def reversecipher(plaintext):
    ciphertext = ''  #cipher text is stored in this variable
    i = len(plaintext) - 1
    while i >= 0:
        ciphertext = ciphertext + plaintext[i]
        i = i - 1
    return ciphertext


def rot13(plaintext):
    table = plaintext.maketrans(
        'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz',
        'NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm')
    ciphertext = plaintext.translate(table)
    return ciphertext


def reverserot13encrypt(plaintext):
    h1 = reversecipher(plaintext)
    result = rot13(h1)
    return result


def reverserot13decrypt(ciphertext):
    h1 = rot13(ciphertext)
    result = reversecipher(h1)
    return result
