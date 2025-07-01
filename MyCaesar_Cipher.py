LETTERS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'    # C1
LETTERSUPPERLOWER = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'  # C2
BASE64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=' # C3


def encrypt(key, plaintext_utf8, list=LETTERS):
    ciphertext_utf8 = ""

    for character in plaintext_utf8:
        if character in list:
            position = list.find(character)
            position = position + key
            if position >= len(list):
                position = position - len(list)
            ciphertext_utf8 = ciphertext_utf8 + list[position]
        else:
            ciphertext_utf8 = ciphertext_utf8 + character

    return ciphertext_utf8


def decrypt(key, ciphertext_utf8, list=LETTERS):
    decryptedtext_utf = ""

    for character in ciphertext_utf8:
        if character in list:
            position = list.find(character)
            position = position - key
            if position < 0:
                position = position + len(list)
            decryptedtext_utf = decryptedtext_utf + list[position]
        else:
            decryptedtext_utf = decryptedtext_utf + character

    return decryptedtext_utf