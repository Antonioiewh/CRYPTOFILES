
import MyCaesar_Cipher


def run_test():
    

    # Caesar key, 3 denotes shifting 3 character positions
    key = 3

    plaintext = input("Enter plaintext: ")
    ciphertext = MyCaesar_Cipher.encrypt(key, plaintext)
    decryptedtext = MyCaesar_Cipher.decrypt(key, ciphertext)
    print("ciphertext: " + ciphertext)
    print("decryptedtext: " + decryptedtext + "\n")

    return


if __name__ == "__main__":
    run_test()
