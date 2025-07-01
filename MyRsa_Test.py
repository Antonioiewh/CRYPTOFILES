

import MyRsa
import base64
import binascii
from Crypto.PublicKey import RSA


def run_test():


    keysize = 2048
    privatekeyFile = "a_private.pem"
    publickeyFile = "a_public.pem"
    plaintext = "This is the string to be encrypted by RSA."

    # generate keypair
    print("\nGenerate 2048 RSA Keypair")
    keypair = MyRsa.generate_keypair(keysize)

    # get private key
    privatekeyObj = MyRsa.get_private_key(keypair)
    print(f"\nPrivate key: \n(N={hex(privatekeyObj.n)}\n D={hex(privatekeyObj.d)})")
    print(privatekeyObj.export_key())

    # get public key
    publickeyObj = MyRsa.get_public_key(keypair)
    print(f"\nPublic key: \n(N={hex(publickeyObj.n)}\n E={hex(publickeyObj.e)})")
    print(publickeyObj.export_key())

    #Test C4,C5

    print("\nWrite private key into ", privatekeyFile , " and public key into ", publickeyFile)
    # store keypair in files
    MyRsa.write_private_key(keypair, privatekeyFile)
    MyRsa.write_public_key(keypair, publickeyFile)


    #Test C6,C7,C8,C9

    print("Read private key from ", privatekeyFile)
    readPrivatekey = MyRsa.read_private_key(privatekeyFile)
    print("Read public key from ", publickeyFile)
    readPublickey = MyRsa.read_public_key(publickeyFile)

    print("\nPlaintext : ", plaintext)
    print("\nGenerate ciphertext with publickey read from " + publickeyFile)
    ciphertextBase64 = MyRsa.encrypt(readPublickey, plaintext.encode("utf8"))
    print("Ciphertext in base64: " , ciphertextBase64)

    print("\nDecrypt ciphertext with privatekey read from " + privatekeyFile )
    decryptedtext = MyRsa.decrypt(readPrivatekey, ciphertextBase64).decode("utf8")
    print("Decryptedtext : " , decryptedtext)


    return


if __name__ == "__main__":
    run_test()
