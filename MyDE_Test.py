import MyDE as MyDE
import base64


def run_test():

    keysize = 2048
    filename = "DE_test.txt"
    de_filename = "DE_test_create_de.txt"
    read_de_filename = "DE_test_decrypt_de.text"

    # generate keypair
    print("\nReceiver generates 2048 RSA Keypair")
    r_keypair = MyDE.generate_keypair(keysize)

    # get private key
    privatekeyObj = MyDE.get_private_key(r_keypair)
    print(f"\nPrivate key: ")
    print(privatekeyObj.export_key())

    # get public key
    publickeyObj = MyDE.get_public_key(r_keypair)
    print(f"\nPublic key: ")
    print(publickeyObj.export_key())

    print("\nSender creates Digital Envelope using original file : ", de_filename)
    MyDE.createDE(publickeyObj, filename, de_filename)

    print("\nReceiver reads Digital Envelope to : ", read_de_filename)
    MyDE.openDE(privatekeyObj, de_filename, read_de_filename)

    return


if __name__ == "__main__":
    run_test()

