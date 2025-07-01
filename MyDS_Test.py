
import MyDS
import MyRsa
import base64

def run_test():


    keysize = 2048
    s_privatekeyFile = "s_private.pem"
    s_publickeyFile = "s_public.pem"
    filename = "DS_test.txt"
    altered_filename = "DS_alt_test.txt"

    # generate keypair
    print("\nGenerate 2048 Sender RSA Keypair and write sender private key into ", s_privatekeyFile , " and sender public key into ", s_publickeyFile)
    s_keypair = MyRsa.generate_keypair(keysize)

    # get private key
    s_privatekeyObj = MyRsa.get_private_key(s_keypair)
    print("\nSender private key \n", s_privatekeyObj.export_key().decode('utf-8'))
    MyRsa.write_private_key(s_keypair, s_privatekeyFile)

    # get public key
    s_publickeyObj = MyRsa.get_public_key(s_keypair)
    print("\nSender ppblic key\n", s_publickeyObj.export_key().decode('utf-8'))
    MyRsa.write_public_key(s_keypair, s_publickeyFile)


    myds = MyDS.my_sign(s_privatekeyObj,filename)
    print("\nSender creates digital signature for file using sender private key \n",  base64.b64encode(myds).decode('utf-8'))


    read_s_publickeyObj = MyRsa.read_public_key(s_publickeyFile)
    print("\nReciever read public key from public key file \n", read_s_publickeyObj.export_key().decode('utf-8'))

    verify = MyDS.my_verify(read_s_publickeyObj, filename, myds)
    print("\nReceiver verifies digital signature for file using sender public key \n  ", verify)

    verify = MyDS.my_verify(read_s_publickeyObj, altered_filename, myds)
    print("\nIf file is altered, receiver receives this when he verifies digital signature for file using sender public key \n  ", verify)

    return


if __name__ == "__main__":
    run_test()

