

import MyHash


def run_test():


    # Testing hash_text_MD5(), hash_text_SHA256(), hash_text_SHA384(), hash_text_SHA512()
    print("Testing hash_text_MD5(), hash_text_SHA256(), hash_text_SHA384(), hash_text_SHA512():")
    plaintext_string = "Original message."
    altered_plaintext_string = "Original Message."
    longer_plaintext_string = "This ia a longer message than the Original message."

    print("plaintext: \n  " + plaintext_string)
    print("altered plaintext: \n  " + altered_plaintext_string)
    print("longer plaintext: \n  " + longer_plaintext_string)

    print("\nMD5 hash value of plaintext: \n  " + MyHash.hash_text_MD5(plaintext_string.encode("utf8")))
    print("MD5 hash value of altered plaintext: \n  " + MyHash.hash_text_MD5(altered_plaintext_string.encode("utf8")))
    print("MD5 hash value of longer plaintext: \n  " + MyHash.hash_text_MD5(longer_plaintext_string.encode("utf8")))


    print("\nSHA256 hash value of plaintext: \n  " + MyHash.hash_text_SHA256(plaintext_string.encode("utf8")))
    print("SHA256 hash value of altered plaintext: \n  " + MyHash.hash_text_SHA256(altered_plaintext_string.encode("utf8")))
    print("SHA256 hash value of longer plaintext: \n  " + MyHash.hash_text_SHA256(longer_plaintext_string.encode("utf8")))

    print("\nSHA384 hash value of plaintext: \n  " + MyHash.hash_text_SHA384(plaintext_string.encode("utf8")))
    print("SHA384 hash value of altered plaintext: \n  " + MyHash.hash_text_SHA384(altered_plaintext_string.encode("utf8")))
    print("SHA384 hash value of longer plaintext: \n  " + MyHash.hash_text_SHA384(longer_plaintext_string.encode("utf8")))

    print("\nSHA512 hash value of plaintext: \n  " + MyHash.hash_text_SHA512(plaintext_string.encode("utf8")))
    print("SHA512 hash value of altered plaintext: \n  " + MyHash.hash_text_SHA512(altered_plaintext_string.encode("utf8")))
    print("SHA512 hash value of longer plaintext: \n  " + MyHash.hash_text_SHA512(longer_plaintext_string.encode("utf8")))

    # Testing hash_file_SHA256()

    filename = "originalFile.docx"
    altered_filename = "alteredFile.docx"
    print("\nMD5 hash value of file: \n  " + MyHash.hash_file_MD5(filename))
    print("MD5 hash value of altered file: \n  " + MyHash.hash_file_MD5(altered_filename))



if __name__ == "__main__":
    run_test()
