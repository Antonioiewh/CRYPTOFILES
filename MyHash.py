__mydoc__ = """


Challenge:

C1. Implement hash_MD5(plaintext_utf8) to return MD5 hash value of plaintext
C2. Implement hash_SHA256(plaintext_utf8) to return SHA256 hash value of plaintext
C3. Implement hash_SHA384(plaintext_utf8) to return SHA384 hash value of plaintext
C4. Implement SHA512(plaintext_utf8) to return SHA512 hash value of plaintext

"""

from Crypto.Hash import MD5, SHA256, SHA384, SHA512


def hash_text_MD5(plaintext_utf8):
    # C1: create new MD5 object
    md5 = MD5.new()
    # C1: update with plaintext
    md5.update(plaintext_utf8)
    # C1: get digest in hexadecimal values
    md5Md = md5.hexdigest()
    return md5Md

def hash_text_SHA256(plaintext_utf8):
    # C2: create new SHA256 object
    sha256 = SHA256.new()
    # C2: update with plaintext
    sha256.update(plaintext_utf8)
    # C2: get digest in hexadecimal values
    sha256Md = sha256.hexdigest()
    return sha256Md

def hash_text_SHA384(plaintext_utf8):
    # C3: create new SHA384 object
    sha384 = SHA384.new()
    # C3: update with plaintext
    sha384.update(plaintext_utf8)
    # C3: get digest in hexadecimal values
    sha384Md = sha384.hexdigest()
    return sha384Md

def hash_text_SHA512(plaintext_utf8):
    # C4: create new SHA512 object
    sha512 = SHA512.new()
    # C4: update with plaintext
    sha512.update(plaintext_utf8)
    # C4: get digest in hexadecimal values
    sha512Md = sha512.hexdigest()
    return sha512Md

def hash_file_MD5(filename):
    # C5: create new MD5 object
    md5 = MD5.new()
    # C5: open file to read data and hash data
    # Alternatively, do this:
    with open(filename, "rb") as input_file:
        file_data = input_file.read()
        md5.update(file_data)
    
    md5Md = md5.hexdigest()
    return md5Md

