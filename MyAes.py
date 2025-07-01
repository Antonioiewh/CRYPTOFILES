__mydoc__ = """
MyAes.py

Challenges:
----------
C1. Implement genKey(keySize) to return Base64 of random size = keySize x 8 bits.

C2. Implement AES encrypt(keyBase64, plaintext) where:
- keyBase64: AES key in Base64 format
- plaintext_utf8: plaintext in UTF8 format
- assumption: use CBC mode, IV and default padding (PKCS7)
- return: iv and cipherText in Base64 format

C3. Implement AES decrypt(ivBase64, keyBase64, ciphertextBase64) where:
- ivBase64: iv in Base64 format
- keyBase64: AES key in Base64 format
- ciphertextBase64: ciphertext in Base64 format
- assumption: use CBC mode and default padding (PKCS7)
- return: decryptedtext

C4. Implement AES encryptToFile(keyBase64, plaintext, filename) where:
- keyBase64: AES key in Base64 format
- plaintext_utf8: plaintext in UTF8 format
- create filename
- assumption: use CBC mode, IV and default padding (PKCS7)
- return: nil

C5. Implement AES decryptFromFile(keyBase64, filename) where:
- keyBase64: AES key in Base64 format
- filename is name of file with iv and ciphertext
- assumption: use CBC mode, IV and default padding (PKCS7)
- return: decryptedtext

Check that the ciphertext file (ciphertext.bin) is also created.

Optional:
---------
Modify to support CFB and OFB modes.

"""

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import base64

def genKey(keySize):
    # Generate random key of size keySize (in bytes)
    keyBytes = get_random_bytes(keySize)
    keyBase64 = base64.b64encode(keyBytes).decode('utf-8')
    return keyBase64

def aes_encrypt(keyBase64, plaintext):
    # convert key and plaintext to bytes
    keyBytes = base64.b64decode(keyBase64)
    plaintextBytes = plaintext.encode('utf-8')
    # create cipher with key and CBC mode
    cipher = AES.new(keyBytes, AES.MODE_CBC)
    # pad plaintext and encrypt
    ciphertextBytes = cipher.encrypt(pad(plaintextBytes, AES.block_size))
    ivBytes = cipher.iv
    # Convert ciphertext and iv from bytes to base64
    ciphertextBase64 = base64.b64encode(ciphertextBytes).decode('utf-8')
    ivBase64 = base64.b64encode(ivBytes).decode('utf-8')
    return ivBase64, ciphertextBase64

def aes_decrypt(ciphertextBase64, keyBase64, ivBase64):
    # convert key, iv, ciphertext to bytes
    keyBytes = base64.b64decode(keyBase64)
    ivBytes = base64.b64decode(ivBase64)
    ciphertextBytes = base64.b64decode(ciphertextBase64)
    # create cipher with key, iv and specify mode
    cipher = AES.new(keyBytes, AES.MODE_CBC, iv=ivBytes)
    # decrypt ciphertext and unpad
    decryptedtextBytes = unpad(cipher.decrypt(ciphertextBytes), AES.block_size)
    decryptedtext = decryptedtextBytes.decode('utf-8')
    return decryptedtext

def aes_encryptToFile(keyBase64, plaintext, fileName):
    # convert key and plaintext to bytes
    keyBytes = base64.b64decode(keyBase64)
    plaintextBytes = plaintext.encode('utf-8')
    # create cipher with key and specify mode
    cipher = AES.new(keyBytes, AES.MODE_CBC)
    ciphertextBytes = cipher.encrypt(pad(plaintextBytes, AES.block_size))
    ivBytes = cipher.iv
    # write iv and ciphertext bytes to file
    with open(fileName, 'wb') as file_out:
        file_out.write(ivBytes)
        file_out.write(ciphertextBytes)
    return

def aes_decryptFromFile(keyBase64, fileName):
    keyBytes = base64.b64decode(keyBase64)
    with open(fileName, 'rb') as fileIn:
        ivBytes = fileIn.read(16)  # AES block size is 16 bytes
        ciphertextBytes = fileIn.read()
    cipher = AES.new(keyBytes, AES.MODE_CBC, iv=ivBytes)
    decryptedtextBytes = unpad(cipher.decrypt(ciphertextBytes), AES.block_size)
    decryptedtext = decryptedtextBytes.decode('utf-8')
    return decryptedtext