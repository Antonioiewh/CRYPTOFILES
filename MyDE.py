__mydoc__ = """

C1. Implement encryptSymKey(publicKey, symKeyBase64) to encrypt symmetric secret key
C2. Implement decryptSymKey(privateKey, e_symKeyBase64) to encrypt symmetric secret key
C3. Implement createDE(r_publickey, in_filename, e_fileName) to create Digital Envelope (DE)
C4. Implement def openDE(r_privatekey, e_filename, d_filename) to extract original file from DE

"""

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64
import pickle

############ Digital Envelope Object ############
class DigitalEnvelope():
    # class attribute
    e_symKeyBase64 = None
    ciphertextBytes = None

    def __init__(self, e_symKeyBase64, ciphertextBytes):
        self.e_symKeyBase64 = e_symKeyBase64
        self.ciphertextBytes = ciphertextBytes

############ From AES ############
def genSymKey(keySize):
    keyBytes = get_random_bytes(keySize)
    keyBase64 = base64.b64encode(keyBytes).decode('utf-8')
    return keyBase64

############ From RSA ############
def generate_keypair(keySize):
    keypair = RSA.generate(keySize)
    return keypair

def get_private_key(keypair):
    privatekey = keypair.export_key()
    privatekeyObj = RSA.import_key(privatekey)
    return privatekeyObj

def get_public_key(keypair):
    publickey = keypair.publickey().export_key()
    publickeyObj = RSA.import_key(publickey)
    return publickeyObj

def rsa_encrypt(publickey, plaintext):
    rsa = PKCS1_OAEP.new(publickey)
    ciphertextBytes = rsa.encrypt(plaintext.encode("utf8"))
    ciphertextBase64 = base64.b64encode(ciphertextBytes).decode('utf-8')
    return ciphertextBase64


def rsa_decrypt(privatekey, ciphertextBase64):
    rsa = PKCS1_OAEP.new(privatekey)
    ciphertextBytes = base64.standard_b64decode(ciphertextBase64)
    decryptedtext = rsa.decrypt(ciphertextBytes)
    return decryptedtext

############ Challenge ############
def encryptSymKey(publicKey, symKeyBase64):
    # C1: encrypt secret key with Receiver's Public key
    rsa = PKCS1_OAEP.new(publicKey)
    symKeyBytes = symKeyBase64.encode('utf-8')
    e_symKeyBytes = rsa.encrypt(symKeyBytes)
    e_symKeyBase64 = base64.b64encode(e_symKeyBytes).decode('utf-8')
    return e_symKeyBase64

def decryptSymKey(privateKey, e_symKeyBase64):
    # C2: decrypt secret key with Receiver's Private key
    rsa = PKCS1_OAEP.new(privateKey)
    e_symKeyBytes = base64.b64decode(e_symKeyBase64)
    symKeyBytes = rsa.decrypt(e_symKeyBytes)
    symKeyBase64 = symKeyBytes.decode('utf-8')
    return symKeyBase64

def createDE(r_publickey, in_filename, e_fileName):
    # C3: Create Digital Envelope
    # create sym secret key
    symKeyBase64 = genSymKey(16)  # 16 bytes = 128 bits AES key
    keyBytes = base64.b64decode(symKeyBase64)
    # create AES in ECB mode cipher
    cipher = AES.new(keyBytes, AES.MODE_ECB)
    # read data in in_filename as plaintextbytes and encrypt 
    with open(in_filename, "rb") as input_file:
        plaintextBytes = input_file.read()
    ciphertextBytes = cipher.encrypt(pad(plaintextBytes, AES.block_size))
    # encrypt sym secret key
    e_symKeyBase64 = encryptSymKey(r_publickey, symKeyBase64)
    # create DE
    de = DigitalEnvelope(e_symKeyBase64, ciphertextBytes)
    # serialize DE object to file using pickle
    with open(e_fileName, "wb") as f:
        pickle.dump(de, f)
    return

def openDE(r_privatekey, e_filename, d_filename):
    # C4: Open Digital Envelope
    # read DE from file using pickle
    with open(e_filename, "rb") as f:
        de = pickle.load(f)
    # get sym secret key from DE
    e_symKeyBase64 = de.e_symKeyBase64
    # get ciphertext from DE
    ciphertextBytes = de.ciphertextBytes
    # decrypt e_symKeyBase64
    symKeyBase64 = decryptSymKey(r_privatekey, e_symKeyBase64)
    keyBytes = base64.b64decode(symKeyBase64)
    # decrypt ciphertextBytes
    cipher = AES.new(keyBytes, AES.MODE_ECB)
    decryptedtextBytes = unpad(cipher.decrypt(ciphertextBytes), AES.block_size)
    # write decryptedtextBytes to outfile
    with open(d_filename, "wb") as file_out:
        file_out.write(decryptedtextBytes)
    return
