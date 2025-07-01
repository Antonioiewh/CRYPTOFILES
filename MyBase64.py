from Crypto.Random import get_random_bytes
import base64

def generateRandom(numOfBytes):
    # Change C1: Generate random
    key_bytes = get_random_bytes(numOfBytes)
    return key_bytes

def bytesToBase64(inBytes):
    # Change C2: Convert bytes to base64
    inBase64 = base64.b64encode(inBytes).decode('utf-8')
    return inBase64

def base64ToBytes(inBase64):
    # Change C2: Convert base64 to bytes
    inBytes = base64.b64decode(inBase64.encode('utf-8'))
    return inBytes
