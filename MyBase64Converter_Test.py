

import MyBase64


def run_test():


    print("Generate 8 bytes of Random Bytes")
    testBytes=MyBase64.get_random_bytes(8)
    print("Print :", testBytes)
    print("Convert bytes to base64")
    testBytesBase64 = MyBase64.bytesToBase64(testBytes)
    print("In base64", testBytesBase64)
    print("Convert base64 to bytes")
    testBytes = MyBase64.base64ToBytes(testBytesBase64)
    print("Print :", testBytes)

    return


if __name__ == "__main__":
    run_test()