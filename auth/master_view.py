from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA
from Crypto.PublicKey import RSA
import os


def decrypt_valuables(f):
    #Check if a key pair exsits, if not, exit
    if not os.path.exists(masterkey.pem):
        print("No key pair has been initialised")
        os.exit(1)
    # Import key from file
    key = RSA.importKey(open('masterkey.pem').read())
    # TODO: For Part 2, you'll need to decrypt the contents of this file
    # The existing scheme uploads in plaintext
    # As such, we just convert it back to ASCII and print it out
    decoded_text = key.decrypt(f)
    print(decoded_text)
    return decoded_text


if __name__ == "__main__":
    fn = input("Which file in pastebot.net does the botnet master want to view? ")
    if not os.path.exists(os.path.join("pastebot.net", fn)):
        print("The given file doesn't exist on pastebot.net")
        os.exit(1)
    f = open(os.path.join("pastebot.net", fn), "rb").read()
    decrypt_valuables(f)
