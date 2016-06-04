import os

from Crypto import Random

from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Cipher import AES

def decrypt_valuables(f):
    #Check if a key pair exsits, if not, exit
    if not os.path.exists("private_key.pem"):
        print("No key pair has been initialised")
        os.exit(1)
    # Import key from file
    private_key = RSA.importKey(open('private_key.pem').read())
    # TODO: For Part 2, you'll need to decrypt the contents of this file
    # The existing scheme uploads in plaintext
    # As such, we just convert it back to ASCII and print it out
    cipher = PKCS1_OAEP.new(private_key, hashAlgo=SHA256)
    # Take the RSA encrypted AES key from the file
    key = cipher.decrypt(f[:512])
    # Take the iv from the file
    iv = f[512:528]
    # Create the AES cipher using the AES key and iv from the file
    AES_cipher = AES.new(key, AES.MODE_CFB, iv)
    # Decrypt the file contents using the AES cipher
    decoded_text = AES_cipher.decrypt(f[528:])
    print(decoded_text)
    return decoded_text


if __name__ == "__main__":
    fn = input("Which file in pastebot.net does the botnet master want to view? ")
    if not os.path.exists(os.path.join("pastebot.net", fn)):
        print("The given file doesn't exist on pastebot.net")
        os.exit(1)
    f = open(os.path.join("pastebot.net", fn), "rb").read()
    decrypt_valuables(f)
