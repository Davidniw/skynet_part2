import os

from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5

def create_key():
    key = RSA.generate(4096)
    # Private key is assumed to be stored on the botmaster server
    file = open("private_key.pem", "wb")
    file.write(key.exportKey("PEM"))
    file.close()
    # Public key is stored and distributed via pastebot.net
    file = open("pastebot.net\public_key.pem", "wb")
    file.write(key.publickey().exportKey("PEM"))
    file.close()
    return key

def sign_file(f):
    # TODO: For Part 2, you'll use public key crypto here
    # The existing scheme just ensures the updates start with the line 'Caesar'
    # This is naive -- replace it with something better!
    try:
        file = open("private_key.pem", "rb")
        private_key = RSA.importKey(file.read())
        print("Key imported.")
    except FileNotFoundError:
        private_key = create_key()
        print("Key created.")
    hash = SHA256.new(f)
    signer = PKCS1_v1_5.new(private_key)
    signature = signer.sign(hash)
    return signature + f

if __name__ == "__main__":
    fn = input("Which file in pastebot.net should be signed? ")
    if not os.path.exists(os.path.join("pastebot.net", fn)):
        print("The given file doesn't exist on pastebot.net")
        os.exit(1)
    f = open(os.path.join("pastebot.net", fn), "rb").read()
    signed_f = sign_file(f)
    signed_fn = os.path.join("pastebot.net", fn + ".signed")
    out = open(signed_fn, "wb")
    out.write(signed_f)
    out.close()
    print("Signed file written to", signed_fn)
