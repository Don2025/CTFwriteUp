from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64
from flag import flag


f=open(r"pubkey.pem","r")
key=RSA.importKey(f.read())
cipher=PKCS1_OAEP.new(key)
cipher_txt=base64.b64encode(cipher.encrypt(flag))

with open(r"flag.enc","wb") as f:
    f.write(cipher_txt)
    f.close()

