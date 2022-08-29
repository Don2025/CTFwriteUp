import requests
from base64 import b64decode
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Util.number import inverse

def factorize(n):
    l = []
    url="http://factordb.com/api?query="+str(n)
    r = requests.get(url)
    data = r.json()
    for factor in data['factors']:
        l.append(int(factor[0]))
    return l

with open('pubkey.pem', 'rb') as f:
    public_key = RSA.import_key(f.read())


n = public_key.n
e = public_key.e
q, p = factorize(n)
d = inverse(e, (p-1)*(q-1))
key_info = RSA.construct((n, e, d, p, q))
private_key = PKCS1_OAEP.new(key_info)

with open('flag.enc', 'rb') as f:
    cipher_text = b64decode(f.read())
    flag = private_key.decrypt(cipher_text).decode()

print(flag) # bugku{tw0_Tig3rs_l0V3_d4nc1ng~ei!}