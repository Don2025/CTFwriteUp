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

with open('public.key', 'rb') as f:
    public_key = RSA.importKey(f.read())

n = public_key.n
e = public_key.e
q, p = factorize(n)
d = inverse(e, (p-1)*(q-1))
key_info = RSA.construct((n, e, d, p, q))
key = RSA.importKey(key_info.exportKey())
private_key = PKCS1_OAEP.new(key)

with open('flag.enc', 'rb') as f:
    cipher_text = b64decode(f.read())
    flag = private_key.decrypt(cipher_text).decode()

print(flag) # afctf{R54_|5_$0_B0rin9}