import rsa
import requests
from Crypto.Util.number import inverse

def factorize(n):
    l = []
    url="http://factordb.com/api?query="+str(n)
    r = requests.get(url)
    data = r.json()
    for factor in data['factors']:
        l.append(int(factor[0]))
    return l

with open('pub.pem', 'rb') as f:
    public_key = rsa.PublicKey.load_pkcs1_openssl_pem(f.read())

n = public_key.n
e = public_key.e
q, p = factorize(n)
d = inverse(e, (p-1)*(q-1))
private_key = rsa.PrivateKey(n, e, d, p, q)

with open('flag.enc', 'rb') as f:
    flag = rsa.decrypt(f.read(), private_key).decode()

print(flag) # flag{decrypt_256}