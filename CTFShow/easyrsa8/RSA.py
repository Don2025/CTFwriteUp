import requests
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
private_key = PKCS1_OAEP.new(key_info)

with open('flag.enc', 'rb') as f:
    flag = private_key.decrypt(f.read()).decode()

print(flag) # flag{p_1s_5mall_num6er}