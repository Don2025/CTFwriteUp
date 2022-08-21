import rsa
import requests
import base64

def factorize(n):
    l = []
    url="http://factordb.com/api?query="+str(n)
    r = requests.get(url)
    data = r.json()
    for factor in data['factors']:
        l.append(int(factor[0]))
    return l

with open('public.pem','rb') as f:
    public_key = rsa.PublicKey.load_pkcs1_openssl_pem(f.read())

n = public_key.n
e = public_key.e
q, p = factorize(n)
d = rsa.common.inverse(e, (p-1)*(q-1))
private_key = rsa.PrivateKey(n, e, d, p, q)
flag = ''
for i in range(1, 5):
    with open('flag.enc'+str(i),'rb') as f:
        c = base64.b64decode(f.read())
        flag += rsa.decrypt(c, private_key).decode('utf-8')
flag = bytes.fromhex(str(flag)).decode()
print(flag) # flag{ISEC-Ir5WM_G4Afbvx_mSM_Ugf8zRAoMkYCPx}