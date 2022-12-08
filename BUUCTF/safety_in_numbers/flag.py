import rsa
from gmpy2 import iroot
from Crypto.Util.number import long_to_bytes

with open('pubkey.pem', 'rb') as f:
    pubkey = rsa.PublicKey.load_pkcs1_openssl_pem(f.read())

# n = pubkey.n
e = pubkey.e
# e = 65537
with open('flag.enc', 'rb') as f:
   cipher = f.read()

c = int.from_bytes(cipher, byteorder='little')
m = iroot(c, e)[0]
flag = long_to_bytes(m)[::-1]
print(flag.decode())  # pctf{!fUtuR3_pR00f}