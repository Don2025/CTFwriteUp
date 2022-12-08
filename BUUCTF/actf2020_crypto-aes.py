from Crypto.Util.number import *
from Crypto.Cipher import AES
from pwn import xor

iv_key = 91144196586662942563895769614300232343026691029427747065707381728622849079757
cipher = b'\x8c-\xcd\xde\xa7\xe9\x7f.b\x8aKs\xf1\xba\xc75\xc4d\x13\x07\xac\xa4&\xd6\x91\xfe\xf3\x14\x10|\xf8p'
iv_key = long_to_bytes(iv_key)
key = iv_key[:16]*2
iv = xor(iv_key, key)[16:]
aes = AES.new(key, AES.MODE_CBC, iv)
flag = aes.decrypt(cipher).decode()
print(flag) # actf{W0W_y0u_can_so1v3_AES_now!}