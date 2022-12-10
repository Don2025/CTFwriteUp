import os
import requests
from pwn import *
from gmpy2 import iroot
from binascii import hexlify
from Crypto.Util.number import *

def proof(s1, s2):
    os.system(f"hashcat -a 3 --hex-salt -m 1420 {s1}:{s2} --potfile-disable ?b?b?b -o tmp.txt --outfile-format=2")
    with open('tmp.txt', 'r') as f:
        l = f.readlines()
    lastline = l[-1]
    if(lastline[0:4]=="$HEX"):
        ans = s2+lastline[5:11]
    else:
        ans = s2+hex(lastline)
    return ans


def challenge1(c, e):
    '''
    已知n, e, c, n很大, e很小, c = m^e
    '''
    m = iroot(c, e)[0]
    flag = long_to_bytes(m)
    return hexlify(flag)


def factorize(n):
    l = []
    url="http://factordb.com/api?query="+str(n)
    r = requests.get(url)
    data = r.json()
    for factor in data['factors']:
        l.append(int(factor[0]))
    return l


def fuck_challenge(n, e, c):
    '''
    已知n, e, c, 暴力分解n得p,q 常规求解
    '''
    q, p = factorize(n)
    d = inverse(e, (p-1)*(q-1))
    m = pow(c, d, n)
    flag = long_to_bytes(m)
    return hexlify(flag) 


def CRT(remainder, modulus):
    '''
    利用中国剩余定理求解同余方程, 
    remainder 余数, modulus 模数
    '''
    M = 1
    for i in modulus:
        M *= i
    ans = 0
    for i in range(len(modulus)):
        Mi = M//modulus[i]
        ans += remainder[i]*Mi*inverse(Mi, modulus[i])
    return ans%M


def challenge4(N, C, e):
    '''
    利用中国剩余定理
    '''
    m_e = CRT(C, N) # m^e
    m = iroot(m_e, e)[0]
    flag = long_to_bytes(m)
    return hexlify(flag)


io = remote('node4.buuoj.cn', 25044)
io.recvuntil(b'hashlib.sha256(skr).hexdigest()=')
s1 = io.recvline().strip().decode()
io.recvuntil(b"skr[0:5].encode('hex')=")
s2 = io.recvline().strip().decode()
payload = proof(s1, s2).encode()
io.sendlineafter(b"skr.encode('hex')=\n", payload)
# challenge 1
io.recvuntil(b'e=')
e = int(io.recvline().strip())
io.recvuntil(b'c=pow(m,e,n)=')
c = int(io.recvline().strip())
payload1 = challenge1(c, e)
io.sendlineafter(b"long_to_bytes(m).encode('hex')=", payload1)
# payload1 = 464c41477b325e3872736137353839363933666336383963373763356635323632643635343237323432377d
# challenge 2
io.recvuntil(b'n=')
n = int(io.recvline().strip())
io.recvuntil(b'e=')
e = int(io.recvline().strip())
io.recvuntil(b'c=pow(m,e,n)=')
c = int(io.recvline().strip())
payload2 = fuck_challenge(n, e, c)
# payload2 = 464c41477b325e3872736136653237376633353564626536646133656464366633353664326462366436667d
io.sendlineafter(b"long_to_bytes(m).encode('hex')=", payload2)
# challenge 3
io.recvuntil(b'n=')
n = int(io.recvline().strip())
io.recvuntil(b'e=')
e = int(io.recvline().strip())
io.recvuntil(b'c=pow(m,e,n)=')
c = int(io.recvline().strip())
payload3 = fuck_challenge(n, e, c)
# payload3 = 464c41477b325e3872736135616230383637343566366563373435363139613862363566653465633536307d
io.sendlineafter(b"long_to_bytes(m).encode('hex')=", payload3)
# challenge 4
io.recvuntil(b'e=')
e = int(io.recvline().strip())
io.recvuntil(b'n1=')
n1 = int(io.recvline().strip())
io.recvuntil(b'c1=pow(m,e,n1)=')
c1 = int(io.recvline().strip())
io.recvuntil(b'n2==') # 真sb 这出题人多写了个=
n2 = int(io.recvline().strip())
io.recvuntil(b'c2=pow(m,e,n2)=')
c2 = int(io.recvline().strip())
io.recvuntil(b'n3=')
n3 = int(io.recvline().strip())
io.recvuntil(b'c3=pow(m,e,n3)=')
c3 = int(io.recvline().strip())
payload4 = challenge4([n1,n2,n3], [c1,c2,c3], e)
# payload4 = 464c41477b325e3872736138633566336366663462633039353334396665633635666332323633653837387d
io.sendlineafter(b"long_to_bytes(m).encode('hex')=", payload4)
# challenge 5
io.recvuntil(b'n=')
n = int(io.recvline().strip())
io.recvuntil(b'e=')
e = int(io.recvline().strip())
io.recvuntil(b'c=pow(m,e,n)=')
c = int(io.recvline().strip())
io.recvuntil(b'x=pow(m+1,e,n)=')
x = int(io.recvline().strip())
# payload5 = challenge(n, e, c, x)
payload5 = b'464c41477b325e3872736133393863663864663763323636363162623763623635623262396661653235657d'
io.sendlineafter(b"long_to_bytes(m).encode('hex')=", payload5)
# challenge 6
'''io.recvuntil(b'n=')
n = int(io.recvline().strip())
io.recvuntil(b'hex(e)=')
e = int(io.recvline().strip())
io.recvuntil(b'c=pow(m,e,n)=')
c = int(io.recvline().strip())
'''
payload6 = b'6b3bb0cdc72a7f2ce89902e19db0fb2c0514c76874b2ca4113b86e6dc128d44cc859283db4ca8b0b5d9ee35032aec8cc8bb96e8c11547915fc9ef05aa2d72b28'
io.sendlineafter(b"long_to_bytes(m).encode('hex')=", payload6)
io.interactive()
