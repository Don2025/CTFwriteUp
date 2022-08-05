import gmpy2
import libnum

n, e = 920139713, 19
p, q = list(libnum.factorize(n).keys()) # 49891 18443
d = gmpy2.invert(e, (p-1)*(q-1))
flag = ''
with open('data.txt', 'r') as f:
    for c in f.readlines():
        m = pow(int(c), d, n)
        flag += chr(m)

print(flag) # flag{13212je2ue28fy71w8u87y31r78eu1e2}