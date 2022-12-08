from gmpy2 import iroot
from libnum import n2s

with open('rsa_16m', 'r') as f:
    data = f.read().split('\n')

c = int(data[1][4:], 16)
e = int(data[2][4:], 16)
m = int(iroot(c, e)[0])
flag = n2s(m).decode()
print(flag) # INSA{(I)NSA_W0uld_bE_pr0uD}