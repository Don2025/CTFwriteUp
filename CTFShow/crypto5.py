from gmpy2 import *

p = mpz(447685307)
q = mpz(2037)
e = mpz(17)
c = mpz(704796792)
n = p*q
phi_n = (p-1)*(q-1)
d = invert(e, phi_n)
m = powmod(c, d, n)  # m = c^d%n
flag = 'flag{' + str(m) + '}' 
print(flag) # flag{904332399012}