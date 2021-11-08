from gmpy2 import *

p = mpz(447685307)
q = mpz(2037)
e = mpz(17)
phi_n = (p-1)*(q-1) 
d = invert(e, phi_n)
flag = 'flag{' + str(d) + '}'
print(flag) # flag{53616899001}