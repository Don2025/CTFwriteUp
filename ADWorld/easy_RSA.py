from gmpy2 import *
# 在一次RSA密钥对生成中, 假设p=473398607161, q=4511491, e=17, 求解出d。
p = mpz(473398607161)
q = mpz(4511491)
e = mpz(17)
phi_n = (p-1)*(q-1) 
d = invert(e, phi_n)    
flag = 'cyberpeace{' + str(d) + '}'
print(flag)  # cyberpeace{125631357777427553}