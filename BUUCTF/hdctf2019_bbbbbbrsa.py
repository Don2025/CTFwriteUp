from libnum import *
from base64 import b64decode

p = 177077389675257695042507998165006460849
n = 37421829509887796274897162249367329400988647145613325367337968063341372726061
c = '==gMzYDNzIjMxUTNyIzNzIjMyYTM4MDM0gTMwEjNzgTM2UTN4cjNwIjN2QzM5ADMwIDNyMTO4UzM2cTM5kDN2MTOyUTO5YDM0czM3MjM'
q = n//p
c = int(b64decode(c[::-1]))
# c = 2373740699529364991763589324200093466206785561836101840381622237225512234632
phi = (p-1)*(q-1)
for e in range(50000, 70000):
    if gcd(e, phi) == 1:
        d = invmod(e, phi)
        m = pow(c, d, n)
        if b'flag' in n2s(m):
            print('e = ', e) # e =  51527
            flag = n2s(m).decode()
            print(flag) # flag{rs4_1s_s1mpl3!#}
            break