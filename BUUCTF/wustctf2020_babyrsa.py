import requests
from libnum import *

def factorize(n):
    l = []
    url="http://factordb.com/api?query="+str(n)
    r = requests.get(url)
    data = r.json()
    for factor in data['factors']:
        l.append(int(factor[0]))
    return l

c = 28767758880940662779934612526152562406674613203406706867456395986985664083182
n = 73069886771625642807435783661014062604264768481735145873508846925735521695159
e = 65537
q, p = factorize(n)
d = invmod(e, (p-1)*(q-1))
m = pow(c, d, n)
flag = n2s(m).decode()
print(flag)  # wctf2020{just_@_piece_0f_cak3}