import re

with open('./sherlock.txt') as f:
    data = f.read()
s = ''
for x in data:
    if x.isupper():
        s += x
print(s)
s = s.replace('ZERO', '0').replace('ONE', '1')
print(s)
l = re.findall(r'.{8}', s)
flag = ''
for x in l:
	flag += chr(int(x, 2))
print(flag) # BITSCTF{h1d3_1n_pl41n_5173}