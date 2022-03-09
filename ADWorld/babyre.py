s = 'fmcd' + chr(127) + 'k7d;V`;np'
flag = ''
for i in range(14):
    flag += chr(ord(s[i])^i)
print(flag) # flag{n1c3_j0b}