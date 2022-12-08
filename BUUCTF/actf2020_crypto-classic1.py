s = 'SRLU{LZPL_S_UASHKXUPD_NXYTFTJT}'
m = 'ACTF{'
l = []
for i in range(4):
    l.append(str(ord(s[i])-ord(m[i])))
flag = m
for i in range(5,len(s)):
    if s[i].isupper():
        flag += chr((ord(s[i])-int(l[i%4])-ord('A'))%26+ord('A'))
    else:
        flag += s[i]
print(flag) # ACTF{WHAT_A_CLASSICAL_VIGENERE}