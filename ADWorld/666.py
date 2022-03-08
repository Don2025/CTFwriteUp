enflag = 'izwhroz""w"v.K".Ni'
key = len(enflag)
flag = ''
for i in range(0, key, 3):
    flag += chr((key^ord(enflag[i]))-6)
    flag += chr((key^ord(enflag[i+1]))+6)
    flag += chr(key^ord(enflag[i+2])^6)
print(flag) # unctf{b66_6b6_66b}