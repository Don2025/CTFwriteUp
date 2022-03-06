v6 = 7
v7 = bytes.fromhex('65626D61726168')[::-1].decode('utf-8')
v8 = ':\"AL_RT^L*.?+6/46'
flag = ''
for i in range(0, len(v8)):
    flag += chr(ord(v7[i%v6])^ord(v8[i]))
print(flag)