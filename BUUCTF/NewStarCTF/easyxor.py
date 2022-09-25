s = bytes.fromhex('9b919c9a8685cd8fa294c8a28c88cc89cea2ce9c878480') #  b'\x9b\x91\x9c\x9a\x86\x85\xcd\x8f\xa2\x94\xc8\xa2\x8c\x88\xcc\x89\xce\xa2\xce\x9c\x87\x84\x80'
key = 253 # b'\xfd'
l = []
for i in range(len(s)):
    l.append(s[i]^253)
flag = bytes(l).decode()
print(flag) # flag{x0r_i5_qu1t3_3azy}