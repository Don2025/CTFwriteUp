f1 = 'GXY{do_not_'
f2 = [0x69, 0x63, 0x75, 0x67, 0x60, 0x6F, 0x66, 0x7F]
flag = ''
for i in range(len(f2)):
    if i%2 == 1:
        flag += chr(f2[i]-2)
    else:
        flag += chr(f2[i]-1)
flag = f1 + flag
print(flag) # GXY{do_not_hate_me}