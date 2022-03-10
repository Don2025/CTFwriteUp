s = 'cbtcqLUBChERV[[Nh@_X^D]X_YPV[CJ'
flag = ''
for i in range(len(s)):
    flag += chr(ord(s[i])^0x37) 
print(flag)