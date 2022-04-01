from base64 import *

s = 'e3nifIH9b_C@n@dH'
flag = ''
for i in range(len(s)):
    flag += chr(ord(s[i])-i)
flag = b64decode(flag).decode('utf-8')
flag = 'flag' + flag
print(flag)