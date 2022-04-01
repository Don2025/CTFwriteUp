s = list('dd2940c04462b4dd7c450528835cca15')
s[2] = chr(ord(s[2])+ord(s[3])-50)
s[4] = chr(ord(s[2])+ord(s[5])-48)
s[30] = chr(ord(s[31])+ord(s[9])-48)
s[14] = chr(ord(s[27])+ord(s[28])-97)
for i in range(16):
    s[31-i], s[i] = s[i], s[31-i]
flag = 'flag{%s}'%''.join(s)
print(flag) # flag{59acc538825054c7de4b26440c0999dd}