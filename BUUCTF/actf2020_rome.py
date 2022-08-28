import string

l = [81,115,119,51,115,106,95,108,122,52,95,85,106,119,64,108]
s1 = string.ascii_lowercase
s2 = string.ascii_uppercase
flag = ''
for i in l:
    if i > 64 and i <=90:
        flag += s2[i-14-65]
    elif i > 96 and i <= 122:
        flag += s1[i-18-97]
    else:
        flag += chr(i)

print(f'flag{{{flag}}}') # flag{Cae3ar_th4_Gre@t}