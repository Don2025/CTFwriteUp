s = ['Dufhbmf', 'pG`imos', 'ewUglpt']
flag = ''
for i in range(12):
    flag += chr(ord(s[i%3][2*int(i/3)])-1)
print(flag)