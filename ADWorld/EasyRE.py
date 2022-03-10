s = 'xIrCj~<r|2tWsv3PtI' 
flag = ''
for i in range(len(s)):
    flag = chr((ord(s[i])^6)-1) + flag
data = [0x7F, 0x7A, 0x6E, 0x64, 0x6B, 0x61]
for i in range(len(data)):
    flag = chr((data[i]^6)-1) + flag
print(flag) # flag{xNqU4otPq3ys9wkDsN}