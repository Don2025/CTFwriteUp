cipher = 'pqcq{gteygpttmj_kc_zuokwv_kqb_gtofmssi_mnrrjt}'
s = 'flag{'
key = ''
for i in range(3):
    key += chr(ord('a') + ord(cipher[i])-ord(s[i]))
# key = 'kfc'
flag = ''
j = 0
for i, x in enumerate(cipher):
    if x.isalpha():
        flag += chr(ord('a') + (ord(x) - ord(key[j%len(key)]))%26)
        j += 1
    else:
        flag += x

print(flag) # flag{bruteforce_is_useful_for_breaking_cipher}