text = 'synt{uvfgbevpny_pvcure_vf_ihyarenoyr}' # 
flag = ''
for i in range(1, 27):
    s = ''
    for x in text:
        if x.isalpha():
            s += chr(ord('a')+(ord(x)-ord('a')+i)%26)
        else:
            s += x
    s = s.lower()
    if 'flag' in s:
        flag = s
        print('{}的移位是{}'.format(s, (ord(text[0])-ord(s[0]))%26))

print(flag) # flag{historical_cipher_is_vulnerable}