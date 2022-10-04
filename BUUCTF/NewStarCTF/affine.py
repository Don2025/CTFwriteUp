from Crypto.Util.number import *

tmp_flag = 'flag{'
tmp_s = b'\xb1\x83\x82T\x10\x80'
for i in range(3, 257):
    for j in range(3, 257):
        cipher_text = []
        for f in tmp_flag:
            cipher_text.append((i*ord(f)+j)%0x100)
        if bytes(cipher_text) in tmp_s:
            a, b = i, j
            print('a={}, b={}'.format(a, b))

s = b"\xb1\x83\x82T\x10\x80\xc9O\x84\xc9<\x0f\xf2\x82\x9a\xc9\x9b8'\x9b<\xdb\x9b\x9b\x82\xc8\xe0V"
flag = ''
cipher_text = list(s)
for f in cipher_text:
    n1 = inverse(a, 256)
    n2 = n1*b%256
    flag += chr((n1*f-n2)%256)
    
print(flag) # flag{Kn0wn_p1aint3xt_4ttack}