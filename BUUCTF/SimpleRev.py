import binascii

key = 'ADSFK'
key += binascii.a2b_hex(hex(0x534C43444E)[2:])[::-1].decode('utf-8')
text = 'kills'
text += binascii.a2b_hex(hex(0x776F646168)[2:])[::-1].decode('utf-8')
key = key.lower()
flag = ''
for i in range(len(text)):
    for j in range(128):
        if chr(j).isupper() and ord(text[i]) == (j-39-ord(key[i])+97)%26+97:
            flag += chr(j)
print(f"flag{{{flag}}}") # flag{KLDQCUDFZO}