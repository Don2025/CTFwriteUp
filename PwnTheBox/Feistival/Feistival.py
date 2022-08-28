m, n = 21, 22
def f(word, key):
    out = ""
    for i in range(len(word)):
        out += chr(ord(word[i]) ^ key)
    return out

ct = open("cipher.txt", "r").read()
x, y = ct[0:len(ct)//2], ct[len(ct)//2:]
R = f(y, 0)
L = ''.join(chr(ord(f(R, n)[i]) ^ ord(x[i])) for i in range(len(x)))
y, x = L, R
R = f(y, 0)
L = ''.join(chr(ord(f(y, m)[i]) ^ ord(x[i])) for i in range(len(x)))
flag = L+R
print(flag) # KCTF{feistel_cipher_ftw}