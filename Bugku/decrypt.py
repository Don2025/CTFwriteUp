import hashlib
from base64 import b64decode

key = hashlib.md5(b'ISCC').hexdigest()
base64str = 'fR4aHWwuFCYYVydFRxMqHhhCKBseH1dbFygrRxIWJ1UYFhotFjA='
data = b64decode(base64str)
x = 0
char = ''
for i in range(len(data)):
    if x == len(key):
        x = 0
    char += key[x]
    x += 1
flag = ''
for i in range(len(data)):
    flag += chr((data[i]-ord(char[i])+128)%128)
print(flag)  # Flag:{asdqwdfasfdawfefqwdqwdadwqadawd}