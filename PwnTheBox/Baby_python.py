from base64 import *
s = b64decode('eYNzc2tjWV1gXFWPYGlTbQ==')
flag = ''
for i in s:
    flag += chr((i-16)^32)
print(flag) # ISCC{simple_pyc}