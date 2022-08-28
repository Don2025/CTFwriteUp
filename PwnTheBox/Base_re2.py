from base64 import b64decode

s = b64decode('Zm1jZH9kYGRqPms5ajxtPiUpICsidyIvKC8oeHglJipBGBoVElg=').decode()
flag = ''
for i in range(len(s)):
    flag += chr(ord(s[i])^i)

print(flag) # flag{afcb7a2f1c158286b48062cd885a9866}