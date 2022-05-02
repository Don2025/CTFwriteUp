import hashlib

passwd1 = '@DBApp'
for i in range(100000, 1000000):
    s = str(i) + passwd1
    #s = str(i)+passwd
    x = hashlib.sha1(s.encode())
    t = x.hexdigest()
    if "6e32d0943418c2c33385bc35a1470250dd8923a9" == t:
        passwd1 = str(i) + passwd1
        break
print(passwd1) # 123321@DBApp

a = [0x05, 0x7D, 0x41, 0x15, 0x26, 0x01]
l = [0x7B, 0x5C, 0x72, 0x74, 0x66, 0x31]
passwd2 = ''
for i in range(6):
    passwd2 += chr(a[i]^l[i])
print(passwd2) # ~!3a@0