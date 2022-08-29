import base64
s = "Gx8EAA8SCBIfHQARCxMUHwsAHRwRHh8BEQwaFBQfGwMYCBYRHx4SBRQdGR8HAQ0QFQ=="
s = base64.b64decode(s)
print(s)
l = [bin(i).replace('0b', '').rjust(5, '0') for i in s]
flag = ''
for i in range(5):
    s = ''.join([x[i] for x in l])
    flag += ''.join([chr(int(s[i:i+7], 2)) for i in range(0, len(s), 7)])

print(flag) # bugku{ce26f61d40fea75fc0b980d7588e}