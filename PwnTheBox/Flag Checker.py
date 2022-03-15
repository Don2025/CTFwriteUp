s = "08'5[Z'Y:H3?X2K3V)?D2G3?H,N6?G$R(G]"
flag = ''
for i in range(len(s)):
    t = ord(s[i]) + 32
    if 65 <= t <= 90:  # 'A'~'Z'
        flag += chr(256-101-t)
    elif 97 <= t <= 122:  # 'a'~'z'
        flag += chr(256-37-t)
    else:
        flag += chr(t)
print(flag)