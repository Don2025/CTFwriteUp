s = 'pvkq{m164675262033l4m49lnp7p9mnk28k75}'
flag = ''
for i in range(1,27): # 凯撒密码
    t = ''
    for c in s:
        if c.islower():
            t += chr(ord('a') + ((ord(c) - ord('a')) + i) % 26)
        elif c.isupper():
            t += chr(ord('A') + ((ord(c) - ord('A')) + i) % 26)
        else:
            t += c
    if "flag" in t:
        flag = t
        break
print(flag) # flag{c164675262033b4c49bdf7f9cda28a75}