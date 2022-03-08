src = 'abcdefghiABCDEFGHIJKLMNjklmn0123456789opqrstuvwxyzOPQRSTUVWXYZ'
dst = 'KanXueCTF2019JustForhappy'
v5 = []
for x in dst:
    v5.append(src.index(x))
# v5 = [19, 0, 27, 59, 44, 4, 11, 55, 14, 30, 28, 29, 37, 18, 44, 42, 43, 14, 38, 41, 7, 0, 39, 39, 48]

flag = ''
for x in v5:
    t = chr(x+29)
    if 'A' <= t <= 'Z':
        flag += t
    t = chr(x+87)
    if 'a' <= t <= 'z':
        flag += t
    t = chr(x+48)
    if '0' <= t <= '9':
        flag += t
print(f'flag{{{flag}}}')