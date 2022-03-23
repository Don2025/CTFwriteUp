Letters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ{}_'
l = [5, 11, 0, 6, 26, 8, 28, 11, 14, 21, 4, 28, 5, 14, 13, 25, 24, 27]
flag = ''
for i in l:
    flag += Letters[i]
print(flag) # FLAG{I_LOVE_FONZY}