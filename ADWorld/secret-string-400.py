nonce = 'groke'
ex = [1, 30, 14, 12, 69, 14, 1, 85, 75, 50, 40, 37, 48, 24, 10, 56, 55, 46, 56, 60]
flag = ''
for i in range(len(ex)):
    flag += chr(ex[i]^ord(nonce[i%5]))
print(flag)  # flag is: WOW_so_EASY