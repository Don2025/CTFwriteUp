key = [180, 136, 137, 147, 191, 137, 147, 191, 148, 136, 133, 191, 134, 140, 129, 135, 191, 65]
flag = ''
for i in range(len(key)):
    flag += chr(key[i]-ord('@')^0x20)
print(f"flag{{{flag}}}") # flag{This_is_the_flag_!}