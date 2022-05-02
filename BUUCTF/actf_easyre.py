key = chr(0x7E)+'}|{zyxwvutsrqponmlkjihgfedcba`_^]\[ZYXWVUTSRQPONMLKJIHGFEDCBA@?>=<;:9876543210/.-,+*)('+chr(0x27)+'&%$# !"'
encrypt = [42, 70, 39, 34, 78, 44, 34, 40, 73, 63, 43, 64]
flag = ''.join([chr(key.find(chr(x))+1) for x in encrypt])
print(f"flag{{{flag}}}") # flag{U9X_1S_W6@T?} 