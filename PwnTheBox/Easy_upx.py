s = "cjfor~c=~?|v &ti"
flag = ''
for i in range(len(s)):
    flag += chr(ord(s[i])^(i+5))
print(flag)