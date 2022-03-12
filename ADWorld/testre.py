def b58decode(s:str) -> str:
    import binascii
    base58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    l = []
    for i in s:
        l.append(base58.index(i))
    s = l[0]
    for i in range(len(l)-1):
        s = s*58+l[i+1]
    return binascii.unhexlify(hex(s)[2:].encode("utf-8")).decode("UTF-8")

flag = b58decode('D9cS9N9iHjMLTdA8YSMRMp')
print(flag) # base58_is_boring