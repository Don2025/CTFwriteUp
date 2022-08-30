from gmpy2 import invert

n = pow(5,175)
p = 5390734306631855467986187436983737752151008395372308788862499432056740530367025683371238030400935613581745610066222336578420939008918998541409247659187704647583389480103444480
y = p // pow(2,175)
k = pow(2, 9825, n)
kinv = int(invert(k, n))
t = (y * kinv) % n
# t=int.from_bytes(str(s).encode(), byteorder='little')
flag = bytes.fromhex(hex(t)[2:])[::-1]
print(flag.decode()) # flag{NuM8eR_7HE0rY_1s_S0_Funny~}