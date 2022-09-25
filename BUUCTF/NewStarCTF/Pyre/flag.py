encode = 'REla{PSF!!fg}!Y_SN_1_0U'
table = [7, 8, 1, 2, 4, 5, 13, 16, 20, 21, 0, 3, 22, 19, 6, 12, 11, 18, 9, 10, 15, 14, 17]

# encode = enc(flag)
d = {}

def dec(input):
    tmp = ''
    for i in range(len(input)):
        d[table[i]] = encode[i]

dec(encode)
flag=''.join(d[i] for i in sorted(d))
print(flag) # flag{PYRE_1S_S0_FUN!!!}