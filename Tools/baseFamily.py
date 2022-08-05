import struct

def b16encode(s:str) -> str:
    import base64
    return base64.b16encode(s)

def b16decode(s:str) -> str:
    import base64
    return base64.b16decode(s)

def b32encode(s:str) -> str:
    '''
    Base32编码将二进制文件转换成32个ASCII字符"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"组成的文本。
    '''
    import base64
    return base64.b32encode(s)

def b32decode(s:str) -> str:
    import base64
    return base64.b32decode(s)

def b58encode(s:str) -> str:
    s = list(map(ord,s))
    l = s[0]
    base58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    for i in range(len(s)-1):
        l = l * 256 + s[i+1]
    s = []
    while True:
        s.insert(0,l % 58)
        l = l // 58
        if l == 0:
            break
    l = ""
    for i in s:
        l += base58[i]
    return l

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

def b62encode(num:int) -> str:
    if type(num) == str:
        print("失败")
    base62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    if num == 0:
        return base62[0]
    l = []
    base = len(base62)
    while num:
        num, rem = divmod(num, base)
        l.append(base62[rem])
    l.reverse()
    return ''.join(l)

def b62decode(s:str) -> int:
    base62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    base = len(base62)
    num = 0
    idx = 0
    for x in s:
        idx += 1
        power = len(s)-idx
        num += base62.index(x)*(base**power) 
    return num

def b64encode(s:str) -> str:
    '''
    Base64是一种基于64个可打印字符来表示二进制数据的表示方法。2⁶=64,因此每6bit为一个单元,对应某个可打印字符。
    3字节有24bit,对应4个Base64单元，即3字节任意二进制数据可由4个可打印字符表示。
    转换时,3字节的数据先后放入一个24位的缓冲区中,先来的字节占高位。数据不足3字节时缓存器中剩下的位用0补足。
    每次取出6bit按照"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"中的字符作为编码后的输出。
    若全部输入数据转换完成后,原数据长度不是3的倍数且剩1个输入数据则在编码结果后加'==',剩2个输入数据则在编码结果后加'='。
    当编码的字符长度正好是3的倍数时,编码后的字符串末尾不会出现等于号。
    '''
    import base64
    return base64.b64encode(s)

def b64decode(s:str) -> str:
    import base64
    return base64.b64decode(s)

def b85encode(s:str) -> str:
    import base64
    return base64.b85encode

def b85decode(s:str) -> str:
    import base64
    return base64.b85decode(s)

def b91encode(s:str) -> str:
    import struct
    base91 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%&()*+,./:;<=>?@[]^_`{|}~\""
    arr = bytearray(s.encode('utf-8'))
    b = 0
    n = 0
    ans = ''
    for i in range(len(arr)):
        byte = arr[i:i+1]
        b |= struct.unpack('B', byte)[0] << n
        n += 8
        if n > 13:
            v = b & 8191
            if v > 88:
                b >>= 13
                n -= 13
            else:
                v = b & 16383
                b >>= 14
                n -= 14
            ans += base91[v%91]+base91[v//91]
    if n:
        ans += base91[b%91]
        if n>7 or b>90:
            ans += base91[b//91]
    return ans
        
def b91decode(s:str) -> str:
    import struct
    base91 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%&()*+,./:;<=>?@[]^_`{|}~\""
    decode_table = dict((v,k) for k,v in enumerate(base91))
    v = -1
    b = 0
    n = 0
    ans = bytearray()
    for x in s:
        if not x in decode_table:
            continue
        c = decode_table[x]
        if v < 0:
            v = c
        else:
            v += c*91
            b |= v << n
            n += 13 if (v&8191)>88 else 14
            while True:
                ans += struct.pack('B', b&255)
                b >>= 8
                n -= 8
                if not n>7:
                    break
            v = -1
    if v+1:
        ans += struct.pack('B', (b|v<<n)&255)
    return ans.decode('utf-8')
'''
def b92encode(s:str) -> str:
    import math
    base92 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%&()*+,./:;<=>?@[]^_`{|}~\""
    if not s:
        return '~'
    bitstr = ''
    while len(bitstr)<13 and s:
        bitstr += '{:08b}'.format(ord(s[0]))
        s = s[1:]
    ans = ''
    while len(bitstr)>13 or s:
        i = int(bitstr[:13], 2)
        ans += 
'''
    


if __name__ == '__main__':

    print(b91decode('[D7gXmNBB22+?j*T6tdE'))
    