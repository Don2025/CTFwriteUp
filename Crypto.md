# Crypto

## ADWorld

### [base64](https://adworld.xctf.org.cn/task/answer?type=crypto&number=5&grade=0&id=5109)

打开`.txt`文件可以看到一行密文`Y3liZXJwZWFjZXtXZWxjb21lX3RvX25ld19Xb3JsZCF9`，编写`Python`代码进行`base64`解码即可得到`cyberpeace{Welcome_to_new_World!}`。

```python
from base64 import *

flag = b64decode('Y3liZXJwZWFjZXtXZWxjb21lX3RvX25ld19Xb3JsZCF9').decode('utf-8')
print(flag) # cyberpeace{Welcome_to_new_World!}
```

------

### [Caesar](https://adworld.xctf.org.cn/task/answer?type=crypto&number=5&grade=0&id=5110)

打开`.txt`文件可以看到一行密文`oknqdbqmoq{kag_tmhq_xqmdzqp_omqemd_qzodkbfuaz}`，盲猜凯撒密码，编写`Python`代码进行解码即可得到`cyberpeace{you_have_learned_caesar_encryption}`。

```python
text = 'oknqdbqmoq{kag_tmhq_xqmdzqp_omqemd_qzodkbfuaz}' # 凯撒密码
flag = ''
for i in range(1, 27):
    s = ''
    for x in text:
        if x.isalpha():
            s += chr(ord('a')+(ord(x)-i)%26)
        else:
            s += x
    s = s.lower()
    if 'cyberpeace' in s:
        flag = s
    print('{}的移位是{}'.format(s, (ord(text[0])-ord(s[0]))%26))

print(flag) # cyberpeace{you_have_learned_caesar_encryption}
```

------

### [Morse](https://adworld.xctf.org.cn/task/answer?type=crypto&number=5&grade=0&id=5111)

打开`.txt`文件可以看到一行密文`11 111 010 000 0 1010 111 100 0 00 000 000 111 00 10 1 0 010 0 000 1 00 10 110`，盲猜`0.1-`，编写`Python`代码进行`Morse`解码即可得到`cyberpeace{you_have_learned_caesar_encryption}`。这里写了一个`morse`电码解码模板，输入密文、点、划、分割符即可得到明文。

```python
def morse(ciphertext:str, dot:str, dash:str, sign:str) -> str:
    '''
    ciphertext => 密文
    dot => 点
    dash => 划
    sign => 分割符
    plaintext => 明文
    '''
    MorseList = {
        '.-': 'A', '-...': 'B', '-.-.': 'C', '-..': 'D', '.': 'E', '..-.': 'F', '--.': 'G',
        '....': 'H', '..': 'I', '.---': 'J', '-.-': 'K', '.-..': 'L', '--': 'M', '-.': 'N',
        '---': 'O', '.--．': 'P', '--.-': 'Q', '.-.': 'R', '...': 'S', '-': 'T',
        '..-': 'U', '...-': 'V', '.--': 'W', '-..-': 'X', '-.--': 'Y', '--..': 'Z',

        '-----': '0', '.----': '1', '..---': '2', '...--': '3', '....-': '4',
        '.....': '5', '-....': '6', '--...': '7', '---..': '8', '----.': '9',

        '.-.-.-': '.', '---...': ':', '--..--': ',', '-.-.-.': ';', '..--..': '?',
        '-...-': '=', '.----.': ''', '-..-.': '/', '-.-.--': '!', '-....-': '-',
        '..--.-': '_', '.-..-.': ''', '-.--.': '(', '-.--.-': ')', '...-..-': '$',
        '....': '&', '.--.-.': '@', '.-.-.': '+',
    }
    plaintext = ''
    for code in ciphertext.replace(dot,'.').replace(dash,'-').split(sign):
        plaintext += MorseList[code]
    return plaintext

if __name__ == '__main__':
    # Case 1: https://adworld.xctf.org.cn/task/answer?type=crypto&number=5&grade=0&id=5111
    text = '11 111 010 000 0 1010 111 100 0 00 000 000 111 00 10 1 0 010 0 000 1 00 10 110' # 0.1-
    flag = morse(text, '0', '1', ' ')  
    flag = 'cyberpeace{' + flag.lower() + '}'
    print(flag) # cyberpeace{morsecodeissointeresting}
```

------

### [幂数加密](https://adworld.xctf.org.cn/task/answer?type=crypto&number=5&grade=0&id=5120)

打开`.txt`文件可以看到一行密文`8842101220480224404014224202480122`。`01248`密码又称为云影密码，使用`0`，`1`，`2`，`4`，`8 `四个数字，其中`0`用来表示间隔，其他数字相加可以得到一个数字，再用`A->Z`来表示`1->26`。编写`Python`代码进行`01248`密码解码即可得到`cyberpeace{WELLDONE}`。

```python
word = '0ABCDEFGHIJKLMNOPQRSTUVWXYZ'  #01248密码
l = '8842101220480224404014224202480122'.split('0')
flag = ''
for s in l:
    n = 0
    for ch in s:
        n += int(ch)
    flag += word[n]
flag = 'cyberpeace{' + flag + '}'
print(flag) # cyberpeace{WELLDONE}
```

------

### [Railfence](https://adworld.xctf.org.cn/task/answer?type=crypto&number=5&grade=0&id=5112)

打开`.txt`文件可以看到一行密文`ccehgyaefnpeoobe{lcirg}epriec_ora_g`。这题是一个`w`型的栅栏密码，编写`Python`代码即可得到`cyberpeace{railfence_cipher_gogogo}`。

```python
def encryptRailFence(text, key):
    # create the matrix to cipher
    # plain text key = rows,
    # length(text) = columns
    # filling the rail matrix
    # to distinguish filled
    # spaces from blank ones
    rail = [['\n' for i in range(len(text))]
                  for j in range(key)]
    # to find the direction
    dir_down = False
    row, col = 0, 0
    for i in range(len(text)):
        # check the direction of flow
        # reverse the direction if we've just
        # filled the top or bottom rail
        if (row == 0) or (row == key - 1):
            dir_down = not dir_down
        # fill the corresponding alphabet
        rail[row][col] = text[i]
        col += 1
        # find the next row using
        # direction flag
        if dir_down:
            row += 1
        else:
            row -= 1
    # now we can construct the cipher
    # using the rail matrix
    result = []
    for i in range(key):
        for j in range(len(text)):
            if rail[i][j] != '\n':
                result.append(rail[i][j])
    return(''.join(result))
     
# This function receives cipher-text and key, then returns the original text after decryption
def decryptRailFence(cipher, key):
    # create the matrix to cipher
    rail = [['\n' for i in range(len(cipher))]
                  for j in range(key)]
    # to find the direction
    dir_down = None
    row, col = 0, 0
    # mark the places with '*'
    for i in range(len(cipher)):
        if row == 0:
            dir_down = True
        if row == key - 1:
            dir_down = False
        # place the marker
        rail[row][col] = '*'
        col += 1
        # find the next row
        # using direction flag
        if dir_down:
            row += 1
        else:
            row -= 1
    # now we can construct the
    # fill the rail matrix
    index = 0
    for i in range(key):
        for j in range(len(cipher)):
            if ((rail[i][j] == '*') and
               (index < len(cipher))):
                rail[i][j] = cipher[index]
                index += 1
    # now read the matrix in
    # zig-zag manner to construct
    # the resultant text
    result = []
    row, col = 0, 0
    for i in range(len(cipher)):
        # check the direction of flow
        if row == 0:
            dir_down = True
        if row == key-1:
            dir_down = False
        # place the marker
        if (rail[row][col] != '*'):
            result.append(rail[row][col])
            col += 1
        # find the next row using
        # direction flag
        if dir_down:
            row += 1
        else:
            row -= 1
    return(''.join(result))

if __name__ == '__main__':
    cipphertext = r'ccehgyaefnpeoobe{lcirg}epriec_ora_g'
    flag = ''
    for i in range(2, len(cipphertext)):
        plaintext = decryptRailFence(cipphertext, i)
        print('栏数为{}时明文为: {}'.format(i, plaintext))
        if 'cyberpeace' in plaintext:
            flag = plaintext
    flag = 'cyberpeace{' + flag + '}'
    print(flag) # cyberpeace{railfence_cipher_gogogo}
```

------

### [easy_RSA](https://adworld.xctf.org.cn/task/answer?type=crypto&number=5&grade=0&id=5114)

打开`.txt`文件可以看到以下内容：

> 在一次RSA密钥对生成中，假设p=473398607161，q=4511491，e=17，求解出d。

```python
from gmpy2 import *

p = mpz(473398607161)
q = mpz(4511491)
e = mpz(17)
phi_n = (p-1)*(q-1) 
d = invert(e, phi_n)
flag = 'cyberpeace{' + str(d) + '}'
print(flag)  # cyberpeace{125631357777427553}
```

------

