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
        '-...-': '=', '.----.': '\'', '-..-.': '/', '-.-.--': '!', '-....-': '-',
        '..--.-': '_', '.-..-.': '\'', '-.--.': '(', '-.--.-': ')', '...-..-': '$',
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

### [不仅仅是Morse](https://adworld.xctf.org.cn/task/answer?type=crypto&number=5&grade=0&id=5117)

打开`.txt`文件可以看到以下信息：

```
--/.-/-.--/..--.-/-..././..--.-/..../.-/...-/./..--.-/.-/-./---/-/...././.-./..--.-/-.././-.-./---/-.././..../..../..../..../.-/.-/.-/.-/.-/-.../.-/.-/-.../-.../-.../.-/.-/-.../-.../.-/.-/.-/.-/.-/.-/.-/.-/-.../.-/.-/-.../.-/-.../.-/.-/.-/.-/.-/.-/.-/-.../-.../.-/-.../.-/.-/.-/-.../-.../.-/.-/.-/-.../-.../.-/.-/-.../.-/.-/.-/.-/-.../.-/-.../.-/.-/-.../.-/.-/.-/-.../-.../.-/-.../.-/.-/.-/-.../.-/.-/.-/-.../.-/.-/-.../.-/-.../-.../.-/.-/-.../-.../-.../.-/-.../.-/.-/.-/-.../.-/-.../.-/-.../-.../.-/.-/.-/-.../-.../.-/-.../.-/.-/.-/-.../.-/.-/-.../.-/.-/-.../.-/.-/.-/.-/-.../-.../.-/-.../-.../.-/.-/-.../-.../.-/.-/-.../.-/.-/-.../.-/.-/.-/-.../.-/.-/-.../.-/.-/-.../.-/.-/-.../.-/-.../.-/.-/-.../-.../.-/-.../.-/.-/.-/.-/-.../-.../.-/-.../.-/.-/-.../-.../.-
```

编写`Python`代码进行摩斯电码解码后可以得到以下字符串：

```
MAY_BE_HAVE_ANOTHER_DECODEHHHHAAAAABAABBBAABBAAAAAAAABAABABAAAAAAABBABAAABBAAABBAABAAAABABAABAAABBABAAABAAABAABABBAABBBABAAABABABBAAABBABAAABAABAABAAAABBABBAABBAABAABAAABAABAABAABABAABBABAAAABBABAABBA
```

其中那一串A和B组成的子字符串显然是经过培根密码加密得到的，编写`Python`代码进行培根电码解码即可得到`cyberpeace{attackanddefenceworldisinteresting}`。

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
        '-...-': '=', '.----.': '\'', '-..-.': '/', '-.-.--': '!', '-....-': '-',
        '..--.-': '_', '.-..-.': '\'', '-.--.': '(', '-.--.-': ')', '...-..-': '$',
        #'....': '&', 
        '.--.-.': '@', '.-.-.': '+',
    }
    plaintext = ''
    for code in ciphertext.replace(dot,'.').replace(dash,'-').split(sign):
        plaintext += MorseList[code]
    return plaintext

def decryptBacon(ciphertext:str) -> str:
    '''
    ciphertext => 密文
    plaintext => 明文
    '''
    BaconList = {  # 培根字典
        'aaaaa': 'a', 'aaaab': 'b', 'aaaba': 'c', 'aaabb': 'd', 'aabaa': 'e', 'aabab': 'f', 'aabba': 'g',
        'aabbb': 'h', 'abaaa': 'i', 'abaab': 'j', 'ababa': 'k', 'ababb': 'l', 'abbaa': 'm', 'abbab': 'n',
        'abbba': 'o', 'abbbb': 'p', 'baaaa': 'q', 'baaab': 'r', 'baaba': 's', 'baabb': 't', 'babaa': 'u',
        'babab': 'v', 'babba': 'w', 'babbb': 'x', 'bbaaa': 'y', 'bbaab': 'z'
    }
    ciphertext = ciphertext.lower()
    l = [ciphertext[i:i+5] for i in range(0, len(ciphertext), 5)]
    plaintext = ''
    for word in l:
        if word in BaconList.keys():
            plaintext += BaconList[word]
    return plaintext

if __name__ == '__main__':
    text = '--/.-/-.--/..--.-/-..././..--.-/..../.-/...-/./..--.-/.-/-./---/-/...././.-./..--.-/-.././-.-./---/-.././..../..../..../..../.-/.-/.-/.-/.-/-.../.-/.-/-.../-.../-.../.-/.-/-.../-.../.-/.-/.-/.-/.-/.-/.-/.-/-.../.-/.-/-.../.-/-.../.-/.-/.-/.-/.-/.-/.-/-.../-.../.-/-.../.-/.-/.-/-.../-.../.-/.-/.-/-.../-.../.-/.-/-.../.-/.-/.-/.-/-.../.-/-.../.-/.-/-.../.-/.-/.-/-.../-.../.-/-.../.-/.-/.-/-.../.-/.-/.-/-.../.-/.-/-.../.-/-.../-.../.-/.-/-.../-.../-.../.-/-.../.-/.-/.-/-.../.-/-.../.-/-.../-.../.-/.-/.-/-.../-.../.-/-.../.-/.-/.-/-.../.-/.-/-.../.-/.-/-.../.-/.-/.-/.-/-.../-.../.-/-.../-.../.-/.-/-.../-.../.-/.-/-.../.-/.-/-.../.-/.-/.-/-.../.-/.-/-.../.-/.-/-.../.-/.-/-.../.-/-.../.-/.-/-.../-.../.-/-.../.-/.-/.-/.-/-.../-.../.-/-.../.-/.-/-.../-.../.-'
    flag = 'cyberpeace{' + decryptBacon(morse(text, '.', '-', '/')[30:]) + '}'
    print(flag) # cyberpeace{attackanddefenceworldisinteresting}
```

------

### [混合编码](https://adworld.xctf.org.cn/task/answer?type=crypto&number=5&grade=0&id=5118)

打开`.txt`文件可以看到以下信息：

```
JiM3NjsmIzEyMjsmIzY5OyYjMTIwOyYjNzk7JiM4MzsmIzU2OyYjMTIwOyYjNzc7JiM2ODsmIzY5OyYjMTE4OyYjNzc7JiM4NDsmIzY1OyYjNTI7JiM3NjsmIzEyMjsmIzEwNzsmIzUzOyYjNzY7JiMxMjI7JiM2OTsmIzEyMDsmIzc3OyYjODM7JiM1NjsmIzEyMDsmIzc3OyYjNjg7JiMxMDc7JiMxMTg7JiM3NzsmIzg0OyYjNjU7JiMxMjA7JiM3NjsmIzEyMjsmIzY5OyYjMTIwOyYjNzg7JiMxMDU7JiM1NjsmIzEyMDsmIzc3OyYjODQ7JiM2OTsmIzExODsmIzc5OyYjODQ7JiM5OTsmIzExODsmIzc3OyYjODQ7JiM2OTsmIzUwOyYjNzY7JiMxMjI7JiM2OTsmIzEyMDsmIzc4OyYjMTA1OyYjNTY7JiM1MzsmIzc4OyYjMTIxOyYjNTY7JiM1MzsmIzc5OyYjODM7JiM1NjsmIzEyMDsmIzc3OyYjNjg7JiM5OTsmIzExODsmIzc5OyYjODQ7JiM5OTsmIzExODsmIzc3OyYjODQ7JiM2OTsmIzExOTsmIzc2OyYjMTIyOyYjNjk7JiMxMTk7JiM3NzsmIzY3OyYjNTY7JiMxMjA7JiM3NzsmIzY4OyYjNjU7JiMxMTg7JiM3NzsmIzg0OyYjNjU7JiMxMjA7JiM3NjsmIzEyMjsmIzY5OyYjMTE5OyYjNzc7JiMxMDU7JiM1NjsmIzEyMDsmIzc3OyYjNjg7JiM2OTsmIzExODsmIzc3OyYjODQ7JiM2OTsmIzExOTsmIzc2OyYjMTIyOyYjMTA3OyYjNTM7JiM3NjsmIzEyMjsmIzY5OyYjMTE5OyYjNzc7JiM4MzsmIzU2OyYjMTIwOyYjNzc7JiM4NDsmIzEwNzsmIzExODsmIzc3OyYjODQ7JiM2OTsmIzEyMDsmIzc2OyYjMTIyOyYjNjk7JiMxMjA7JiM3ODsmIzY3OyYjNTY7JiMxMjA7JiM3NzsmIzY4OyYjMTAzOyYjMTE4OyYjNzc7JiM4NDsmIzY1OyYjMTE5Ow==
```

编写`Python`代码进行`base64`解码后可以得到以下字符串：

```
&#76;&#122;&#69;&#120;&#79;&#83;&#56;&#120;&#77;&#68;&#69;&#118;&#77;&#84;&#65;&#52;&#76;&#122;&#107;&#53;&#76;&#122;&#69;&#120;&#77;&#83;&#56;&#120;&#77;&#68;&#107;&#118;&#77;&#84;&#65;&#120;&#76;&#122;&#69;&#120;&#78;&#105;&#56;&#120;&#77;&#84;&#69;&#118;&#79;&#84;&#99;&#118;&#77;&#84;&#69;&#50;&#76;&#122;&#69;&#120;&#78;&#105;&#56;&#53;&#78;&#121;&#56;&#53;&#79;&#83;&#56;&#120;&#77;&#68;&#99;&#118;&#79;&#84;&#99;&#118;&#77;&#84;&#69;&#119;&#76;&#122;&#69;&#119;&#77;&#67;&#56;&#120;&#77;&#68;&#65;&#118;&#77;&#84;&#65;&#120;&#76;&#122;&#69;&#119;&#77;&#105;&#56;&#120;&#77;&#68;&#69;&#118;&#77;&#84;&#69;&#119;&#76;&#122;&#107;&#53;&#76;&#122;&#69;&#119;&#77;&#83;&#56;&#120;&#77;&#84;&#107;&#118;&#77;&#84;&#69;&#120;&#76;&#122;&#69;&#120;&#78;&#67;&#56;&#120;&#77;&#68;&#103;&#118;&#77;&#84;&#65;&#119;
```

盲猜是`Unicode`编码，将字符串进行分割后进行`ASCII`码编码可以得到以下字符串：

```
LzExOS8xMDEvMTA4Lzk5LzExMS8xMDkvMTAxLzExNi8xMTEvOTcvMTE2LzExNi85Ny85OS8xMDcvOTcvMTEwLzEwMC8xMDAvMTAxLzEwMi8xMDEvMTEwLzk5LzEwMS8xMTkvMTExLzExNC8xMDgvMTAw
```

再次进行`base64`解码后可以得到以下字符串：

```
/119/101/108/99/111/109/101/116/111/97/116/116/97/99/107/97/110/100/100/101/102/101/110/99/101/119/111/114/108/100
```

盲猜是`ASCII`码，将字符串进行分割后进行`ASCII`码编码可以得到字符串：`welcometoattackanddefenceworld`。

根据题目描述的格式`cyberpeace{小写的你解出的答案}`，可以得到最终的`flag`：`cyberpeace{welcometoattackanddefenceworld}`。

```python
import base64

flag = base64.b64decode('JiM3NjsmIzEyMjsmIzY5OyYjMTIwOyYjNzk7JiM4MzsmIzU2OyYjMTIwOyYjNzc7JiM2ODsmIzY5OyYjMTE4OyYjNzc7JiM4NDsmIzY1OyYjNTI7JiM3NjsmIzEyMjsmIzEwNzsmIzUzOyYjNzY7JiMxMjI7JiM2OTsmIzEyMDsmIzc3OyYjODM7JiM1NjsmIzEyMDsmIzc3OyYjNjg7JiMxMDc7JiMxMTg7JiM3NzsmIzg0OyYjNjU7JiMxMjA7JiM3NjsmIzEyMjsmIzY5OyYjMTIwOyYjNzg7JiMxMDU7JiM1NjsmIzEyMDsmIzc3OyYjODQ7JiM2OTsmIzExODsmIzc5OyYjODQ7JiM5OTsmIzExODsmIzc3OyYjODQ7JiM2OTsmIzUwOyYjNzY7JiMxMjI7JiM2OTsmIzEyMDsmIzc4OyYjMTA1OyYjNTY7JiM1MzsmIzc4OyYjMTIxOyYjNTY7JiM1MzsmIzc5OyYjODM7JiM1NjsmIzEyMDsmIzc3OyYjNjg7JiM5OTsmIzExODsmIzc5OyYjODQ7JiM5OTsmIzExODsmIzc3OyYjODQ7JiM2OTsmIzExOTsmIzc2OyYjMTIyOyYjNjk7JiMxMTk7JiM3NzsmIzY3OyYjNTY7JiMxMjA7JiM3NzsmIzY4OyYjNjU7JiMxMTg7JiM3NzsmIzg0OyYjNjU7JiMxMjA7JiM3NjsmIzEyMjsmIzY5OyYjMTE5OyYjNzc7JiMxMDU7JiM1NjsmIzEyMDsmIzc3OyYjNjg7JiM2OTsmIzExODsmIzc3OyYjODQ7JiM2OTsmIzExOTsmIzc2OyYjMTIyOyYjMTA3OyYjNTM7JiM3NjsmIzEyMjsmIzY5OyYjMTE5OyYjNzc7JiM4MzsmIzU2OyYjMTIwOyYjNzc7JiM4NDsmIzEwNzsmIzExODsmIzc3OyYjODQ7JiM2OTsmIzEyMDsmIzc2OyYjMTIyOyYjNjk7JiMxMjA7JiM3ODsmIzY3OyYjNTY7JiMxMjA7JiM3NzsmIzY4OyYjMTAzOyYjMTE4OyYjNzc7JiM4NDsmIzY1OyYjMTE5Ow==').decode('utf-8')
# &#76;&#122;&#69;&#120;&#79;&#83;&#56;&#120;&#77;&#68;&#69;&#118;&#77;&#84;&#65;&#52;&#76;&#122;&#107;&#53;&#76;&#122;&#69;&#120;&#77;&#83;&#56;&#120;&#77;&#68;&#107;&#118;&#77;&#84;&#65;&#120;&#76;&#122;&#69;&#120;&#78;&#105;&#56;&#120;&#77;&#84;&#69;&#118;&#79;&#84;&#99;&#118;&#77;&#84;&#69;&#50;&#76;&#122;&#69;&#120;&#78;&#105;&#56;&#53;&#78;&#121;&#56;&#53;&#79;&#83;&#56;&#120;&#77;&#68;&#99;&#118;&#79;&#84;&#99;&#118;&#77;&#84;&#69;&#119;&#76;&#122;&#69;&#119;&#77;&#67;&#56;&#120;&#77;&#68;&#65;&#118;&#77;&#84;&#65;&#120;&#76;&#122;&#69;&#119;&#77;&#105;&#56;&#120;&#77;&#68;&#69;&#118;&#77;&#84;&#69;&#119;&#76;&#122;&#107;&#53;&#76;&#122;&#69;&#119;&#77;&#83;&#56;&#120;&#77;&#84;&#107;&#118;&#77;&#84;&#69;&#120;&#76;&#122;&#69;&#120;&#78;&#67;&#56;&#120;&#77;&#68;&#103;&#118;&#77;&#84;&#65;&#119;
flag = ''.join(chr(x) for x in list(map(int, flag[2:-1].split(';&#'))))
# LzExOS8xMDEvMTA4Lzk5LzExMS8xMDkvMTAxLzExNi8xMTEvOTcvMTE2LzExNi85Ny85OS8xMDcvOTcvMTEwLzEwMC8xMDAvMTAxLzEwMi8xMDEvMTEwLzk5LzEwMS8xMTkvMTExLzExNC8xMDgvMTAw
flag = base64.b64decode(flag).decode('utf-8')
# /119/101/108/99/111/109/101/116/111/97/116/116/97/99/107/97/110/100/100/101/102/101/110/99/101/119/111/114/108/100
flag = ''.join(chr(x) for x in list(map(int, flag[1:].split('/'))))
flag = 'cyberpeace{' + flag + '}'
print(flag) # cyberpeace{welcometoattackanddefenceworld}
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

### [easychallenge](https://adworld.xctf.org.cn/task/answer?type=crypto&number=5&grade=0&id=5119)

这道题的附件是一个`.pyc`文件，`.pyc`是一种二进制文件，是由`.py`文件经过编译后生成的文件，是一种`byte code`，`.py`文件变成`.pyc`文件后，运行加载的速度会有所提高，并且可以实现部分的源码隐藏，保证了`Python`做商业化软件时的安全性。

我们可以使用[**python-uncompyle6**](https://github.com/rocky/python-uncompyle6)来对`.pyc`文件进行反编译从而得到`.py`文件。

```bash
pip install uncompyle6
uncompyle6 -o . main.pyc
```

打开反编译得到的`.py`文件可以看到以下`Python2.x`版本的源码：

```python
# uncompyle6 version 3.7.4
# Python bytecode 2.7 (62211)
# Decompiled from: Python 3.8.8 (default, Apr 13 2021, 15:08:03) [MSC v.1916 64 bit (AMD64)]
# Embedded file name: ans.py
# Compiled at: 2018-08-09 11:29:44
import base64

def encode1(ans):
    s = ''
    for i in ans:
        x = ord(i) ^ 36
        x = x + 25
        s += chr(x)
    return s

def encode2(ans):
    s = ''
    for i in ans:
        x = ord(i) + 36
        x = x ^ 36
        s += chr(x)
    return s

def encode3(ans):
    return base64.b32encode(ans)

flag = ' '
print 'Please Input your flag:'
flag = raw_input()
final = 'UC7KOWVXWVNKNIC2XCXKHKK2W5NLBKNOUOSK3LNNVWW3E==='
if encode3(encode2(encode1(flag))) == final:
    print 'correct'
else:
    print 'wrong'
```

要得到原始`flag`的话，首先进入函数的顺序改成先`decode3`再`decode2`最后`decode1`，然后每个函数内部运算，`+`变`-`，`-`变`+`，异或运算的逆过程就是再做一次异或，`base64.b32encode()`改成`base64.b32decode()`，需要注意的是`base64.b32decode()`后不能使用`decode('utf-8')`来解码会报错，应该使用`decode('ISO-8859-1')`。运行`Python`代码即可得到`cyberpeace{interestinghhhhh}`。

```python
import base64 # 需要注意的是之前那题base64的脚本文件我命名为了base64.py 所以这里会报错 把那题的文件改成Base64.py即可

def decode1(ans):
    s = ''
    for i in ans:
        x = ord(i) - 25
        x = x ^ 36
        s += chr(x)
    return s

def decode2(ans):
    s = ''
    for i in ans:
        x = ord(i) ^ 36
        x = x - 36
        s += chr(x)
    return s

def decode3(ans):
    return base64.b32decode(ans)

final = 'UC7KOWVXWVNKNIC2XCXKHKK2W5NLBKNOUOSK3LNNVWW3E==='
flag = decode1(decode2(decode3(final).decode('ISO-8859-1')))
print(flag) # cyberpeace{interestinghhhhh}
```

------

### [转轮机加密](https://adworld.xctf.org.cn/task/answer?type=crypto&number=5&grade=0&id=5113)

打开`.txt`文件后，提取有用的信息，编写`Python`代码即可得到`flag`：`fireinthehole`。

```python
code = ['ZWAXJGDLUBVIQHKYPNTCRMOSFE', 'KPBELNACZDTRXMJQOYHGVSFUWI',
    'BDMAIZVRNSJUWFHTEQGYXPLOCK', 'RPLNDVHGFCUKTEBSXQYIZMJWAO',
    'IHFRLABEUOTSGJVDKCPMNZQWXY', 'AMKGHIWPNYCJBFZDRUSLOQXVET',
    'GWTHSPYBXIZULVKMRAFDCEONJQ', 'NOZUTWDCVRJLXKISEFAPMYGHBQ',
    'XPLTDSRFHENYVUBMCQWAOIKZGJ', 'UDNAJFBOWTGVRSCZQKELMXYIHP',
    'MNBVCXZQWERTPOIUYALSKDJFHG', 'LVNCMXZPQOWEIURYTASBKJDFHG',
    'JZQAWSXCDERFVBGTYHNUMKILOP'
]
ciphertext = 'NFQKSEVOQOFNP'
cipher = '2,3,7,5,13,12,9,1,8,10,4,11,6'.split(',')
cnt = 0
print("解密后为：")
for i in cipher:
    index=code[int(i)-1].index(ciphertext[cnt])
    cnt += 1
    code[int(i)-1]=code[int(i)-1][index:]+code[int(i)-1][:index]
    print(code[int(i)-1])
print('每一列为：')
for i in range(len(code[0])):
      s = ''
      print("第{}列的是:".format(i+1),end="")
      for j in cipher:
          s += code[int(j)-1][i]
      print(s.lower())
flag = 'fireinthehole' # 二战时期
print(flag)
```

------

### [Normal_RSA](https://adworld.xctf.org.cn/task/answer?type=crypto&number=5&grade=0&id=5115)

附件给出了`flag.enc`和`pubkey.pem`两个文件。用`Kali Linux`打开终端输入`openssl`。输入以下代码查看信息：

```bash
rsa -pubin -text -modulus -in warmup -in pubkey.pem
```

![](https://paper.tanyaodan.com/ADWorld/crypto/5115/1.png)

其中`Exponent`指的是`RSA`中的`e`，`Modulus`指的是`N`，即p和q的乘积，因式分解后可以得到：

```python
p = 275127860351348928173285174381581152299
q = 319576316814478949870590164193048041239
e = 65537
```

使用 [rsatool.py](https://github.com/ius/rsatool) 这个工具来通过`p`、`q`、`e`计算`d`，并生成`.pem`文件。

![](https://paper.tanyaodan.com/ADWorld/crypto/5115/2.png)

输入以下命令即可得到`PCTF{256b_i5_m3dium}`。

```bash
python rsatool.py -f PEM -o private.pem -p 275127860351348928173285174381581152299 -q 319576316814478949870590164193048041239 -e 65537
```

![](https://paper.tanyaodan.com/ADWorld/crypto/5115/3.png)

------

### [Broadcast](https://adworld.xctf.org.cn/task/answer?type=crypto&number=5&grade=1&id=5522)

这题的附件给出了一系列的文件：

![](https://paper.tanyaodan.com/ADWorld/crypto/5522/1.png)

用`Sublime Text`打开`task.py`查看源代码如下：

```python
#!/usr/bin/env python3
from Crypto.Util import number
from Crypto.PublicKey import RSA
from hashlib import sha256
import json

#from secret import msg
msg = 'Hahaha, Hastad\'s method don\'t work on this. Flag is flag{fa0f8335-ae80-448e-a329-6fb69048aae4}.'
assert len(msg) == 95

Usernames = ['Alice', 'Bob', 'Carol', 'Dan', 'Erin']
N = [ ( number.getPrime(1024) * number.getPrime(1024) ) for _ in range(4) ]
PKs = [ RSA.construct( (N[0], 3) ), RSA.construct( (N[1], 3) ), RSA.construct( (N[2], 5) ), RSA.construct( (N[3], 5) ) ]

for i in range(4):
    name = Usernames[i+1]
    open(name+'Public.pem', 'wb').write( PKs[i].exportKey('PEM') )
    data = {'from': sha256( b'Alice' ).hexdigest(),
            'to'  : sha256( name.encode() ).hexdigest(),
            'msg' : msg
            }
    data = json.dumps(data, sort_keys=True)
    m = number.bytes_to_long( data.encode() )
    cipher = pow(m, PKs[i].e, PKs[i].n)
    open(name+'Cipher.enc', 'wb').write( number.long_to_bytes(cipher) )
```

好家伙，真的像题目描述所述的那样明文存储，提交`flag{fa0f8335-ae80-448e-a329-6fb69048aae4}`即可。

------

### 	 [cr3-what-is-this-encryption](https://adworld.xctf.org.cn/task/answer?type=crypto&number=5&grade=1&id=5029)

题目描述给出了以下信息：

```
p=0xa6055ec186de51800ddd6fcbf0192384ff42d707a55f57af4fcfb0d1dc7bd97055e8275cd4b78ec63c5d592f567c66393a061324aa2e6a8d8fc2a910cbee1ed9 q=0xfa0f9463ea0a93b929c099320d31c277e0b0dbc65b189ed76124f5a1218f5d91fd0102a4c8de11f28be5e4d0ae91ab319f4537e97ed74bc663e972a4a9119307 e=0x6d1fdab4ce3217b3fc32c9ed480a31d067fd57d93a9ab52b472dc393ab7852fbcb11abbebfd6aaae8032db1316dc22d3f7c3d631e24df13ef23d3b381a1c3e04abcc745d402ee3a031ac2718fae63b240837b4f657f29ca4702da9af22a3a019d68904a969ddb01bcf941df70af042f4fae5cbeb9c2151b324f387e525094c41 c=0x7fe1a4f743675d1987d25d38111fae0f78bbea6852cba5beda47db76d119a3efe24cb04b9449f53becd43b0b46e269826a983f832abb53b7a7e24a43ad15378344ed5c20f51e268186d24c76050c1e73647523bd5f91d9b6ad3e86bbf9126588b1dee21e6997372e36c3e74284734748891829665086e0dc523ed23c386bb520
```

编写`Python`代码即可得到`ALEXCTF{RS4_I5_E55ENT1AL_T0_D0_BY_H4ND}`。

```python
from gmpy2 import *
from Crypto.Util.number import long_to_bytes

p = mpz(0xa6055ec186de51800ddd6fcbf0192384ff42d707a55f57af4fcfb0d1dc7bd97055e8275cd4b78ec63c5d592f567c66393a061324aa2e6a8d8fc2a910cbee1ed9)
q = mpz(0xfa0f9463ea0a93b929c099320d31c277e0b0dbc65b189ed76124f5a1218f5d91fd0102a4c8de11f28be5e4d0ae91ab319f4537e97ed74bc663e972a4a9119307)
e = mpz(0x6d1fdab4ce3217b3fc32c9ed480a31d067fd57d93a9ab52b472dc393ab7852fbcb11abbebfd6aaae8032db1316dc22d3f7c3d631e24df13ef23d3b381a1c3e04abcc745d402ee3a031ac2718fae63b240837b4f657f29ca4702da9af22a3a019d68904a969ddb01bcf941df70af042f4fae5cbeb9c2151b324f387e525094c41)
phi_n = (p-1)*(q-1) 
d = invert(e, phi_n)
c = mpz(0x7fe1a4f743675d1987d25d38111fae0f78bbea6852cba5beda47db76d119a3efe24cb04b9449f53becd43b0b46e269826a983f832abb53b7a7e24a43ad15378344ed5c20f51e268186d24c76050c1e73647523bd5f91d9b6ad3e86bbf9126588b1dee21e6997372e36c3e74284734748891829665086e0dc523ed23c386bb520)
n = p*q
m = pow(c, d, n) # 2128227823044560158221770077085626332217552832266712453155349316324457362201641068235664016509
flag = long_to_bytes(m)
print(flag) # ALEXCTF{RS4_I5_E55ENT1AL_T0_D0_BY_H4ND}
```

------

### [flag_in_your_hand1](https://adworld.xctf.org.cn/task/answer?type=crypto&number=5&grade=1&id=4869)

这题的附件给出了两个文件：`script-min.js`和`index.html`，代码审计时发现关键代码段：

```javascript
function ck(s) {
    try {
        ic
    } catch (e) {
        return;
    }
    var a = [118, 104, 102, 120, 117, 108, 119, 124, 48,123,101,120];
    if (s.length == a.length) {
        for (i = 0; i < s.length; i++) {
            if (a[i] - s.charCodeAt(i) != 3)
                return ic = false;
        }
        return ic = true;
    }
    return ic = false;
}
```

将传入函数的字符串`s`中的每个字符与数组`a`中的数字对比，只要相差`3`，就输出`true`。所以只要将`a`中的数字减`3`，换成`ASCII`字符，编写`Python`代码运行即可得到正确的字符串`security-xbu`。

```python
a = [118, 104, 102, 120, 117, 108, 119, 124, 48, 123, 101, 120]
flag = ''.join(chr(i-3) for i in a)
print(flag)
```

在`index.html`网页中输入`security-xbu`即可得到`flag`：`RenIbyd8Fgg5hawvQm7TDQ`。

![](https://paper.tanyaodan.com/ADWorld/crypto/4869/1.png)

------

### [flag_in_your_hand](https://adworld.xctf.org.cn/task/answer?type=crypto&number=5&grade=1&id=4626)

这题的附件给出了两个文件：`script-min.js`和`index.html`，代码审计时发现关键代码段：

```javascript
function ck(s) {
    try {
        ic
    } catch (e) {
        return;
    }
    var a = [118, 104, 102, 120, 117, 108, 119, 124, 48,123,101,120];
    if (s.length == a.length) {
        for (i = 0; i < s.length; i++) {
            if (a[i] - s.charCodeAt(i) != 3)
                return ic = false;
        }
        return ic = true;
    }
    return ic = false;
}
```

将传入函数的字符串`s`中的每个字符与数组`a`中的数字对比，只要相差`3`，就输出`true`。所以只要将`a`中的数字减`3`，换成`ASCII`字符，编写`Python`代码运行即可得到正确的字符串`security-xbu`。

```python
a = [118, 104, 102, 120, 117, 108, 119, 124, 48, 123, 101, 120]
flag = ''.join(chr(i-3) for i in a)
print(flag)
```

在`index.html`网页中输入`security-xbu`即可得到`flag`：`RenIbyd8Fgg5hawvQm7TDQ`。

![](https://paper.tanyaodan.com/ADWorld/crypto/4626/1.png)

------

### [告诉你个秘密](https://adworld.xctf.org.cn/task/answer?type=crypto&number=5&grade=1&id=4929)

打开`.txt`文件可以看到以下信息：

```
636A56355279427363446C4A49454A7154534230526D6843
56445A31614342354E326C4B4946467A5769426961453067
```

怀疑是`16`进制的`ASCII`码，编写`Python`代码解码后可以得到`cjV5RyBscDlJIEJqTSB0RmhCVDZ1aCB5N2lKIFFzWiBiaE0g`。

```python
s=bytes.fromhex('636A56355279427363446C4A49454A7154534230526D684356445A31614342354E326C4B4946467A5769426961453067')
```

将得到的字符串进行`base64`解码后得到`r5yG lp9I BjM tFhBT6uh y7iJ QsZ bhM`，注意我们是把俩个数字串一起解码的，其实这组字符串本来应该是`r5yG lp9I BjM tFhB T6uh y7iJ QsZ bhM`。

```python
s = base64.b64decode(s).decode('utf-8')
```

观察键盘可以发现每一组字母在键盘上围出一个字母，`r5yG => T`，`lp9I => O`，`BjM => N`，`tFhB => G`，`T6uh => Y`，`y7iJ => U`，`QsZ => A`，`bhM => N`，最终得到`flag`：`TONGYUAN`提交即可。

------

### [你猜猜](https://adworld.xctf.org.cn/task/answer?type=crypto&number=5&grade=1&id=4930)

打开`.txt`文件可以看到以下信息：

```
504B03040A0001080000626D0A49F4B5091F1E0000001200000008000000666C61672E7478746C9F170D35D0A45826A03E161FB96870EDDFC7C89A11862F9199B4CD78E7504B01023F000A0001080000626D0A49F4B5091F1E00000012000000080024000000000000002000000000000000666C61672E7478740A0020000000000001001800AF150210CAF2D1015CAEAA05CAF2D1015CAEAA05CAF2D101504B050600000000010001005A000000440000000000
```

`504B0304`是经典的`zip`文件开头，用`WinHex`新建文件然后将`.txt`中的数据拷贝进去，保存为`.zip`文件，这里我命名为了`a.zip`。解压`a.zip`时发现需要解压密码，使用`Ziperello`暴力破解可以得到解压密码`123456`。

![](https://paper.tanyaodan.com/ADWorld/crypto/4930/1.png)

输入`123456`解压缩文件后，打开`flag.txt`可以得到`daczcasdqwdcsdzasd`。

------

### [工业协议分析2](https://adworld.xctf.org.cn/task/answer?type=crypto&number=5&grade=1&id=5525)

用`wireshark`打开`.pcapng`文件，发现存在大量`UDP`流量包，大部分`UDP`流量包的长度相同，只有一些长度的`UDP`流量包仅出现过一次，猜测它们可能有异常。

![](https://paper.tanyaodan.com/ADWorld/crypto/5525/1.png)

将字符串`666c61677b37466f4d3253746b6865507a7d`进行16进制ASCII码解码即可得到`flag{7FoM2StkhePz}`。

```python
flag = bytes.fromhex('666c61677b37466f4d3253746b6865507a7d').decode('utf-8')
print(flag) # flag{7FoM2StkhePz}
```

------

