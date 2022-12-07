# Crypto

[TOC]

------

## ADWorld

### base64

打开`.txt`文件可以看到一行密文`Y3liZXJwZWFjZXtXZWxjb21lX3RvX25ld19Xb3JsZCF9`，编写`Python`代码进行`base64`解码即可得到`cyberpeace{Welcome_to_new_World!}`。

```python
from base64 import *

flag = b64decode('Y3liZXJwZWFjZXtXZWxjb21lX3RvX25ld19Xb3JsZCF9').decode('utf-8')
print(flag) # cyberpeace{Welcome_to_new_World!}
```

------

### Caesar

打开`.txt`文件可以看到一行密文`oknqdbqmoq{kag_tmhq_xqmdzqp_omqemd_qzodkbfuaz}`，盲猜凯撒密码，编写`Python`代码进行解码即可得到`cyberpeace{you_have_learned_caesar_encryption}`。

```python
text = 'oknqdbqmoq{kag_tmhq_xqmdzqp_omqemd_qzodkbfuaz}' # 凯撒密码
flag = ''
for i in range(1, 27):
    s = ''
    for x in text:
        if x.isalpha():
            s += chr(ord('a')+(ord(x)-ord('a')+i)%26)
        else:
            s += x
    s = s.lower()
    if 'cyberpeace' in s:
        flag = s
    print('{}的移位是{}'.format(s, (ord(text[0])-ord(s[0]))%26))

print(flag) # cyberpeace{you_have_learned_caesar_encryption}
```

------

### Morse

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

### 幂数加密

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

### Railfence

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

### 不仅仅是Morse

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

### 混合编码

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

### easy_RSA

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

### easychallenge

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

### 转轮机加密

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

### Normal_RSA

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

### Broadcast

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

### 	 cr3-what-is-this-encryption

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

### flag_in_your_hand1

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

### flag_in_your_hand

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

### 告诉你个秘密

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

### 你猜猜

打开`.txt`文件可以看到以下信息：

```
504B03040A0001080000626D0A49F4B5091F1E0000001200000008000000666C61672E7478746C9F170D35D0A45826A03E161FB96870EDDFC7C89A11862F9199B4CD78E7504B01023F000A0001080000626D0A49F4B5091F1E00000012000000080024000000000000002000000000000000666C61672E7478740A0020000000000001001800AF150210CAF2D1015CAEAA05CAF2D1015CAEAA05CAF2D101504B050600000000010001005A000000440000000000
```

`504B0304`是经典的`zip`文件开头，用`WinHex`新建文件然后将`.txt`中的数据拷贝进去，保存为`.zip`文件，这里我命名为了`a.zip`。解压`a.zip`时发现需要解压密码，使用`Ziperello`暴力破解可以得到解压密码`123456`。

![](https://paper.tanyaodan.com/ADWorld/crypto/4930/1.png)

输入`123456`解压缩文件后，打开`flag.txt`可以得到`daczcasdqwdcsdzasd`。

------

### 工业协议分析2

用`wireshark`打开`.pcapng`文件，发现存在大量`UDP`流量包，大部分`UDP`流量包的长度相同，只有一些长度的`UDP`流量包仅出现过一次，猜测它们可能有异常。

![](https://paper.tanyaodan.com/ADWorld/crypto/5525/1.png)

将字符串`666c61677b37466f4d3253746b6865507a7d`进行16进制ASCII码解码即可得到`flag{7FoM2StkhePz}`。

```python
flag = bytes.fromhex('666c61677b37466f4d3253746b6865507a7d').decode('utf-8')
print(flag) # flag{7FoM2StkhePz}
```

------

### sherlock

打开`.txt`文件后发现文件中的字符有一些莫名奇妙的大写字符，观察后发现所有的大写字符都是字母`Z`，`E`，`R`，`O`，`N`，`E`组成的。

编写`Python`代码提取所有大写字母拼接，再把`ZERO`替换成`0`，`ONE`替换成`1`，即可得到`flag`：`BITSCTF{h1d3_1n_pl41n_5173}`。

```python
import re

with open('./sherlock.txt') as f:
    data = f.read()
s = ''
for x in data:
    if x.isupper():
        s += x
print(s)
s = s.replace('ZERO', '0').replace('ONE', '1')
print(s)
l = re.findall(r'.{8}', s)
flag = ''
for x in l:
	flag += chr(int(x, 2))
print(flag) # BITSCTF{h1d3_1n_pl41n_5173}
```

------

## PwnTheBox

### [Base32](https://ce.pwnthebox.com/challenges?type=3&id=686)

题目名字叫`Base32`，题目描述给出的信息如下：

```
MZWGCZ33HFRDMNZVMJSDKNZQGU4GMZBUGZ6Q
```

编写`Python`代码进行`base32`解密，程序直接抛出异常`"binascii.Error: Incorrect padding"`。

```python
import base64

flag = base64.b32decode('MZWGCZ33HFRDMNZVMJSDKNZQGU4GMZBUGZ6Q')
print(flag) # binascii.Error: Incorrect padding
```

在`Python`中`base64`模块遵循`RFC 3548`。`base32`编码是用`32`个字符表示`256`个`ASCII`字符，即每`5`个`ASCII`字符一组生成`8`个`Base`字符，不足`5`个的用`0`补充。因此`base32`字符串长度应该是`8`的倍数，`"MZWGCZ33HFRDMNZVMJSDKNZQGU4GMZBUGZ6Q"`是`36`个字符，将它末尾补上`4`个`=`，重新进行`base32`解码即可得到`flag{9b675bd57058fd46}`。

```python
import base64

s = 'MZWGCZ33HFRDMNZVMJSDKNZQGU4GMZBUGZ6Q'.ljust(40, '=')
flag = base64.b32decode(s).decode()
print(flag) # flag{9b675bd57058fd46}
```

------

### [easy_crypto](https://ce.pwnthebox.com/challenges?type=3&id=677)

题目描述非常简洁：

> 0010 0100 01 110 1111011 11 11111 010 000 0 001101 1010 111 100 0 001101 01111 000 001101 00 10 1 0 010 0 000 1 01111 10 11110 101011 1111101
>
> flag为小写

`0010`让人联想到`mose`电码的`..-.`代表字母`F`，编写`Python`代码进行摩斯电码解密得到`flag`，提交`flag{m0rse_code_1s_interest1n9!}`即可。

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
        '....': '&', '.--.-.': '@', '.-.-.': '+', '----.--': '{', '-----.-': '}'
    }
    plaintext = ''
    for code in ciphertext.replace(dot,'.').replace(dash,'-').split(sign):
        plaintext += MorseList[code]
    return plaintext

if __name__ == '__main__':
    # Case: https://ce.pwnthebox.com/challenges?type=3&id=677
    text = '0010 0100 01 110 1111011 11 11111 010 000 0 001101 1010 111 100 0 001101 01111 000 001101 00 10 1 0 010 0 000 1 01111 10 11110 101011 1111101' # 0.1-
    flag = morse(text, '0', '1', ' ').lower()
    print(flag) # flag{m0rse_code_1s_interest1n9!}
```

------

### [维吉尼亚密码](https://ce.pwnthebox.com/challenges?type=3&id=682)

题目名字叫维吉尼亚密码，但是题目描述只给出了以下字符串：

```
gndk{911k46l0jln5804oo592mo9q363st1r1}
```

显然，这道题考察的是在无密钥的情况下破解维基尼亚密码。维吉尼亚密码是在凯撒密码基础上产生的一种加密方法，它将凯撒密码的全部`25`种位移排序为一张表，与原字母序列共同组成`26`行及`26`列的字母表。

维吉尼亚密码的加密原理是将`26`个英文字母（`a-z`）对应`26`个自然数（`0-25`），它只对字母（不区分大小写）进行加密，若文本中出现非字母字符会保留原样。由`flag`与`gndk`的对应关系可知，`f + 1 = g`，`l + 2 = n`，`a + 3 = d`，`g + 4 = k`，因此密钥前四位为`bcde`，以此类推可得密钥为字母表`bcdefghijklmnopqrstuvwxyza`，编写`Python`代码用密文减去密钥即可得到明文：`flag{911f46f0cde5804ed592ab9c363dd1a1}`。

```python
cipher = 'gndk{911k46l0jln5804oo592mo9q363st1r1}'
key = 'bcdefghijklmnopqrstuvwxyza'
flag = ''
j = 0
for i, x in enumerate(cipher):
    if x.isalpha():
        flag += chr(ord('a') + ord(x) - ord(key[j%len(key)]))
        j += 1
    else:
        flag += x

print(flag) # flag{911f46f0cde5804ed592ab9c363dd1a1}
```

------

### [Vigenère](https://ce.pwnthebox.com/challenges?type=3&id=421)

根据题目名字可以推测出这题的考察点还是维吉尼亚密码，附件给出了俩个文件：`Encode.c` 和 `flag_encode`。

```c
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int main()
{
	freopen("flag.txt","r",stdin);
	freopen("flag_encode.txt","w",stdout);
	char key[] = /*SADLY SAYING! Key is eaten by Monster!*/;
	int len = strlen(key);
	char ch;
	int index = 0;
	while((ch = getchar()) != EOF){
		if(ch>='a'&&ch<='z'){
			putchar((ch-'a'+key[index%len]-'a')%26+'a');
			++index;
		}else if(ch>='A'&&ch<='Z'){
			putchar((ch-'A'+key[index%len]-'a')%26+'A');
			++index;
		}else{
			putchar(ch);
		}
	}
	return 0;
}
```

审计源码可以看到`SADLY SAYING! Key is eaten by Monster!`，密钥被怪物吃掉了，这题也是在无密钥的情况下破解维基尼亚密码。`.txt`文件中是多行文本，每一行是单独加密的。

```
Yzyj ia zqm Cbatky kf uavin rbgfno ig hnkozku fyyefyjzy sut gha pruyte gu famooybn bhr vqdcpipgu jaaju obecu njde pupfyytrj cpez cklb wnbzqmr ntf li wsfavm azupy nde cufmrf uh lba enxcp, tuk uwjwrnzn inq ksmuh sggcqoa zq obecu zqm Lncu gz Jagaam aaj qx Hwthxn'a Gbj gfnetyk cpez, g fwwang xnapriv li phr uyqnvupk ib mnttqnq xgioerry cpag zjws ohbaul drinsla tuk liufku obecu ovxey zjwg po gnn aecgtsneoa.

Cn poyj vzyoe gxdbhf zq ty oeyl-ndiqkpl, ndag gut mrt cjy yrrgcmd rwwsf, phnz cpel gtw yjdbcnl bl zjwcn Cekjboe cklb yeezjqn htcdcannhum Rvmjlm, phnz juoam vzyoe nxn Tisk, Navarge jvd gng honshoc wf Ugrhcjefy. — Cpag zq kyyuek cpefk taadtf, Mxdeetowhps nxn qnfzklopeq gvwnt Sgf, xarvbrvg gngal fufz ywwrxu xlkm gnn koaygfn kf gnn ooiktfyz, — Tugc ehrtgnyn aae Owrz uh Yireetvmng hguiief jnateaelcre bl cpefk gfxo, ig ob bhr Xkybp os zqm Prurdy po nrcmr bx vg uxoyobp ig, gpv nk iaycqthzg fys Gbbnznzkpl, fwyvtp qtf lqmhzagoxv oa ywub lrvtlqpyku shz oemjvimopy cps cufmrf op koyh suau, af zq lbam fnjtl fkge gksg rrseye vg ybfric bhrot Kubege jvd Ugrhcjefy. Yzuqkpuy, enqknl, wvrn vcytnzn bhnz Igparasnvtf rqfa asggktifngv mdohrm vog hg ubwntkm noe rkybp aaj czaaykwhp cnabms; ntf swyoejrvgye cdf axckaqeaig zuph fnnen gncl gwnxowl aek ogla dvyywsrj vg mqfska, ehvrg wpelf gam shlhwlwbyk cpaa zq jcchg zqmmfknnyo bl gkwlvyjahc tuk owrzy vg qdipn cpel gtw uychycwmrj. Dmn shrt j toam vjuen bl jjufku shz ufaaxagoqfm, lueydqnt opnuninhug tuk usga Oopnkt rbkfwas n jnaitt vg ladhin bhrs wfxar nhbwlhzg Vyopbzram, vz kk ndevx aqguz, kl co tukrz dhza, li pheuf wfs ywub Coikavmrtv, shz tb vawvvjg fys Ghgals sut lbaie ldbuek uwwqrvzh. — Aupn jsm xert cpe cgvayjt faoneegpuy kf gnnae Pungheef; gwl shij am joj zqm nrigkmetl cqqcu iqfmprnowa tuko li wlgka bhrot xinmrx Bgsgkok ib Gbbnznzkpl. Nde uobboee qx nde cxnaeaz Mahc os Mamag Htanwia ob i hvyvglu os xnxenzgv cjjhxrms ntf mmqrcgcqoay, cdf daiowo ia jkjyyt bhsmcg zjw yotnhuqsusgfn kf nt jjsbrwly Pyegwvy bbgj ndefk Bbagku. Li lrbbn bhvy, nwn Bapzb je fadecptrj cw a pgpvcz wbxul.

Hr nck lafhynl hvy Ckmang zx Tajy, vzy iofz fpoykugga aaj wmcryuslu fbx cpe caddcy gbum.

Pe ugu xinbvjmmn uou Yireetxzs gu rsmo Lncb wf vsowxeagk jvd cxgkment ovxoezcfwa, uarnas fauhyjdrj rv tukkj ileegcqoa zkdf dif Gbaeaz uziqlq hn wbggkfyz; aaj fpea yq kooprtmmd, uk jsm qtgkaty akidyytrj cw agzgfx po gnnu.

Hr nck lafhynl tb vckm ktuka Tajy hgl phr glkozsqvupibt xn lnxiw xesgxrktf uh hykpyk, dvlryu lbksr vnwpyk ygohd ekuqndakkb phr xrohg uh Jylrrynvtnzkgh en gnn Tetoudupuek, j zitnv ahasgovibyk vg ndez gwl fbxoaxwbyk cw tlxcfno oarh.

Pe ugu uuhlrj cwgrzjwl hetobtagoxw vkdvkb it crcuyo uaabcay, apuiifbxcibyk, cfx zifzjvt sxqe nde qkywsvzqjs kf gnnqr Caddcy Rrixzdf, lqj nde fuum phxrgma os ljbitakfa phrs rvtb iqejhintlm wvzj zco mrgbcrry.

Jw bws qobaoybgv Lapekbmnggvapa Hbabms ekrwupeqrh, noe urhioiam fqtu scffu fvxvvefy jam enigbqoay qf nde eopptf uh lba pruyte.

Uk jsm nesabmd sut s fknt zrue, nlvwl oupn mqsfunmneoay, cw cnauw iphrxb bo ok gdyytrj, fpeekdq nde Ykpqsygvapa Pbcnzs, vtesjwbyk xn Aatkzchagoxv, hnbg jypuetnl tb zjw Jaocrn it ygtyy boe zqmie kzwlyifk; cpe Fzcly nezgrviam kf nde zkjv tvsg wrlofkm bo nrn lba dntpmrf uh ahrafoxv feuo ocphbac, inq iqfpqlfoxvs jovzcj.

Hr nja eajgspkuekm bo cxgnyjt gnn xocansneoa uo bhryg Knwtry; owr gncl jqrcubm ooyvjoytvtp bhr Rcom boe Tjbuegnatwtvuw wf Sutwccnrxb; zesauahc tb vjas bzjwlo tb kwkohxcyy phroa uitxclcknf nrbhrx, cfx navyrvg gng uijdvzrwnf uh fys Acvawpeoclcknf uo Taaju.

Zy daf ukateaelyz tuk Jlmvtkknnagoxv os Pwknecr hh zesauahc hvy Jasrtv li Hajy owr ryvsvhifnrvg Wafaweaee Ywwrxu.

Zy daf sjle Wafyyo drvnvdrtv gh dif Crtl nrqfy boe zqm trtwjy kf gnnqr blhawas, ntm bhr gogojt ntm xalsgfn kf gnnqr fgnsleef.

luig vy cxwpf{Jnxwobuqg_O_Cogiqi!}

Hr nck ynepznl a zanlcpuqk xn Nrc Qxzecry, jvd fkpl betuka awnxok ib Oslrkeey vg bwrnyb wue vggjhe ntm mag uwl ndevx bcbfzcfwa.

Hr nja krvv sgknt ab, qn goowm kf ckjke, Fzcfxent Gauiry yandohz cpe Pupkyjt bl xcr ykiamhagaams.

Uk jsm wfsklbeq zq jyjdrx cpe Zonanwrl owleckpvyjt bl jvd farwleoe zx bhr Iknch Pbcnz.

Hr nck wkmoowmd jovz iphrxb bo fadbyyt hy cw a watamzipzrwn sutwccn gu xcr pupknethzrwn, ntf mhwcxtxelrjiwx xy baa tajy; iapent nra Afygfn po gnnqr Nivk ib pekcmnqkf Dycifrjbibt:

Hgl munxcmrvti dungr hxliry qx unmrj czobvu sgknt ab:

Noe vtgnacgowo tuko, ts w mbit Brvgn xlkm cawqsusgfn boe gwg Mhxfwlo wuolp tuka kbkuyj lwmzov gh phr Owpaoovshps bl cpefk Ulupef:

Lxz chzvahc osl xcr Gxcvy sign jtl cgtlm kf gnn eoerf:

Xin izvxaiam Vsras bt da wvzjgop ohx Lwnfkpl:

Zkr qkyziiopy oo ia sjvy pguwm, kf gnn jeakhan kf Gxril oe Lmlu:

Fbx czaayrglpiam da breqfx Oeny cw br ztayz fbx yzegkpvyz oslnvcry:

Hgl wbbrrahvti lba fekn Ayfzge ib Eamuqsu Rcom en n tnqguhqmlent Vawvvtew, yotnhuqsuopy ndeekrv aa Gttcprnxh ooiktfgang, gwl earcjaent oca Bbapvuniry bw af zq jyjdrx rb ag upuy wn rdjupyk cfx big owateaowhp fbx rvteufmwent zqm snsg svooyacm rhrg ahpo gnnae Pungheef

Lxz tnqkfa wwne xcr Pncjnarf, gkwlvyjahc ohx vwsg bcdowbyk Uiwf gpv uhtrxrvg sapvuieazjtll zjw Zkrzy xn ohx Igparasnvtf:

Lqj mqsckwliam qml kwa Rnoifrclonef, gwl drinslent zqmmfknnyo iabnatrj yand pbcnz tb rgycolnzn noe au ah wly ijaef cjsnoorbnz.

Hr nck uxdvijbeq Mqnynnzkwb hrxg, ts zeprjziam wk iqt bl qqs Cxqlyytvuw inq ccycjg Jga ignopkn qs.

Uk qis crwfxarrj xcr fkck, lwvnmnl ohx eguotf, hdzng uwj nkway, jvd qkullkyrj cpe yoxwm kf baa xebvnw.

Ba if gc bhvy vaga tegwapbxvahc lnxpm Aeskwm kf suamitt Owlyeagaqef zq uiipykjb tuk yglgs bl mmagn, fwmklnzrwn, ntf lsnaath, ilekcvs xetaw eign ealyuzycinpku gz Yrhkuby & Cktxczy fijzcrra hunayrnteq op lba mbyc jaehcjiqs nmna, aaj vgnwlye dvwbxvzs phr Nnid bl c ucriyoimd agvaij.

Hr nja cbtullwiakm wue lgdfkw Pocqzrtu lugea Ijxtvbg gh phr nroh Fkck nk brga Irzy cyuenfz cpevx Egojtee, cw briqey phr kgmchzkgharf uo bhrot xleeajb inq Htwndrrt, xz tb lcdf phrsbmliku ts phroa Paaju.

Zy daf kgkigkf viiefzrk iaywjlacgoxvs nsqfaot hy, jvd ugu whzenbxcrrj vg vniam xv tuk kfbwbvzjvtf uh gon feuwbirxu, lba mrxlqlryu Ahzint Bivnmgk qdofk tvojt tmfa os cjzfnxg, am wn htmqsgopyoesukm lefztmwpibt xn ayr cyyo, srdna aaj eghzigoxvs.

Vt gnyny fzjoe bl vzyoe Bvyzefykgho Wr njde Ckvaneoakm noe Xgvlasf ow bhr sqkn duzhum trxok: Iqr ekymagkf Hypigoxvs ugxw vaea gwawrxgv ijll hh zeckclyz iapdzy. N Vtahye, jnxae pncjuytrx ra tuau eunkrj kg eiktq uyt jnrkh zga vybiak j Byegpl, co ualrb tb hg lba rhrnz os g hjya pruyte.

Aut zure Jk kmea ccfnent ow itgkplcknf zx wue Htanesu hamtuxgf. Qa hnbn eaetgv ndez lawm goow nk tvsn wf nzvwgltf hh bhrot dycifrjbuek vg yttrtm in htyslnaazjjlr pwjcodvicqoa uxwl qs. Jk qivr xgecjdrj cpez uh lba cvxlcmfzcfwas bl xcr rskylwtvuw inq yglnhezkwb hrxg. Oy daik jxprgnwx po gnnqr agvapa jhycqcr gpv gwgagwqmvza, shz wr njde pupboneq zqmm oe vzy piry xn ohx eggioa qrvdekf li zifgeww gngky qshxyitvupk, qdipn fwuyj kfyriggkty vtvwlnucz xcr pupfyytvuwa aaj eglnefvxvdrtew. Ndel zxw hnbg tyan qkjn tb zjw pkipk xn jhyvawa aaj xn cbtushcuvtrby. Jk ommp, tukamfbxg, swmuvkbke vt vzy jepkbaige, yzcyh qkwwuaigk iqr Fkyirnzkgh, wnq nxtd gnge, uo wr nxtd gng jyot bl vinxopv, Yjezona ia Ccj, cj Prglm Feogfxo.

Wr, zqmrrlqjy, phr Xnxrrygfnwtvbna os zjw ojigkm Atnzgk ib Azkaqcn, op Yyjeegu Koamtwmo, Afynubykf, sjlenrrvg gu vzy Oucxnue Wafyy kf gnn eoerf xin tuk amcgovmxa os udz iazgfneoay, mw, ia zjw Hwmr, gwl bl Gwlbkrvzh wf gng yikd Ckxxlr uh lbasr Ixtoaogk, mklrswty caddcoh ntm leprcjy, Phnz cpefk wfcpeq Ixtoaogk une, ntm wf Eoizn kutnc bo ok Hjya aaj Rvdrvgfxang Ycitry, vzup tukh irr Gdkihvrj ozoz gnd Uhlrmrinpk vg nde Oxrbifn Ejisn, ntm bhnz cdf loyocqcnr eghjepzrwn okvoyan gnnu aaj vzy Otnzn wf Txgsn Xrvzjqn, vy cfx kutnc bo ok vgnwlye mqsfunnyz; aaj cpag gu Xlae ntm Qnqkrwhzeaz Bbagku, lbay ugem fhrn Hisee zx teie Ysl, yoaiucdr Vgswa, cbtczapz Cdfeaaina, efzctfesu Ixumrxew, ujd gu mw ayr qlbar Nica aaj Vzcjgf cqqcu Opvyleajnvt Fzclyo mne xn rvmjl xk. — Aaj owr gng kolpbxc wf gnkk Xacygaitvup, ocph n lrzm eknaujcr uw bhr vtgnacgoxv os Jkncje Cxxdiqkpuy, se zaccayra hfadtk cw enij gndee udz Lvbgk, iqr Suabuaku, shz ohx bicekf Zijoe.
```

使用 https://www.guballa.de/vigenere-solver 进行线上解密， 可以知道密钥为`"csuwangjiang"`，破解后的明文如下：

```
When in the Course of human events it becomes necessary for one people to dissolve the political bands which have connected them with another and to assume among the powers of the earth, the separate and equal station to which the Laws of Nature and of Nature's God entitle them, a decent respect to the opinions of mankind requires that they should declare the causes which impel them to the separation.

We hold these truths to be self-evident, that all men are created equal, that they are endowed by their Creator with certain unalienable Rights, that among these are Life, Liberty and the pursuit of Happiness. — That to secure these rights, Governments are instituted among Men, deriving their just powers from the consent of the governed, — That whenever any Form of Government becomes destructive of these ends, it is the Right of the People to alter or to abolish it, and to institute new Government, laying its foundation on such principles and organizing its powers in such form, as to them shall seem most likely to effect their Safety and Happiness. Prudence, indeed, will dictate that Governments long established should not be changed for light and transient causes; and accordingly all experience hath shewn that mankind are more disposed to suffer, while evils are sufferable than to right themselves by abolishing the forms to which they are accustomed. But when a long train of abuses and usurpations, pursuing invariably the same Object evinces a design to reduce them under absolute Despotism, it is their right, it is their duty, to throw off such Government, and to provide new Guards for their future security. — Such has been the patient sufferance of these Colonies; and such is now the necessity which constrains them to alter their former Systems of Government. The history of the present King of Great Britain is a history of repeated injuries and usurpations, all having in direct object the establishment of an absolute Tyranny over these States. To prove this, let Facts be submitted to a candid world.

He has refused his Assent to Laws, the most wholesome and necessary for the public good.

He has forbidden his Governors to pass Laws of immediate and pressing importance, unless suspended in their operation till his Assent should be obtained; and when so suspended, he has utterly neglected to attend to them.

He has refused to pass other Laws for the accommodation of large districts of people, unless those people would relinquish the right of Representation in the Legislature, a right inestimable to them and formidable to tyrants only.

He has called together legislative bodies at places unusual, uncomfortable, and distant from the depository of their Public Records, for the sole purpose of fatiguing them into compliance with his measures.

He has dissolved Representative Houses repeatedly, for opposing with manly firmness his invasions on the rights of the people.

He has refused for a long time, after such dissolutions, to cause others to be elected, whereby the Legislative Powers, incapable of Annihilation, have returned to the People at large for their exercise; the State remaining in the mean time exposed to all the dangers of invasion from without, and convulsions within.

He has endeavoured to prevent the population of these States; for that purpose obstructing the Laws for Naturalization of Foreigners; refusing to pass others to encourage their migrations hither, and raising the conditions of new Appropriations of Lands.

He has obstructed the Administration of Justice by refusing his Assent to Laws for establishing Judiciary Powers.

He has made Judges dependent on his Will alone for the tenure of their offices, and the amount and payment of their salaries.

flag is afctf{Whooooooo_U_Gotcha!}

He has erected a multitude of New Offices, and sent hither swarms of Officers to harass our people and eat out their substance.

He has kept among us, in times of peace, Standing Armies without the Consent of our legislatures.

He has affected to render the Military independent of and superior to the Civil Power.

He has combined with others to subject us to a jurisdiction foreign to our constitution, and unacknowledged by our laws; giving his Assent to their Acts of pretended Legislation:

For quartering large bodies of armed troops among us:

For protecting them, by a mock Trial from punishment for any Murders which they should commit on the Inhabitants of these States:

For cutting off our Trade with all parts of the world:

For imposing Taxes on us without our Consent:

For depriving us in many cases, of the benefit of Trial by Jury:

For transporting us beyond Seas to be tried for pretended offences:

For abolishing the free System of English Laws in a neighbouring Province, establishing therein an Arbitrary government, and enlarging its Boundaries so as to render it at once an example and fit instrument for introducing the same absolute rule into these Colonies

For taking away our Charters, abolishing our most valuable Laws and altering fundamentally the Forms of our Governments:

For suspending our own Legislatures, and declaring themselves invested with power to legislate for us in all cases whatsoever.

He has abdicated Government here, by declaring us out of his Protection and waging War against us.

He has plundered our seas, ravaged our coasts, burnt our towns, and destroyed the lives of our people.

He is at this time transporting large Armies of foreign Mercenaries to compleat the works of death, desolation, and tyranny, already begun with circumstances of Cruelty & Perfidy scarcely paralleled in the most barbarous ages, and totally unworthy the Head of a civilized nation.

He has constrained our fellow Citizens taken Captive on the high Seas to bear Arms against their Country, to become the executioners of their friends and Brethren, or to fall themselves by their Hands.

He has excited domestic insurrections amongst us, and has endeavoured to bring on the inhabitants of our frontiers, the merciless Indian Savages whose known rule of warfare, is an undistinguished destruction of all ages, sexes and conditions.

In every stage of these Oppressions We have Petitioned for Redress in the most humble terms: Our repeated Petitions have been answered only by repeated injury. A Prince, whose character is thus marked by every act which may define a Tyrant, is unfit to be the ruler of a free people.

Nor have We been wanting in attentions to our British brethren. We have warned them from time to time of attempts by their legislature to extend an unwarrantable jurisdiction over us. We have reminded them of the circumstances of our emigration and settlement here. We have appealed to their native justice and magnanimity, and we have conjured them by the ties of our common kindred to disavow these usurpations, which would inevitably interrupt our connections and correspondence. They too have been deaf to the voice of justice and of consanguinity. We must, therefore, acquiesce in the necessity, which denounces our Separation, and hold them, as we hold the rest of mankind, Enemies in War, in Peace Friends.

We, therefore, the Representatives of the united States of America, in General Congress, Assembled, appealing to the Supreme Judge of the world for the rectitude of our intentions, do, in the Name, and by Authority of the good People of these Colonies, solemnly publish and declare, That these united Colonies are, and of Right ought to be Free and Independent States, that they are Absolved from all Allegiance to the British Crown, and that all political connection between them and the State of Great Britain, is and ought to be totally dissolved; and that as Free and Independent States, they have full Power to levy War, conclude Peace, contract Alliances, establish Commerce, and to do all other Acts and Things which Independent States may of right do. — And for the support of this Declaration, with a firm reliance on the protection of Divine Providence, we mutually pledge to each other our Lives, our Fortunes, and our sacred Honor.
```

可以看到明文中有一行`flag is afctf{Whooooooo_U_Gotcha!}`，提交`afctf{Whooooooo_U_Gotcha!}`即可。

------

### [Caesar](https://ce.pwnthebox.com/challenges?id=83)

附件解压缩后得到`.py`文件，源码如下：

```python
import hashlib

def change(key, str):
    result = ""
    for i in str:
        if ord(i) >= 97 and ord(i) <= 122:
            result += chr(97+(ord(i)+key) % 26)
        else:
            result += i
    return result


key = *
str1 = "********************************"
str2 = change(key, str1)  # zab81501z9740b67dc0by8z15093a426
flag = hashlib.md5(str1).hexdigest()
print(flag[10:16]）  # aebc0a
```

编写`Python`代码求解得到`flag{8f36ba62b0aebc0ae2a9c7abea36f7ef}`。

```python
import hashlib

def change(key, str):
    result = ""
    for i in str:
        if ord(i) >= 97 and ord(i) <= 122:
            result += chr(97+(ord(i)+key) % 26)
        else:
            result += i
    return result


str2 = 'zab81501z9740b67dc0by8z15093a426'
for key in range(1,26):
    str1 = change(key, str2)
    flag = hashlib.md5(str1.encode()).hexdigest()
    if flag[10:16] == 'aebc0a':
        print(f'flag{{{flag}}}')
        break
```

------

### [BabyRSA](https://ce.pwnthebox.com/challenges?id=314)

```python
from Crypto.Util.number import *

flag = bytes_to_long("n1book{*********}")

p = getPrime(128)
q = getPrime(128)
n = p * q
e = 65537

cipher = pow(flag, e, n)
print n, cipher

# 69343391982073836527260787066436662760820725339907775857387709078502658633087 
# 19914364722342610626569065936888842248099105322649309104924491672406432347316
```

直接对`n`进行大因数分解，得到`p`和`q`，再求`m`。

```python
from Crypto.Util.number import *
from factordb.factordb import FactorDB
e = 65537

n = 69343391982073836527260787066436662760820725339907775857387709078502658633087 
c = 19914364722342610626569065936888842248099105322649309104924491672406432347316

# f = FactorDB(n)
# f.connect()
# print((f.get_factor_list())) # 226134486267985710544345427491176087287, 306646691207889915109374013611076713401
p, q = 226134486267985710544345427491176087287, 306646691207889915109374013611076713401
m = pow(c, inverse(e, (p-1)*(q-1)), n)
print(long_to_bytes(m))
```

------

### [RSA](https://ce.pwnthebox.com/challenges?type=3&id=679)

附件`rsa-encrypted.txt`给出的信息如下：

```
4153372421328787064168548641845708183921443446990158572506114559735441950501706984118235944441928889749083563790293558028143373121367441549974248211570336802004821051820943229232421937298269855190652251294220483768084460779714162849925877879859830009443131489814222929347727735616113359695228615432020363240247474622132986939108457393618346100033147945959684443762976681454755482192433993286205527003029269574787026484389622816932835184754540312561890719407986296481186847292967270288752616
```

使用 http://factordb.com 在线进行大因数分解。

```
16074357572745018593418837326290993512421736655307780242162599660198598253230550168811761868953242350136362894008095983571749530656901163555918436741973772511575306
```

编写`Python`代码将数字转换成字符串。

```python
import libnum

flag = libnum.n2s(16074357572745018593418837326290993512421736655307780242162599660198598253230550168811761868953242350136362894008095983571749530656901163555918436741973772511575306)
print(flag.decode()) # Guvf vf gur cnffjbeq lbh arrq sbe gur MVC svyr: synt{efnZ0erQ33crE}
```

编写`Python`代码进行凯撒密码解密，可以得到`This is the password you need for the ZIP file: flag{rsaM0reD33peR}`。

```python
s = 'Guvf vf gur cnffjbeq lbh arrq sbe gur MVC svyr: synt{efnZ0erQ33crE}'
flag = ''
for i in range(1,27):
    t = ''
    for c in s:
        if c.islower():
            t += chr(ord('a') + ((ord(c) - ord('a')) + i) % 26)
        elif c.isupper():
            t += chr(ord('A') + ((ord(c) - ord('A')) + i) % 26)
        else:
            t += c
    if "flag" in t:
        flag = t
        break
print(flag) # This is the password you need for the ZIP file: flag{rsaM0reD33peR}
```

------

### [ezrsa](https://ce.pwnthebox.com/challenges?id=595)

附件解压缩后得到`task.py`，源码如下：

```python
from Crypto.Util.number import *
from gmpy2 import *

def RSA_gen():
    p = getPrime(512)
    q = next_prime(p)
    n = p*q
    e = 0x10001
    d = invert(e,(p-1)*(q-1))
    Parameter = (p,q,n,e,d)
    return Parameter
def leak(c,Parameter):
    (p,q,n,e,d) = Parameter
    print("n =",n)
    print("e =",e)
    print("c_mod_p =",c % p)
    print("c_mod_q =",c % q)

def encryption(message,Parameter):
    (p,q,n,e,d) = Parameter
    m = bytes_to_long(message)
    c = pow(m,e,n)
    print(c)
    return c

if __name__ == '__main__':
    flag = b'flag{xxxxxxxxxxxxxxxxxxxx}'
    Parameter = RSA_gen()
    cipher = encryption(flag,Parameter)
    leak(cipher,Parameter)

#n = 60451215053202473004940952621742735161658776366659855277231745089406139921920247699935855664424690715827311751776376765039253720695107034417349327247413785321282310515940197744035889015386751355695663945883766755254889478550954910913617031495509031272479126330010210073745554866695555903062215643355046569531
#e = 65537
#c_mod_p = 5860001067333912869348276317959806331354930830756907188134520598132033029685961651079042255479216212218840727162091566460728252274773922656346335208185716
#c_mod_q = 233846791877558838234653540832234409293133184826445436186569970711741339843931083266127545694840179770763904903248540633847534630328748650704882388519907
```

如果线下赛不准联外网用http://factordb.com 在线求解`p`和`q`的话，就用`yafu`工具分解， 或者编写`Python`代码暴力破解`p`和`q`。
由`p = getPrime(512) `，`q = next_prime(p)`，可知`p`和`q`是相近的素数。`n=p*q`，可以对`n`进行开方，得`r`。在`r`的附近`[r-1000, r+1000]`进行爆破，得到`p`和`q`。 

```python
from gmpy2 import *

n = 60451215053202473004940952621742735161658776366659855277231745089406139921920247699935855664424690715827311751776376765039253720695107034417349327247413785321282310515940197744035889015386751355695663945883766755254889478550954910913617031495509031272479126330010210073745554866695555903062215643355046569531
r, f = iroot(n, 2) 
for p in range(r-1000, r+1000):
    if is_prime(p):
        q = next_prime(p) 
        t = p*q 
        if t==n: 
            print(q,p)
# 解出结果
p = 7775037945450972074306550333494120484720176686937970436452427912326505124727011077406894038014608345834514099931510587280606879496551971589714415968674527
q = 7775037945450972074306550333494120484720176686937970436452427912326505124727011077406894038014608345834514099931510587280606879496551971589714415968674853
```

根据`c % q == c_mod_q`和`c % p == c_mod_p`这两个条件，利用`z3`直接求解`c`。

```python
from z3 import *

p = 7775037945450972074306550333494120484720176686937970436452427912326505124727011077406894038014608345834514099931510587280606879496551971589714415968674527
q = 7775037945450972074306550333494120484720176686937970436452427912326505124727011077406894038014608345834514099931510587280606879496551971589714415968674853
c_mod_p = 5860001067333912869348276317959806331354930830756907188134520598132033029685961651079042255479216212218840727162091566460728252274773922656346335208185716
c_mod_q = 233846791877558838234653540832234409293133184826445436186569970711741339843931083266127545694840179770763904903248540633847534630328748650704882388519907
x = Int('x')
s = Solver()
s.add(x>0)
s.add(x%q == c_mod_q)
s.add(x%p == c_mod_p)
if s.check() == sat:
    result = s.model()
c = result[x]
print(c)
# 解出结果
c = 47151276918981583567523648994179430148149948747698685873110089240682910171948851068764675122915379237725883244046107442907684194750830923424437683099073544825359731502984910522664259100042832108387724184182561564126572144921453168070150979343615465806743760339599417267305068355617917378977403151005726078444
```

接着就是编写`Python`代码进行常规的`RSA`求解啦，提交`flag{6ba3851f-94d2-43be-a321-5a22b8977829}`即可。

```python
from gmpy2 import *
from Crypto.Util.number import long_to_bytes

n = 60451215053202473004940952621742735161658776366659855277231745089406139921920247699935855664424690715827311751776376765039253720695107034417349327247413785321282310515940197744035889015386751355695663945883766755254889478550954910913617031495509031272479126330010210073745554866695555903062215643355046569531
e = 65537
p = 7775037945450972074306550333494120484720176686937970436452427912326505124727011077406894038014608345834514099931510587280606879496551971589714415968674527
q = 7775037945450972074306550333494120484720176686937970436452427912326505124727011077406894038014608345834514099931510587280606879496551971589714415968674853
c = 47151276918981583567523648994179430148149948747698685873110089240682910171948851068764675122915379237725883244046107442907684194750830923424437683099073544825359731502984910522664259100042832108387724184182561564126572144921453168070150979343615465806743760339599417267305068355617917378977403151005726078444
d = invert(e, (p-1)*(q-1))
m = pow(c, d, n)
flag = long_to_bytes(m).decode() 
print(flag) # flag{6ba3851f-94d2-43be-a321-5a22b8977829}
```

------

### [Rsa](https://ce.pwnthebox.com/challenges?type=3&id=1052)

附件解压缩后得到`task.py`，源码如下：

```python
from Crypto.Util.number import getPrime,bytes_to_long

flag=open("flag","rb").read()

p=getPrime(1024) # 得到一个最大为1024位的随机素数p
q=getPrime(1024) # 得到一个最大为1024位的随机素数q
assert(e<100000) # e 是小于100000的数
n=p*q
m=bytes_to_long(flag) #flag从字符串转换成整数
c=pow(m,e,n)
print c,n
print pow(294,e,n)

p=getPrime(1024)
n=p*q # q没变 p变了
m=bytes_to_long("BJD"*32) # m白给
c=pow(m,e,n) # 已知 c, n, m 可以求e
print c,n

'''
output:
12641635617803746150332232646354596292707861480200207537199141183624438303757120570096741248020236666965755798009656547738616399025300123043766255518596149348930444599820675230046423373053051631932557230849083426859490183732303751744004874183062594856870318614289991675980063548316499486908923209627563871554875612702079100567018698992935818206109087568166097392314105717555482926141030505639571708876213167112187962584484065321545727594135175369233925922507794999607323536976824183162923385005669930403448853465141405846835919842908469787547341752365471892495204307644586161393228776042015534147913888338316244169120  13508774104460209743306714034546704137247627344981133461801953479736017021401725818808462898375994767375627749494839671944543822403059978073813122441407612530658168942987820256786583006947001711749230193542370570950705530167921702835627122401475251039000775017381633900222474727396823708695063136246115652622259769634591309421761269548260984426148824641285010730983215377509255011298737827621611158032976420011662547854515610597955628898073569684158225678333474543920326532893446849808112837476684390030976472053905069855522297850688026960701186543428139843783907624317274796926248829543413464754127208843070331063037
381631268825806469518166370387352035475775677163615730759454343913563615970881967332407709901235637718936184198930226303761876517101208677107311006065728014220477966000620964056616058676999878976943319063836649085085377577273214792371548775204594097887078898598463892440141577974544939268247818937936607013100808169758675042264568547764031628431414727922168580998494695800403043312406643527637667466318473669542326169218665366423043579003388486634167642663495896607282155808331902351188500197960905672207046579647052764579411814305689137519860880916467272056778641442758940135016400808740387144508156358067955215018
979153370552535153498477459720877329811204688208387543826122582132404214848454954722487086658061408795223805022202997613522014736983452121073860054851302343517756732701026667062765906277626879215457936330799698812755973057557620930172778859116538571207100424990838508255127616637334499680058645411786925302368790414768248611809358160197554369255458675450109457987698749584630551177577492043403656419968285163536823819817573531356497236154342689914525321673807925458651854768512396355389740863270148775362744448115581639629326362342160548500035000156097215446881251055505465713854173913142040976382500435185442521721  12806210903061368369054309575159360374022344774547459345216907128193957592938071815865954073287532545947370671838372144806539753829484356064919357285623305209600680570975224639214396805124350862772159272362778768036844634760917612708721787320159318432456050806227784435091161119982613987303255995543165395426658059462110056431392517548717447898084915167661172362984251201688639469652283452307712821398857016487590794996544468826705600332208535201443322267298747117528882985955375246424812616478327182399461709978893464093245135530135430007842223389360212803439850867615121148050034887767584693608776323252233254261047
'''
```

审计代码后发现可以先求出第二次加密后的`m`：

```python
from Crypto.Util.number import bytes_to_long

m = bytes_to_long(b'BJD'*32)
print(m) # m = 402017913579464308549065187632311712702457024609243629355239472425901405342857173163318953042818239800250726439867872520201555400267080696314487494273728199047706293587181667486153447024103148497383783335982253445744950705916103236
```

已知`c`，`n`，`m`，`c = pow(m, e, n)`，`assert(e < 100000)`可以爆破出`e = 52361`。这里也可以结合`pow(294,e,n)`和第一次输出的`n`进行求解，得到的结果`e`都是一样的。

```python
c = 979153370552535153498477459720877329811204688208387543826122582132404214848454954722487086658061408795223805022202997613522014736983452121073860054851302343517756732701026667062765906277626879215457936330799698812755973057557620930172778859116538571207100424990838508255127616637334499680058645411786925302368790414768248611809358160197554369255458675450109457987698749584630551177577492043403656419968285163536823819817573531356497236154342689914525321673807925458651854768512396355389740863270148775362744448115581639629326362342160548500035000156097215446881251055505465713854173913142040976382500435185442521721

n = 12806210903061368369054309575159360374022344774547459345216907128193957592938071815865954073287532545947370671838372144806539753829484356064919357285623305209600680570975224639214396805124350862772159272362778768036844634760917612708721787320159318432456050806227784435091161119982613987303255995543165395426658059462110056431392517548717447898084915167661172362984251201688639469652283452307712821398857016487590794996544468826705600332208535201443322267298747117528882985955375246424812616478327182399461709978893464093245135530135430007842223389360212803439850867615121148050034887767584693608776323252233254261047

m = 402017913579464308549065187632311712702457024609243629355239472425901405342857173163318953042818239800250726439867872520201555400267080696314487494273728199047706293587181667486153447024103148497383783335982253445744950705916103236

for i in range(100000):
    if pow(m, i, n) == c:
        e = i
        break
print(e) # e = 52361
```

知道`e`后，想要求解出第一次生成的`m`，还需要先对第一次生成的`n`进行大因数分解得到`p`和`q`。已知两次`rsa`加密的`n1`和`n2`，且加密过程中使用的是同一个`q`，由于`p`和`q`都是素数，当`q`相同时，`n1`和`n2`的最大公因数就是`q`值。知道`q`后自然也就得到了`p1`。

```python
from gmpy2 import *

n1 = 13508774104460209743306714034546704137247627344981133461801953479736017021401725818808462898375994767375627749494839671944543822403059978073813122441407612530658168942987820256786583006947001711749230193542370570950705530167921702835627122401475251039000775017381633900222474727396823708695063136246115652622259769634591309421761269548260984426148824641285010730983215377509255011298737827621611158032976420011662547854515610597955628898073569684158225678333474543920326532893446849808112837476684390030976472053905069855522297850688026960701186543428139843783907624317274796926248829543413464754127208843070331063037

n2 = 12806210903061368369054309575159360374022344774547459345216907128193957592938071815865954073287532545947370671838372144806539753829484356064919357285623305209600680570975224639214396805124350862772159272362778768036844634760917612708721787320159318432456050806227784435091161119982613987303255995543165395426658059462110056431392517548717447898084915167661172362984251201688639469652283452307712821398857016487590794996544468826705600332208535201443322267298747117528882985955375246424812616478327182399461709978893464093245135530135430007842223389360212803439850867615121148050034887767584693608776323252233254261047

q = gcd(n1, n2)
print(q) # q = 99855353761764939308265951492116976798674681282941462516956577712943717850048051273358745095906207085170915794187749954588685850452162165059831749303473106541930948723000882713453679904525655327168665295207423257922666721077747911860159181041422993030618385436504858943615630219459262419715816361781062898911
p = n1//q
print(p) # p = 135283423427545651023916134156519717109709399113553907832988770259402226695880524199087896377303631866790192008529658716376684328032075836094156150811025163336681163420875451747389868549203081743561907379260240665153166927504059379076555558704275659133135906827306189040804323574468819553401905127999523676067
```

接着就是编写`Python`代码进行常规的`RSA`求解啦，得到`BJD{p_is_common_divisor}`，提交`flag{p_is_common_divisor}`即可。

```python
from gmpy2 import *
from Crypto.Util.number import long_to_bytes

n = 13508774104460209743306714034546704137247627344981133461801953479736017021401725818808462898375994767375627749494839671944543822403059978073813122441407612530658168942987820256786583006947001711749230193542370570950705530167921702835627122401475251039000775017381633900222474727396823708695063136246115652622259769634591309421761269548260984426148824641285010730983215377509255011298737827621611158032976420011662547854515610597955628898073569684158225678333474543920326532893446849808112837476684390030976472053905069855522297850688026960701186543428139843783907624317274796926248829543413464754127208843070331063037
e = 52361
p = 135283423427545651023916134156519717109709399113553907832988770259402226695880524199087896377303631866790192008529658716376684328032075836094156150811025163336681163420875451747389868549203081743561907379260240665153166927504059379076555558704275659133135906827306189040804323574468819553401905127999523676067
q = 99855353761764939308265951492116976798674681282941462516956577712943717850048051273358745095906207085170915794187749954588685850452162165059831749303473106541930948723000882713453679904525655327168665295207423257922666721077747911860159181041422993030618385436504858943615630219459262419715816361781062898911
c = 12641635617803746150332232646354596292707861480200207537199141183624438303757120570096741248020236666965755798009656547738616399025300123043766255518596149348930444599820675230046423373053051631932557230849083426859490183732303751744004874183062594856870318614289991675980063548316499486908923209627563871554875612702079100567018698992935818206109087568166097392314105717555482926141030505639571708876213167112187962584484065321545727594135175369233925922507794999607323536976824183162923385005669930403448853465141405846835919842908469787547341752365471892495204307644586161393228776042015534147913888338316244169120
d = invert(e, (p-1)*(q-1))
m = pow(c, d, n)
flag = long_to_bytes(m).decode() 
print(flag) # BJD{p_is_common_divisor}
```

整理后，这题的完整求解过程如下：

```python
from Crypto.Util.number import bytes_to_long, long_to_bytes
from gmpy2 import *

c2 = 979153370552535153498477459720877329811204688208387543826122582132404214848454954722487086658061408795223805022202997613522014736983452121073860054851302343517756732701026667062765906277626879215457936330799698812755973057557620930172778859116538571207100424990838508255127616637334499680058645411786925302368790414768248611809358160197554369255458675450109457987698749584630551177577492043403656419968285163536823819817573531356497236154342689914525321673807925458651854768512396355389740863270148775362744448115581639629326362342160548500035000156097215446881251055505465713854173913142040976382500435185442521721
n2 = 12806210903061368369054309575159360374022344774547459345216907128193957592938071815865954073287532545947370671838372144806539753829484356064919357285623305209600680570975224639214396805124350862772159272362778768036844634760917612708721787320159318432456050806227784435091161119982613987303255995543165395426658059462110056431392517548717447898084915167661172362984251201688639469652283452307712821398857016487590794996544468826705600332208535201443322267298747117528882985955375246424812616478327182399461709978893464093245135530135430007842223389360212803439850867615121148050034887767584693608776323252233254261047
m2 = bytes_to_long(b'BJD'*32)
# print(m2) 
# m2 = 402017913579464308549065187632311712702457024609243629355239472425901405342857173163318953042818239800250726439867872520201555400267080696314487494273728199047706293587181667486153447024103148497383783335982253445744950705916103236
for i in range(100000):
    if pow(m2, i, n2) == c2:
        e = i
        break
# print(e) 
# e = 52361
n1 = 13508774104460209743306714034546704137247627344981133461801953479736017021401725818808462898375994767375627749494839671944543822403059978073813122441407612530658168942987820256786583006947001711749230193542370570950705530167921702835627122401475251039000775017381633900222474727396823708695063136246115652622259769634591309421761269548260984426148824641285010730983215377509255011298737827621611158032976420011662547854515610597955628898073569684158225678333474543920326532893446849808112837476684390030976472053905069855522297850688026960701186543428139843783907624317274796926248829543413464754127208843070331063037
q = gcd(n1, n2)
# print(q)
# q = 99855353761764939308265951492116976798674681282941462516956577712943717850048051273358745095906207085170915794187749954588685850452162165059831749303473106541930948723000882713453679904525655327168665295207423257922666721077747911860159181041422993030618385436504858943615630219459262419715816361781062898911
p1 = n1//q
# print(p1)
# p1 = 135283423427545651023916134156519717109709399113553907832988770259402226695880524199087896377303631866790192008529658716376684328032075836094156150811025163336681163420875451747389868549203081743561907379260240665153166927504059379076555558704275659133135906827306189040804323574468819553401905127999523676067
c1 = 12641635617803746150332232646354596292707861480200207537199141183624438303757120570096741248020236666965755798009656547738616399025300123043766255518596149348930444599820675230046423373053051631932557230849083426859490183732303751744004874183062594856870318614289991675980063548316499486908923209627563871554875612702079100567018698992935818206109087568166097392314105717555482926141030505639571708876213167112187962584484065321545727594135175369233925922507794999607323536976824183162923385005669930403448853465141405846835919842908469787547341752365471892495204307644586161393228776042015534147913888338316244169120
d = invert(e, (p1-1)*(q-1))
m1 = pow(c1, d, n1)
flag = long_to_bytes(m1).decode().replace('BJD', 'flag')
print(flag) # flag{p_is_common_divisor}
```

------

### [RSA](https://ce.pwnthebox.com/challenges?id=1063)

```python
A=(((y%x)**5)%(x%y))**2019+y**316+(y+1)/x
p=next_prime(z*x*y)
q=next_prime(z)
A = 2683349182678714524247469512793476009861014781004924905484127480308161377768192868061561886577048646432382128960881487463427414176114486885830693959404989743229103516924432512724195654425703453612710310587164417035878308390676612592848750287387318129424195208623440294647817367740878211949147526287091298307480502897462279102572556822231669438279317474828479089719046386411971105448723910594710418093977044179949800373224354729179833393219827789389078869290217569511230868967647963089430594258815146362187250855166897553056073744582946148472068334167445499314471518357535261186318756327890016183228412253724
n = 117930806043507374325982291823027285148807239117987369609583515353889814856088099671454394340816761242974462268435911765045576377767711593100416932019831889059333166946263184861287975722954992219766493089630810876984781113645362450398009234556085330943125568377741065242183073882558834603430862598066786475299918395341014877416901185392905676043795425126968745185649565106322336954427505104906770493155723995382318346714944184577894150229037758434597242564815299174950147754426950251419204917376517360505024549691723683358170823416757973059354784142601436519500811159036795034676360028928301979780528294114933347127
c = 41971850275428383625653350824107291609587853887037624239544762751558838294718672159979929266922528917912189124713273673948051464226519605803745171340724343705832198554680196798623263806617998072496026019940476324971696928551159371970207365741517064295956376809297272541800647747885170905737868568000101029143923792003486793278197051326716680212726111099439262589341050943913401067673851885114314709706016622157285023272496793595281054074260451116213815934843317894898883215362289599366101018081513215120728297131352439066930452281829446586562062242527329672575620261776042653626411730955819001674118193293313612128
```

使用http://factordb.com 在线分解`n`可得`p`和`q`：

```python
p = 842868045681390934539739959201847552284980179958879667933078453950968566151662147267006293571765463137270594151138695778986165111380428806545593588078365331313084230014618714412959584843421586674162688321942889369912392031882620994944241987153078156389470370195514285850736541078623854327959382156753458569
q = 139916095583110895133596833227506693679306709873174024876891023355860781981175916446323044732913066880786918629089023499311703408489151181886568535621008644997971982182426706592551291084007983387911006261442519635405457077292515085160744169867410973960652081452455371451222265819051559818441257438021073941183
```

无法得知`e`的值，只能挨个`try`进行爆破啦，编写`Python`代码运行可得`e = 65537`, `flag: b'RoarCTF{wm-l1l1ll1l1l1l111ll}'`。提交`flag{wm-l1l1ll1l1l1l111ll}`即可。

```python
from gmpy2 import next_prime
from Crypto.Util.number import inverse, long_to_bytes

n = 117930806043507374325982291823027285148807239117987369609583515353889814856088099671454394340816761242974462268435911765045576377767711593100416932019831889059333166946263184861287975722954992219766493089630810876984781113645362450398009234556085330943125568377741065242183073882558834603430862598066786475299918395341014877416901185392905676043795425126968745185649565106322336954427505104906770493155723995382318346714944184577894150229037758434597242564815299174950147754426950251419204917376517360505024549691723683358170823416757973059354784142601436519500811159036795034676360028928301979780528294114933347127
c = 41971850275428383625653350824107291609587853887037624239544762751558838294718672159979929266922528917912189124713273673948051464226519605803745171340724343705832198554680196798623263806617998072496026019940476324971696928551159371970207365741517064295956376809297272541800647747885170905737868568000101029143923792003486793278197051326716680212726111099439262589341050943913401067673851885114314709706016622157285023272496793595281054074260451116213815934843317894898883215362289599366101018081513215120728297131352439066930452281829446586562062242527329672575620261776042653626411730955819001674118193293313612128
p = 842868045681390934539739959201847552284980179958879667933078453950968566151662147267006293571765463137270594151138695778986165111380428806545593588078365331313084230014618714412959584843421586674162688321942889369912392031882620994944241987153078156389470370195514285850736541078623854327959382156753458569
q = 139916095583110895133596833227506693679306709873174024876891023355860781981175916446323044732913066880786918629089023499311703408489151181886568535621008644997971982182426706592551291084007983387911006261442519635405457077292515085160744169867410973960652081452455371451222265819051559818441257438021073941183
phi_n = (p-1)*(q-1)
e = 0
while True:
    e = next_prime(e)
    try:
        d = inverse(e, phi_n)
        m = pow(c, d, n)
    except:
        pass
    else:
        s = str(long_to_bytes(m))
        if 'CTF' in s or 'flag' in s:
            flag = s
            break

print("e = {}, flag: {}".format(e,flag)) # flag{wm-l1l1ll1l1l1l111ll}
```

------

### [Rsa-1](https://ce.pwnthebox.com/challenges?id=121)

附件解压缩后内容如下：

```python
p = 473398607161
q = 4511491
e = 17
import hashlib
flag = hashlib.md5(str(d).encode()).hexdigest()
```

显然这段代码是不能运行的，因为变量`d`没有被声明。补全`Python`代码，运行得到`flag{ebde301cb778a90496afd30637b345ae}`。

```python
p = 473398607161
q = 4511491
e = 17
from gmpy2 import invert
d = invert(e, (p-1)*(q-1))
import hashlib
flag = hashlib.md5(str(d).encode()).hexdigest()
print(f'flag{{{flag}}}') # flag{ebde301cb778a90496afd30637b345ae}
```

------

### [Rsa2](https://ce.pwnthebox.com/challenges?id=122)

附件解压缩后内容如下：

```python
e = 9381227
p+q = 19557532192412770135396612754285285862683596643931761304241244951607949645171603318285236011702235101665676486522272947846730991666618798325812810258224406
p-q = 1650676835020556888453234895519708130417780877512373678819915730300719385001354199106679712335032655467448380397633077586536806154457656255747639793919628 
c = 27547276638529171065509412221175661764235537727284046788847560106007680393042160546744837423306870550936908103385332804059870319330198485286374792929657313035321660130970784463719347066550910527833718736819018212643397915649241906156866360428203454699367989718776887507055164028637433982239456710840668151058 
```

已知`p+q`和`p-q`，可得`p = ((p+q)+(p-q))/2`，从而得到`q = (p+q)-p`，`n = p×q`，接着就是`RSA`的常规求解过程啦。

编写`Python`代码进行求解，运行得到`flag{7bc5c014-f08a-4877-9dea-7f1dd4b08dfb}`，提交即可。

```python
from Crypto.Util.number import *

e = 9381227
a = 19557532192412770135396612754285285862683596643931761304241244951607949645171603318285236011702235101665676486522272947846730991666618798325812810258224406
b = 1650676835020556888453234895519708130417780877512373678819915730300719385001354199106679712335032655467448380397633077586536806154457656255747639793919628 
c = 27547276638529171065509412221175661764235537727284046788847560106007680393042160546744837423306870550936908103385332804059870319330198485286374792929657313035321660130970784463719347066550910527833718736819018212643397915649241906156866360428203454699367989718776887507055164028637433982239456710840668151058
p = (a+b)//2
q = a-p
n = p*q
d = inverse(e, (p-1)*(q-1))
m = pow(c, d, n)
flag = long_to_bytes(m).decode()
print(flag) # flag{7bc5c014-f08a-4877-9dea-7f1dd4b08dfb}
```

------

### ♥ [rsa3](https://ce.pwnthebox.com/challenges?id=188)

附件解压缩后得到`pub.pem`和`flag.enc`。编写`Python`代码进行求解，首先用`rsa`库来获取公钥对`<n, e>`，然后调用`requests`库在线请求 http://factordb.com 分解模数`n`，得到`p`和`q`，算出 `φ(n) = (p-1)(q-1)`，进而得到私钥的解密质数`d`，至此私钥已经拿到。用私钥对`flag.enc`进行`rsa`解密，可以得到明文`flag{decrypt_256}`，提交即可。

```python
import rsa
import requests
from Crypto.Util.number import inverse

def factorize(n):
    l = []
    url="http://factordb.com/api?query="+str(n)
    r = requests.get(url)
    data = r.json()
    for factor in data['factors']:
        l.append(int(factor[0]))
    return l

with open('pub.pem', 'rb') as f:
    public_key = rsa.PublicKey.load_pkcs1_openssl_pem(f.read())

n = public_key.n
e = public_key.e
q, p = factorize(n)
d = inverse(e, (p-1)*(q-1))
private_key = rsa.PrivateKey(n, e, d, p, q)

with open('flag.enc', 'rb') as f:
    flag = rsa.decrypt(f.read(), private_key).decode()

print(flag) # flag{decrypt_256}
```

------

### [rsa4](https://ce.pwnthebox.com/challenges?id=189)

附件解压缩后得到`.txt`文件，内容如下：

```
n = 1104130035214152028743808527720953724991813899642456182968687
c = 403785626607301529860930456948470905639964209556965338539932
e = 65537
```

编写`Python`代码进行求解，得到`flag{this_is_flag}`。

```python
import requests
from Crypto.Util.number import *

def factorize(n):
    l = []
    url="http://factordb.com/api?query="+str(n)
    r = requests.get(url)
    data = r.json()
    for factor in data['factors']:
        l.append(int(factor[0]))
    return l

n = 1104130035214152028743808527720953724991813899642456182968687
c = 403785626607301529860930456948470905639964209556965338539932
e = 65537
q, p = factorize(n)
d = inverse(e, (p-1)*(q-1))
m = pow(c, d, n)
flag = long_to_bytes(m).decode()
print(flag) # flag{this_is_flag}
```

------

### [Baby RSA](https://ce.pwnthebox.com/challenges?id=1062)

附件解压缩后得到`RoarCTF_2019babyRSA.py`，源码如下：

```python
import sympy
import random

def myGetPrime():
    A= getPrime(513)
    print(A)
    B=A-random.randint(1e3,1e5)
    print(B)
    return sympy.nextPrime((B!)%A)
p=myGetPrime()
#A1=21856963452461630437348278434191434000066076750419027493852463513469865262064340836613831066602300959772632397773487317560339056658299954464169264467234407
#B1=21856963452461630437348278434191434000066076750419027493852463513469865262064340836613831066602300959772632397773487317560339056658299954464169264467140596

q=myGetPrime()
#A2=16466113115839228119767887899308820025749260933863446888224167169857612178664139545726340867406790754560227516013796269941438076818194617030304851858418927
#B2=16466113115839228119767887899308820025749260933863446888224167169857612178664139545726340867406790754560227516013796269941438076818194617030304851858351026

r=myGetPrime()

n=p*q*r
#n=85492663786275292159831603391083876175149354309327673008716627650718160585639723100793347534649628330416631255660901307533909900431413447524262332232659153047067908693481947121069070451562822417357656432171870951184673132554213690123308042697361969986360375060954702920656364144154145812838558365334172935931441424096270206140691814662318562696925767991937369782627908408239087358033165410020690152067715711112732252038588432896758405898709010342467882264362733
c=pow(flag,e,n)
#e=0x1001
#c=75700883021669577739329316795450706204502635802310731477156998834710820770245219468703245302009998932067080383977560299708060476222089630209972629755965140317526034680452483360917378812244365884527186056341888615564335560765053550155758362271622330017433403027261127561225585912484777829588501213961110690451987625502701331485141639684356427316905122995759825241133872734362716041819819948645662803292418802204430874521342108413623635150475963121220095236776428
#so,what is the flag?
```

通过自定义函数`myGetPrime()`得到三个大质数`p`，`q`和`r`，将它们的乘积赋值给`n`，然后再对`flag`进行加密。`myGetPrime()`函数的关键在于`sympy.nextPrime((B!)%A)`，`B`的阶乘计算量太大啦。根据威尔逊定理有`(p-1)!+1 ≡ 0(mod p)`。因为`A`和`B`相近且`A > B`，所以`A!`是包含`B!`的。

> (B - 1) ! + 1 ≡ 0 ( mod B)
>
> (A - 1) ! +1 ≡ 0 ( mod A)   →   B! × (B+1) × (B+2) × ... × (A-1) ≡ -1 ( mod A)
>
> 因此只要求出 (B+1) × (B+2) × ... × (A-1) 在模数A下的逆即可求出B!
>
> 记 C = (B+1) × (B+2) × ... × (A-1) , 有 B! × C ≡ -1 ( mod A)
>
> B! ≡ -1×C (mod A) 知道 B! 后 B!%A的值也能计算出来

```python
import sympy
from Crypto.Util.number import * 

A1 = 21856963452461630437348278434191434000066076750419027493852463513469865262064340836613831066602300959772632397773487317560339056658299954464169264467234407
B1 = 21856963452461630437348278434191434000066076750419027493852463513469865262064340836613831066602300959772632397773487317560339056658299954464169264467140596
A2 = 16466113115839228119767887899308820025749260933863446888224167169857612178664139545726340867406790754560227516013796269941438076818194617030304851858418927
B2 = 16466113115839228119767887899308820025749260933863446888224167169857612178664139545726340867406790754560227516013796269941438076818194617030304851858351026
n = 85492663786275292159831603391083876175149354309327673008716627650718160585639723100793347534649628330416631255660901307533909900431413447524262332232659153047067908693481947121069070451562822417357656432171870951184673132554213690123308042697361969986360375060954702920656364144154145812838558365334172935931441424096270206140691814662318562696925767991937369782627908408239087358033165410020690152067715711112732252038588432896758405898709010342467882264362733
e = 0x1001
c = 75700883021669577739329316795450706204502635802310731477156998834710820770245219468703245302009998932067080383977560299708060476222089630209972629755965140317526034680452483360917378812244365884527186056341888615564335560765053550155758362271622330017433403027261127561225585912484777829588501213961110690451987625502701331485141639684356427316905122995759825241133872734362716041819819948645662803292418802204430874521342108413623635150475963121220095236776428

def myGetPrime(A, B):
    C = 1
    for i in range(B+1, A):
        C = (C*inverse(i, A))%A
    C = C*(A-1)%A
    return sympy.nextprime(C)

p = myGetPrime(A1, B1)
q = myGetPrime(A2, B2)
r = n//p//q
d = inverse(e, (p-1)*(q-1)*(r-1))
m = pow(c, d, n)
flag = long_to_bytes(m).decode()
print(flag) # RoarCTF{wm-CongrAtu1ation4-1t4-ju4t-A-bAby-R4A}
flag = flag.replace('RoarCTF', 'flag')
print(flag) # flag{wm-CongrAtu1ation4-1t4-ju4t-A-bAby-R4A}
```

------

### ♥ [Poor RSA](https://ce.pwnthebox.com/challenges?id=278)

附件解压缩后得到`public.key`和`flag.enc`。这题和[rsa3](#rsa3)很相似，编写`Python`代码进行求解，首先用`Crypto.PublicKey`的`RSA`模块来获取公钥对`<n, e>`，然后调用`requests`库在线请求 http://factordb.com 分解模数`n`，得到`p`和`q`，算出 `φ(n) = (p-1)(q-1)`，进而得到私钥的解密质数`d`，至此私钥已经拿到。用`Crypto.PublicKey`的`PKCS1_OAEP`模块生成私钥对`base64`解码后的`flag.enc`进行`RSA`解密，可以得到明文`afctf{R54_|5_$0_B0rin9}`，提交即可。

```python
import requests
from base64 import b64decode
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Util.number import inverse

def factorize(n):
    l = []
    url="http://factordb.com/api?query="+str(n)
    r = requests.get(url)
    data = r.json()
    for factor in data['factors']:
        l.append(int(factor[0]))
    return l

with open('public.key', 'rb') as f:
    public_key = RSA.importKey(f.read())

n = public_key.n
e = public_key.e
q, p = factorize(n)
d = inverse(e, (p-1)*(q-1))
key_info = RSA.construct((n, e, d, p, q))
key = RSA.importKey(key_info.exportKey())
private_key = PKCS1_OAEP.new(key)

with open('flag.enc', 'rb') as f:
    cipher_text = b64decode(f.read())
    flag = private_key.decrypt(cipher_text).decode()

print(flag) # afctf{R54_|5_$0_B0rin9}
```

------

### ♥ [Baby RSA](https://ce.pwnthebox.com/challenges?id=1060)

附件解压缩后得到`encrypt.py`和`secret`，其中`encrypt.py`源码如下：

```python
import hashlib
import sympy
from Crypto.Util.number import *

flag = 'GWHT{******}'
secret = '******'

assert(len(flag) == 38)

half = len(flag) / 2

flag1 = flag[:half]
flag2 = flag[half:]

secret_num = getPrime(1024) * bytes_to_long(secret)

p = sympy.nextprime(secret_num)
q = sympy.nextprime(p)

N = p * q

e = 0x10001

F1 = bytes_to_long(flag1)
F2 = bytes_to_long(flag2)

c1 = F1 + F2
c2 = pow(F1, 3) + pow(F2, 3)
assert(c2 < N)

m1 = pow(c1, e, N)
m2 = pow(c2, e, N)

output = open('secret', 'w')
output.write('N=' + str(N) + '\n')
output.write('m1=' + str(m1) + '\n')
output.write('m2=' + str(m2) + '\n')
output.close()
```

`secret`中的内容如下：

```python
N=636585149594574746909030160182690866222909256464847291783000651837227921337237899651287943597773270944384034858925295744880727101606841413640006527614873110651410155893776548737823152943797884729130149758279127430044739254000426610922834573094957082589539445610828279428814524313491262061930512829074466232633130599104490893572093943832740301809630847541592548921200288222432789208650949937638303429456468889100192613859073752923812454212239908948930178355331390933536771065791817643978763045030833712326162883810638120029378337092938662174119747687899484603628344079493556601422498405360731958162719296160584042671057160241284852522913676264596201906163
m1=90009974341452243216986938028371257528604943208941176518717463554774967878152694586469377765296113165659498726012712288670458884373971419842750929287658640266219686646956929872115782173093979742958745121671928568709468526098715927189829600497283118051641107305128852697032053368115181216069626606165503465125725204875578701237789292966211824002761481815276666236869005129138862782476859103086726091860497614883282949955023222414333243193268564781621699870412557822404381213804026685831221430728290755597819259339616650158674713248841654338515199405532003173732520457813901170264713085107077001478083341339002069870585378257051150217511755761491021553239
m2=487443985757405173426628188375657117604235507936967522993257972108872283698305238454465723214226871414276788912058186197039821242912736742824080627680971802511206914394672159240206910735850651999316100014691067295708138639363203596244693995562780286637116394738250774129759021080197323724805414668042318806010652814405078769738548913675466181551005527065309515364950610137206393257148357659666687091662749848560225453826362271704292692847596339533229088038820532086109421158575841077601268713175097874083536249006018948789413238783922845633494023608865256071962856581229890043896939025613600564283391329331452199062858930374565991634191495137939574539546
```

`p`和`q`是相近的两个素数，加密指数`e`是已知的，调用`requests`库在线请求 http://factordb.com 分解模数`n`可以得到`p`和`q`，接着算出 `φ(n) = (p-1)(q-1)`，进而得到私钥的解密质数`d`。`m1`和`m2`是已知的，可以求出`c1`和`c2`。接着利用`z3`约束求解器计算方程组，得到`F1`和`F2`，转换成字符串后拼接可得`GWHT{f709e0e2cfe7e530ca8972959a1033b2}`，提交报错，按照题目描述需要修改`GWHT`为`flag`，提交`flag{f709e0e2cfe7e530ca8972959a1033b2}`即可。这题的另一种解法见[[GWCTF 2019]BabyRSA](#[GWCTF 2019]BabyRSA)。

```python
import requests
from Crypto.Util.number import *
from z3 import *

def factorize(n):
    l = []
    url="http://factordb.com/api?query="+str(n)
    r = requests.get(url)
    data = r.json()
    for factor in data['factors']:
        l.append(int(factor[0]))
    return l

N = 636585149594574746909030160182690866222909256464847291783000651837227921337237899651287943597773270944384034858925295744880727101606841413640006527614873110651410155893776548737823152943797884729130149758279127430044739254000426610922834573094957082589539445610828279428814524313491262061930512829074466232633130599104490893572093943832740301809630847541592548921200288222432789208650949937638303429456468889100192613859073752923812454212239908948930178355331390933536771065791817643978763045030833712326162883810638120029378337092938662174119747687899484603628344079493556601422498405360731958162719296160584042671057160241284852522913676264596201906163
m1 = 90009974341452243216986938028371257528604943208941176518717463554774967878152694586469377765296113165659498726012712288670458884373971419842750929287658640266219686646956929872115782173093979742958745121671928568709468526098715927189829600497283118051641107305128852697032053368115181216069626606165503465125725204875578701237789292966211824002761481815276666236869005129138862782476859103086726091860497614883282949955023222414333243193268564781621699870412557822404381213804026685831221430728290755597819259339616650158674713248841654338515199405532003173732520457813901170264713085107077001478083341339002069870585378257051150217511755761491021553239
m2 = 487443985757405173426628188375657117604235507936967522993257972108872283698305238454465723214226871414276788912058186197039821242912736742824080627680971802511206914394672159240206910735850651999316100014691067295708138639363203596244693995562780286637116394738250774129759021080197323724805414668042318806010652814405078769738548913675466181551005527065309515364950610137206393257148357659666687091662749848560225453826362271704292692847596339533229088038820532086109421158575841077601268713175097874083536249006018948789413238783922845633494023608865256071962856581229890043896939025613600564283391329331452199062858930374565991634191495137939574539546
q, p = factorize(N)
e = 0x10001
d = inverse(e, (p-1)*(q-1))
c1 = pow(m1, d, N)
c2 = pow(m2, d, N)
F1, F2 = Int('F1'), Int('F2')
s = Solver()
s.add(F1+F2 == c1)
s.add(F1**3+F2**3 == c2)
if s.check() == sat:
    flag1 = long_to_bytes(s.model()[F1].as_long())
    flag2 = long_to_bytes(s.model()[F2].as_long())
    flag = (flag2+flag1).decode()
    print(flag) # GWHT{f709e0e2cfe7e530ca8972959a1033b2}
```

------

### [EasyRSA](https://ce.pwnthebox.com/challenges?id=1049)

附件解压缩后得到`.py`文件，源码如下：

```python
from Crypto.Util.number import getPrime,bytes_to_long
from sympy import Derivative
from fractions import Fraction
from secret import flag

p=getPrime(1024)
q=getPrime(1024)
e=65537·
n=p*q
z=Fraction(1,Derivative(arctan(p),p))-Fraction(1,Derivative(arth(q),q))
m=bytes_to_long(flag)
c=pow(m,e,n)
print(c,z,n)
'''
output:
7922547866857761459807491502654216283012776177789511549350672958101810281348402284098310147796549430689253803510994877420135537268549410652654479620858691324110367182025648788407041599943091386227543182157746202947099572389676084392706406084307657000104665696654409155006313203957292885743791715198781974205578654792123191584957665293208390453748369182333152809882312453359706147808198922916762773721726681588977103877454119043744889164529383188077499194932909643918696646876907327364751380953182517883134591810800848971719184808713694342985458103006676013451912221080252735948993692674899399826084848622145815461035
32115748677623209667471622872185275070257924766015020072805267359839059393284316595882933372289732127274076434587519333300142473010344694803885168557548801202495933226215437763329280242113556524498457559562872900811602056944423967403777623306961880757613246328729616643032628964072931272085866928045973799374711846825157781056965164178505232524245809179235607571567174228822561697888645968559343608375331988097157145264357626738141646556353500994924115875748198318036296898604097000938272195903056733565880150540275369239637793975923329598716003350308259321436752579291000355560431542229699759955141152914708362494482
15310745161336895413406690009324766200789179248896951942047235448901612351128459309145825547569298479821101249094161867207686537607047447968708758990950136380924747359052570549594098569970632854351825950729752563502284849263730127586382522703959893392329333760927637353052250274195821469023401443841395096410231843592101426591882573405934188675124326997277775238287928403743324297705151732524641213516306585297722190780088180705070359469719869343939106529204798285957516860774384001892777525916167743272419958572055332232056095979448155082465977781482598371994798871917514767508394730447974770329967681767625495394441
'''
```

编写`Python`代码求解得`BJD{Advanced_mathematics_is_too_hard!!!}`，提交`flag{Advanced_mathematics_is_too_hard!!!}`。

```python
import requests
from Crypto.Util.number import *

def factorize(n):
    l = []
    url="http://factordb.com/api?query="+str(n)
    r = requests.get(url)
    data = r.json()
    for factor in data['factors']:
        l.append(int(factor[0]))
    return l

c = 7922547866857761459807491502654216283012776177789511549350672958101810281348402284098310147796549430689253803510994877420135537268549410652654479620858691324110367182025648788407041599943091386227543182157746202947099572389676084392706406084307657000104665696654409155006313203957292885743791715198781974205578654792123191584957665293208390453748369182333152809882312453359706147808198922916762773721726681588977103877454119043744889164529383188077499194932909643918696646876907327364751380953182517883134591810800848971719184808713694342985458103006676013451912221080252735948993692674899399826084848622145815461035
z = 32115748677623209667471622872185275070257924766015020072805267359839059393284316595882933372289732127274076434587519333300142473010344694803885168557548801202495933226215437763329280242113556524498457559562872900811602056944423967403777623306961880757613246328729616643032628964072931272085866928045973799374711846825157781056965164178505232524245809179235607571567174228822561697888645968559343608375331988097157145264357626738141646556353500994924115875748198318036296898604097000938272195903056733565880150540275369239637793975923329598716003350308259321436752579291000355560431542229699759955141152914708362494482
n = 15310745161336895413406690009324766200789179248896951942047235448901612351128459309145825547569298479821101249094161867207686537607047447968708758990950136380924747359052570549594098569970632854351825950729752563502284849263730127586382522703959893392329333760927637353052250274195821469023401443841395096410231843592101426591882573405934188675124326997277775238287928403743324297705151732524641213516306585297722190780088180705070359469719869343939106529204798285957516860774384001892777525916167743272419958572055332232056095979448155082465977781482598371994798871917514767508394730447974770329967681767625495394441
e = 65537

p, q = factorize(n)
d = inverse(e, (p-1)*(q-1))
m = pow(c, d, n)
flag = long_to_bytes(m).decode()
print(flag) # BJD{Advanced_mathematics_is_too_hard!!!}
```

------

### ♥ [Power](https://ce.pwnthebox.com/challenges?id=1108)

附件解压缩后得到`.py`文件，源码如下：

```python
from Crypto.Util.number import *
import gmpy2
from secret import flag

p = getPrime(512)
q = getPrime(512)
n = p**4*q

e = 0x10001
phi = gmpy2.lcm(p - 1, q - 1)
d = gmpy2.invert(e, phi)
dp = d % (p - 1)
m = bytes_to_long(flag)
c = pow(m, e, n)
print "dp = " + str(dp)
print "c = " + str(c)

y = 449703347709287328982446812318870158230369688625894307953604074502413258045265502496365998383562119915565080518077360839705004058211784369656486678307007348691991136610142919372779782779111507129101110674559235388392082113417306002050124215904803026894400155194275424834577942500150410440057660679460918645357376095613079720172148302097893734034788458122333816759162605888879531594217661921547293164281934920669935417080156833072528358511807757748554348615957977663784762124746554638152693469580761002437793837094101338408017407251986116589240523625340964025531357446706263871843489143068620501020284421781243879675292060268876353250854369189182926055204229002568224846436918153245720514450234433170717311083868591477186061896282790880850797471658321324127334704438430354844770131980049668516350774939625369909869906362174015628078258039638111064842324979997867746404806457329528690722757322373158670827203350590809390932986616805533168714686834174965211242863201076482127152571774960580915318022303418111346406295217571564155573765371519749325922145875128395909112254242027512400564855444101325427710643212690768272048881411988830011985059218048684311349415764441760364762942692722834850287985399559042457470942580456516395188637916303814055777357738894264037988945951468416861647204658893837753361851667573185920779272635885127149348845064478121843462789367112698673780005436144393573832498203659056909233757206537514290993810628872250841862059672570704733990716282248839
g = 2
x = 2019*p**2 + 2020*p**3 + 2021*p**4
c1 = pow(g, x, y)
print "c1 = " + str(c1)

# dp = 3272293505696712831419859641571956066667516012597886098021642320155056349966612629986261146617139998624603483170466852538289743936225789351270153550594329
# c = 22524257534087703614496632403022329621384173069680778965750290698059674588465640878754707363673789674111671270645152584118206145007310499274423606886261969807360070526126452646719628307689968971699215841867636770320159256301550908771135042912287955209485328267670825390080110910391913063177323585204392804538642393453388536211144485389902591029350060800993352969569703901717308330574394200996651534321547814313195218895547718815009876393987398738932001924661338796059973950012706427109598830049455186171345179840564502215531573714428772608739268313985559628612004439028014417408631851880698512023740903181116906766066951473942201698375224240271523568161242951730224901227589413731025281719101368668617497947995579443908773425555177346524678673641140157885033923288401884
# c1 = 290707924192892686920253390955676600323331633814839708838347288502692494699485764473635783441705302268064111648851157070038783719749721994682837294625334517914882191486257362565066745587415388291939979195637720350919055988532145531805200483161599965215275808797976727969023747299578173497083532351976473770041800769265319548352841139802163279116490053292316399038329210043455932786945180855178341998049756983301499491011851026499269682821602212971062877270127451987836730083380463825717889123804613394241190839837791281657872259492589868751745327696030438893865069941066073554427558697972551085353027574529823439588670263047287131740802375738439636789806332323994866753085014446479034974063195632514803340511247735647970572837053148490258113394359072976858781060349776921428492973183958437965966963122069107876143476772436757554253049619918403996315720023020827394900507088006299225934263699192253079026440287311664705744424959801981503191480257138833694306501816837037995549817186335377411638035575004595417788588264823861850877111374085336446477943372458378834664678094751978400910288151519902977326995118727880223621964441498323865158898463327323193833062919619201107279964663654606753750042791368210261574897455830722232022689695292080269205470491791950839486861811469879413313773338916781857981641910031441448964144000585506870170898052132929034349451945051362244755750988705018897859238859476967568556992146975789444151432386692872801263000639711599152191790766776280
```

已知明文`c1`反求加密指数`x`，可以使用`sympy`库中的`discrete_log()`函数，依靠离散对数进行求解得到`x`。知道`x`的值后，可以使用`z3`约束求解器来解方程计算出`p`的值。

> 根据同余的性质，由 $a≡b(mod c*d)$ 可得 $a≡b(mod c)$和$a≡b(mod d)$
>
> 因此$m≡c^d(mod p^4*q)$可化简为$m≡c^d(mod p)$，这样就只需要知道 c, d, p 的值就能求解m，目前只有d未知。
>
> 动笔算算后会发现其实不需要知道 d 也能算出来。
>
> $c = m^emodn$
>
> $dp = d mod(p-1)$
>
> $c^{dp} = m^{e×dp}modn$
>
> $c^{dp}modp = m^{e×dp}modp$
>
> 又因为 $e×dp = e×d mod(p-1)=1mod(p-1)$
>
> 所以 $c^{dp}modp = m^{1+k×(p-1)}modp$
>
> 根据费马小定理有$m^{(p-1)}=1 mod p$，所以上式可转化为 $c^{dp}modp = mmodp$
>
> 因此在m < p时，pow(c, dp, p) = m mod p 可简化为 m = pow(c, dp, p)

编写`Python`代码求解得`GWHT{f372e52f2a0918d92267ff78ff1a9f09}`，提交`flag{f372e52f2a0918d92267ff78ff1a9f09}`即可。

```python
import sympy
from z3 import *
from Crypto.Util.number import long_to_bytes

y = 449703347709287328982446812318870158230369688625894307953604074502413258045265502496365998383562119915565080518077360839705004058211784369656486678307007348691991136610142919372779782779111507129101110674559235388392082113417306002050124215904803026894400155194275424834577942500150410440057660679460918645357376095613079720172148302097893734034788458122333816759162605888879531594217661921547293164281934920669935417080156833072528358511807757748554348615957977663784762124746554638152693469580761002437793837094101338408017407251986116589240523625340964025531357446706263871843489143068620501020284421781243879675292060268876353250854369189182926055204229002568224846436918153245720514450234433170717311083868591477186061896282790880850797471658321324127334704438430354844770131980049668516350774939625369909869906362174015628078258039638111064842324979997867746404806457329528690722757322373158670827203350590809390932986616805533168714686834174965211242863201076482127152571774960580915318022303418111346406295217571564155573765371519749325922145875128395909112254242027512400564855444101325427710643212690768272048881411988830011985059218048684311349415764441760364762942692722834850287985399559042457470942580456516395188637916303814055777357738894264037988945951468416861647204658893837753361851667573185920779272635885127149348845064478121843462789367112698673780005436144393573832498203659056909233757206537514290993810628872250841862059672570704733990716282248839
g = 2
c1 = 290707924192892686920253390955676600323331633814839708838347288502692494699485764473635783441705302268064111648851157070038783719749721994682837294625334517914882191486257362565066745587415388291939979195637720350919055988532145531805200483161599965215275808797976727969023747299578173497083532351976473770041800769265319548352841139802163279116490053292316399038329210043455932786945180855178341998049756983301499491011851026499269682821602212971062877270127451987836730083380463825717889123804613394241190839837791281657872259492589868751745327696030438893865069941066073554427558697972551085353027574529823439588670263047287131740802375738439636789806332323994866753085014446479034974063195632514803340511247735647970572837053148490258113394359072976858781060349776921428492973183958437965966963122069107876143476772436757554253049619918403996315720023020827394900507088006299225934263699192253079026440287311664705744424959801981503191480257138833694306501816837037995549817186335377411638035575004595417788588264823861850877111374085336446477943372458378834664678094751978400910288151519902977326995118727880223621964441498323865158898463327323193833062919619201107279964663654606753750042791368210261574897455830722232022689695292080269205470491791950839486861811469879413313773338916781857981641910031441448964144000585506870170898052132929034349451945051362244755750988705018897859238859476967568556992146975789444151432386692872801263000639711599152191790766776280
x = sympy.discrete_log(y,c1,g)
print(x) 
# x = 5535722692962580764045545539105119140941061679289569420988353884209653851308860058948669740693107863231179565602072744542122031789184119031739723962825082929025825322421201364211726001366490949760887367407718763255964735567971493859197583624076478457865073449246835949075135223468616834636386958924709024763349115622062848212445867198457630368236782421195503713107838541903829979118327675371550868768159024260793541264335548489228744367609071659968450303895118817379316060805148754136917043160175570565717388336822960389664337656603584425629662613786203920234401824957121860225422901340950436355650311392398098947210940
p = Int('p')
s = Solver()
s.add(2019*p**2+2020*p**3+2021*p**4 == x)
if s.check() == sat:
    p = s.model()[p].as_long()
    print(p)
# p = 7234391427703598327916723159145232922047935397302241978344500497098972068808591685717500902909442183573763273395725479516998210374727754578133587007330339
dp = 3272293505696712831419859641571956066667516012597886098021642320155056349966612629986261146617139998624603483170466852538289743936225789351270153550594329
c = 22524257534087703614496632403022329621384173069680778965750290698059674588465640878754707363673789674111671270645152584118206145007310499274423606886261969807360070526126452646719628307689968971699215841867636770320159256301550908771135042912287955209485328267670825390080110910391913063177323585204392804538642393453388536211144485389902591029350060800993352969569703901717308330574394200996651534321547814313195218895547718815009876393987398738932001924661338796059973950012706427109598830049455186171345179840564502215531573714428772608739268313985559628612004439028014417408631851880698512023740903181116906766066951473942201698375224240271523568161242951730224901227589413731025281719101368668617497947995579443908773425555177346524678673641140157885033923288401884
m = pow(c, dp, p)
flag = long_to_bytes(m).decode()
print(flag) # GWHT{f372e52f2a0918d92267ff78ff1a9f09}
```

------

### [happy](https://ce.pwnthebox.com/challenges?id=1065)

附件解压缩后内容如下：

```python
('c=', '0x7a7e031f14f6b6c3292d11a41161d2491ce8bcdc67ef1baa9eL')
('e=', '0x872a335')
#q + q*p^3 =1285367317452089980789441829580397855321901891350429414413655782431779727560841427444135440068248152908241981758331600586
#qp + q *p^2 = 1109691832903289208389283296592510864729403914873734836011311325874120780079555500202475594
```

动笔算算就可以知道`p`和`q`应该如何得知：

![](https://paper.tanyaodan.com/PwnTheBox/1065/1.jpg)

编写`Python`代码求解得`flag{happy_rsa_1}`， 提交即可。

```python
from libnum import *

c = 0x7a7e031f14f6b6c3292d11a41161d2491ce8bcdc67ef1baa9e
e = 0x872a335
A = 1285367317452089980789441829580397855321901891350429414413655782431779727560841427444135440068248152908241981758331600586
B = 1109691832903289208389283296592510864729403914873734836011311325874120780079555500202475594
C = gcd(A, B)
p = B//C
q = C//(1+p)
n = p*q
d = invmod(e, (p-1)*(q-1))
m = pow(c, d, n)
flag = n2s(m).decode()
print(flag) # flag{happy_rsa_1}
```

------

### ♥ [试试大数据分解](https://ce.pwnthebox.com/challenges?id=1079)

附件解压缩后得到以下文件：`flag.enc1`，`flag.enc2`，`flag.enc3`，`flag.enc4`，`public.pem`。编写`Python`进行求解，首先用`rsa`库来获取公钥对`<n, e>`，然后调用`requests`库在线请求 http://factordb.com 分解模数`n`，得到`p`和`q`，算出 `φ(n) = (p-1)(q-1)`，进而得到私钥的解密质数`d`，至此私钥已经拿到。打开`flag.enc1`后发现是`base64`加密的数据，需要`base64`解密后才能得到密文。用私钥对`flag.enc1-4`系列文件进行`rsa`解密，拼接后可以得到十六进制的`flag`，使用`bytes.fromhex()`进行转换，可以得到明文`flag{ISEC-Ir5WM_G4Afbvx_mSM_Ugf8zRAoMkYCPx}`，提交即可。

```python
import rsa
import requests
import base64

def factorize(n):
    l = []
    url="http://factordb.com/api?query="+str(n)
    r = requests.get(url)
    data = r.json()
    for factor in data['factors']:
        l.append(int(factor[0]))
    return l

with open('public.pem','rb') as f:
    public_key = rsa.PublicKey.load_pkcs1_openssl_pem(f.read())

n = public_key.n
e = public_key.e
q, p = factorize(n)
d = rsa.common.inverse(e, (p-1)*(q-1))
private_key = rsa.PrivateKey(n, e, d, p, q)
flag = ''
for i in range(1, 5):
    with open('flag.enc'+str(i),'rb') as f:
        c = base64.b64decode(f.read())
        flag += rsa.decrypt(c, private_key).decode('utf-8')
flag = bytes.fromhex(str(flag)).decode()
print(flag) # flag{ISEC-Ir5WM_G4Afbvx_mSM_Ugf8zRAoMkYCPx}
```

------

### [easy RSA](https://ce.pwnthebox.com/challenges?id=1118)

附件解压缩后得到以下源码：

```python
from Crypto.Util.number import *
from secret import flag

def add(a,b):
    if(a<b):
        a0 = str(b).encode()
        b0 = str(a).encode()
    else:
        a0 = str(a).encode()
        b0 = str(b).encode()
    ans = 0
    for i in range(len(a0)-len(b0)):
        ans = ans*10+a0[i]-48
    for i in range(len(b0)):
        ans = ans*10+(a0[i+len(a0)-len(b0)]+b0[i]+4)%10
    return ans

def mul(a,b):
    if(a<b):
        a0 = str(b).encode()
        b0 = str(a).encode()
    else:
        a0 = str(a).encode()
        b0 = str(b).encode()
    ans = 0
    for i in range(len(b0)):
        ans = ans*10+((a0[i+len(a0)-len(b0)]+2)*(b0[i]+2))%10
    return ans

m = bytes_to_long(flag)
e = 65537
p = getPrime(512)
q = getPrime(512)
n = p*q
c = pow(m,e,n)
print(add(p,q))
print(mul(p,q))
print(n)
print(c)
# 10399034381787849923326924881454040531711492204619924608227265350044149907274051734345037676383421545973249148286183660679683016947030357640361405556516408
# 6004903250672248020273453078045186428048881010508070095760634049430058892705564009054400328070528434060550830050010084328522605000400260581038846465000861
# 100457237809578238448997689590363740025639066957321554834356116114019566855447194466985968666777662995007348443263561295712530012665535942780881309520544097928921920784417859632308854225762469971326925931642031846400402355926637518199130760304347996335637140724757568332604740023000379088112644537238901495181
# 49042009464540753864186870038605696433949255281829439530955555557471951265762643642510403828448619593655860548966001304965902133517879714352191832895783859451396658166132732818620715968231113019681486494621363269268257297512939412717227009564539512793374347236183475339558666141579267673676878540943373877937
```

审计代码发现`add()`函数是将`a`和`b`相加但不进位，`mul()`函数是将`a`和`b`相乘但不进位。`pq0`用来保存当前循环所有可能的`(p, q)`，编写`Python`代码进行求解得到`flag{a4e3676e1e340581f7018972dd1905be}`。

```python
from Crypto.Util.number import *
from gmpy2 import *

a = 10399034381787849923326924881454040531711492204619924608227265350044149907274051734345037676383421545973249148286183660679683016947030357640361405556516408
b = 6004903250672248020273453078045186428048881010508070095760634049430058892705564009054400328070528434060550830050010084328522605000400260581038846465000861
n = 100457237809578238448997689590363740025639066957321554834356116114019566855447194466985968666777662995007348443263561295712530012665535942780881309520544097928921920784417859632308854225762469971326925931642031846400402355926637518199130760304347996335637140724757568332604740023000379088112644537238901495181
c = 49042009464540753864186870038605696433949255281829439530955555557471951265762643642510403828448619593655860548966001304965902133517879714352191832895783859451396658166132732818620715968231113019681486494621363269268257297512939412717227009564539512793374347236183475339558666141579267673676878540943373877937

def fun(k, p0, q0):
    if (p0 * q0) % (10 ** (k + 1)) == n % (10 ** (k + 1)):
        pq0.append((p0, q0))

a0 = str(a)
b0 = str(b)
pq0 = [(0, 0)]
for k in range(len(b0)):
    pq, pq0 = pq0, [(0, 0)]
    for i in range(10):
        for j in range(10):
            if (i + j) % 10 == int(a0[-k - 1]) and (i * j) % 10 == int(b0[-k - 1]):
                for (p, q) in pq:
                    p = (p + i * 10 ** k)
                    q = (q + j * 10 ** k)
                    fun(k, p, q)
#print(pq0)
p = int('1' + str(pq0[1][0]))
q = pq0[1][1]
#p=12092931636613623040737253079065768977037831274116990695362696899634198318309588587556607732878944639910799730236593646983127255905400637167879667181506829
#q=8307103755174226983699771812499382664784661030503034013965679561410051699975573257899430944515587916063550418050690024796566861042630720583592848475010689
phi = (p - 1) * (q - 1)
d = inverse(65537, phi)
m = pow(c, d, n)
flag = long_to_bytes(m).decode()
print(flag) # flag{a4e3676e1e340581f7018972dd1905be}
```

------

### [Feistival](https://ce.pwnthebox.com/challenges?id=1875)

附件解压缩后得到`cipher.txt`和`enc.py`两个文件，其中`enc.py`的源码如下：

```python
m, n = 21, 22
def f(word, key):
    out = ""
    for i in range(len(word)):
        out += chr(ord(word[i]) ^ key)
    return out

flag = open("flag.txt", "r").read()

L, R = flag[0:len(flag)//2], flag[len(flag)//2:]
x = "".join(chr(ord(f(R, m)[i]) ^ ord(L[i])) for i in range(len(L)))
y = f(R, 0)

L, R = y, x
x = "".join(chr(ord(f(R, n)[i]) ^ ord(L[i])) for i in range(len(L)))
y = f(R, 0)

ciphertext = x + y
ct = open("cipher.txt", "w")
ct.write(ciphertext)
ct.close()
```

编写`Python`代码进行异或操作，得到`KCTF{feistel_cipher_ftw}`。

```python
m, n = 21, 22
def f(word, key):
    out = ""
    for i in range(len(word)):
        out += chr(ord(word[i]) ^ key)
    return out

ct = open("cipher.txt", "r").read()
x, y = ct[0:len(ct)//2], ct[len(ct)//2:]
R = f(y, 0)
L = ''.join(chr(ord(f(R, n)[i]) ^ ord(x[i])) for i in range(len(x)))
y, x = L, R
R = f(y, 0)
L = ''.join(chr(ord(f(y, m)[i]) ^ ord(x[i])) for i in range(len(x)))
flag = L+R
print(flag) # KCTF{feistel_cipher_ftw}
```

------

### [A CRYPTO](https://ce.pwnthebox.com/challenges?id=1089)

题目描述如下：

> 4O595954494Q32515046324757595N534R52415653334357474R4N575955544R4O5N4Q46434S4O59474253464Q5N444R4Q51334557524O5N4S424944473542554O595N44534O324R49565746515532464O49345649564O464R4R494543504N35

字符串中发现字母`NOPQRS`，而`16`进制字符串中只有`ABCDEF`，将其依次进行替换即可，也可以使用`ROT13`编码解码得到：

```
4B595954494D32515046324757595A534E52415653334357474E4A575955544E4B5A4D46434F4B59474253464D5A444E4D51334557524B5A4F424944473542554B595A44534B324E49565746515532464B49345649564B464E4E494543504A35
```

将其转换为字符串，调用`bytes.fromhex()`函数得到：

```
KYYTIM2QPF2GWYZSNRAVS3CWGNJWYUTNKZMFCOKYGBSFMZDNMQ3EWRKZOBIDG5BUKYZDSK2NIVWFQU2FKI4VIVKFNNIECPJ5
```

调用`base64.b32decode()`函数进行`base32`解码得到：

```
V143Pytkc2lAYlV3SlRmVXQ9X0dVdmd6KEYpP3t4V29+MElXSER9TUEkPA==
```

调用`base64.b64decode()`函数进行`base64`解码得到：

```
W^7?+dsi@bUwJTfUt=_GUvgz(F)?{xWo~0IWHD}MA$<
```

调用`base64.b85decode()`函数进行`base85`解码得到：

```
flag{W0w_y0u_c4n_rea11y_enc0d1ng!}
```

------

### [base64?base64换表](https://ce.pwnthebox.com/challenges?id=1981)

[**CyberChef**](https://github.com/gchq/CyberChef)是英国情报机构政府通信总部（GCHQ）发布了一款新型的开源Web工具，为安全从业人员分析和解密数据提供了方便。

附件解压缩后的`.txt`文件包含以下信息：

```
25)G64I+9VQ-2D5S<51)=4LR>6U+,T%I2S)Q:6\R13D
```

选中`From Base64`，`Alphabet`为`Uuencoding: -_`，解码得到：

```
IRgYJKglMJEsqTIuK2ymK3AiK2qio2E9
```

选中`From Base64`，`Alphabet`为`ROT13:N-ZA-Mn-za-m0-9+/=`，解码得到：

```
TKKY{red_tea_is_so_good}
```

提交即可。

------

### [这是base??](https://ce.pwnthebox.com/challenges?id=1048)

附件解压缩后得到的`.txt`文件内容如下：

```
dict:{0: 'J', 1: 'K', 2: 'L', 3: 'M', 4: 'N', 5: 'O', 6: 'x', 7: 'y', 8: 'U', 9: 'V', 10: 'z', 11: 'A', 12: 'B', 13: 'C', 14: 'D', 15: 'E', 16: 'F', 17: 'G', 18: 'H', 19: '7', 20: '8', 21: '9', 22: 'P', 23: 'Q', 24: 'I', 25: 'a', 26: 'b', 27: 'c', 28: 'd', 29: 'e', 30: 'f', 31: 'g', 32: 'h', 33: 'i', 34: 'j', 35: 'k', 36: 'l', 37: 'm', 38: 'W', 39: 'X', 40: 'Y', 41: 'Z', 42: '0', 43: '1', 44: '2', 45: '3', 46: '4', 47: '5', 48: '6', 49: 'R', 50: 'S', 51: 'T', 52: 'n', 53: 'o', 54: 'p', 55: 'q', 56: 'r', 57: 's', 58: 't', 59: 'u', 60: 'v', 61: 'w', 62: '+', 63: '/', 64: '='}

chipertext:
FlZNfnF6Qol6e9w17WwQQoGYBQCgIkGTa9w3IQKw
```

编写`Python`代码进行求解，首先根据`dict`还原字符串得到`QkpEe0QwX1kwdV9rTm9XX1RoMXNfYjRzZV9tYXB9`，进行`base64`解码就能得到`flag`，根据题目描述提交`flag{D0_Y0u_kNoW_Th1s_b4se_map}`。

```python
from base64 import b64decode

dict = {0: 'J', 1: 'K', 2: 'L', 3: 'M', 4: 'N', 5: 'O', 6: 'x', 7: 'y', 8: 'U', 9: 'V', 10: 'z', 11: 'A', 12: 'B', 13: 'C', 14: 'D', 15: 'E', 16: 'F', 17: 'G', 18: 'H', 19: '7', 20: '8', 21: '9', 22: 'P', 23: 'Q', 24: 'I', 25: 'a', 26: 'b', 27: 'c', 28: 'd', 29: 'e', 30: 'f', 31: 'g', 32: 'h', 33: 'i', 34: 'j', 35: 'k', 36: 'l', 37: 'm', 38: 'W', 39: 'X', 40: 'Y', 41: 'Z', 42: '0', 43: '1', 44: '2', 45: '3', 46: '4', 47: '5', 48: '6', 49: 'R', 50: 'S', 51: 'T', 52: 'n', 53: 'o', 54: 'p', 55: 'q', 56: 'r', 57: 's', 58: 't', 59: 'u', 60: 'v', 61: 'w', 62: '+', 63: '/', 64: '='}
l = ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P','Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f','g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v','w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/']
chipertext = 'FlZNfnF6Qol6e9w17WwQQoGYBQCgIkGTa9w3IQKw'
s = ''
for x in chipertext:
    for k, v in dict.items():
        if x == v:
            s += l[k]
            break
print(s) # QkpEe0QwX1kwdV9rTm9XX1RoMXNfYjRzZV9tYXB9
flag = b64decode(s).decode()
print(flag) # BJD{D0_Y0u_kNoW_Th1s_b4se_map}
flag = flag.replace('BJD', 'flag')
print(flag) # flag{D0_Y0u_kNoW_Th1s_b4se_map}
```

------

### [RSA1](https://ce.pwnthebox.com/challenges?id=216)

附件解压缩后得到`.txt`文件，内容如下：

```
n1:
19869526284752088148939972354773627021440824533894698351471306514507074380861900899337746265984127203745503431163626292927194075402561350642083535708084259061401774944942303487139743123454945186086440751466038047046765032004612150970950848719541561716848748565998085623961955973126154183160606975887904970483534623474557395741848672541199629461822557952290762508281829069777324330110007319971403723161807001865803082053555594485323704726330461596656583724637363487772306707788883455850088111877624554616608867713229641664259944189686715214749600476932872970837208412021167149814446448621276008478685199626589491072103
n2:
25494295697375473321252857899221625231822688935999690596959123132795394181801545650716478462630917517506821455499594187037125131674991934561225560148196194018158902673788583445646149997813802656755830524568566221253331430322174085820622392657174862705225294401371342412006513883557841523218761694411840682545681595615026193508601218931383774737152556284656604091573294546995759637708895860241171374764821181665739070177811943750571655444733267642280846124366191147994563232179869914470170731679510812971919415202103015857987687003943346843882948365208988093225179089845716159576436292039301229587968394908153377614733
n3:
24083785064060535511405832100999131194723125484592241443513012423397355653850614506890799766453569227901046951201644550086548283776506959932283450074399478803879861810508053141216986657521156549846033127516719666165353558057348585298770026625402727254268738716111765712229988016409935512639504223436904404985662178706065468520653194859312444315980012906189755591458006421168438274937569567997346149935394749041225143388079047804446371550593668411818554928761054839047518144771287796898138519724264989403370698748387992284824609014990318797065771102162067784368870360937616207885202090285325524585099648483673921730461
e:
65537
c1:
6539804048047557815141482917417693725807559194770347972204604201835527457672990917777090485646244334945990407671840051209765314745265407945790748751926619881027320018791645830034051168775561447504658500779797243613196578253480984242951410622136704053385605780434319608065678532928890417999557902155066390955856957741474738673866210755503615696316729427644942191500200749714767228429390741528542442378680308285285581785700738948053282062582143368540424608248916941150853062270786707125180149849561160498338732304909604269485281529049915406127174551318245378003521902473791390417452836137175877037114618874373135449373
c2:
24711937469673074548897423145692836896076785324540777350486490402150426688364046647173270084375613193777298127411165102117880509907862180384455451137118948899229218560975415693135785055187619528235788445407286043790074139893082980121487516980182720228252348348341253668878576678033766820948782611431802143288245370696180224257916404836720405563643274847074280484462792856619595395342734972129413376568485370109868430749664814544057733196926907746147944441351103267663544158693913681996381415022972214194508614869558267408364583458776356280657582621319898467454650942923480777976181539825363542798226112640816571625085
c3:
15194896408422329349097203922984853539796539042396962682928825971639634289915198422526326699329221743935756075832684757156104224403096789177888915888790372996186864868789904311364598941890579199097275770150167924962104169815778269068808139194191084491234769445814413965811841852418714420595102451833188863426675614856326169365067436560482404384456791121052021790125294462638764703163172896622687008944536337112985412723093557710269680319322392550882893019792045009403259290732356071247859307688862775413212889975009217976243917113012068908828077088593164525817183467671913093855316041182221108152893068637787554643712
```

题目给定加密指数`e`和多组`n`和`c`。循环遍历所有的`n`，两两计算找最大公约数，从而得到`p1`，`p2`，`p3`和`q1`，`q2`，`q3`，然后是`RSA`常规求解。编写`Python`代码求解，得到`m1`，`m2`，`m3`后拼接，提交`flag{n0_CRT_4ndnO_facTOR_db_bUT_gcD_1s_r1ght!}`即可。

```python
from libnum import *

n1 = 19869526284752088148939972354773627021440824533894698351471306514507074380861900899337746265984127203745503431163626292927194075402561350642083535708084259061401774944942303487139743123454945186086440751466038047046765032004612150970950848719541561716848748565998085623961955973126154183160606975887904970483534623474557395741848672541199629461822557952290762508281829069777324330110007319971403723161807001865803082053555594485323704726330461596656583724637363487772306707788883455850088111877624554616608867713229641664259944189686715214749600476932872970837208412021167149814446448621276008478685199626589491072103
n2 = 25494295697375473321252857899221625231822688935999690596959123132795394181801545650716478462630917517506821455499594187037125131674991934561225560148196194018158902673788583445646149997813802656755830524568566221253331430322174085820622392657174862705225294401371342412006513883557841523218761694411840682545681595615026193508601218931383774737152556284656604091573294546995759637708895860241171374764821181665739070177811943750571655444733267642280846124366191147994563232179869914470170731679510812971919415202103015857987687003943346843882948365208988093225179089845716159576436292039301229587968394908153377614733
n3 = 24083785064060535511405832100999131194723125484592241443513012423397355653850614506890799766453569227901046951201644550086548283776506959932283450074399478803879861810508053141216986657521156549846033127516719666165353558057348585298770026625402727254268738716111765712229988016409935512639504223436904404985662178706065468520653194859312444315980012906189755591458006421168438274937569567997346149935394749041225143388079047804446371550593668411818554928761054839047518144771287796898138519724264989403370698748387992284824609014990318797065771102162067784368870360937616207885202090285325524585099648483673921730461
e = 65537
c1 = 6539804048047557815141482917417693725807559194770347972204604201835527457672990917777090485646244334945990407671840051209765314745265407945790748751926619881027320018791645830034051168775561447504658500779797243613196578253480984242951410622136704053385605780434319608065678532928890417999557902155066390955856957741474738673866210755503615696316729427644942191500200749714767228429390741528542442378680308285285581785700738948053282062582143368540424608248916941150853062270786707125180149849561160498338732304909604269485281529049915406127174551318245378003521902473791390417452836137175877037114618874373135449373
c2 = 24711937469673074548897423145692836896076785324540777350486490402150426688364046647173270084375613193777298127411165102117880509907862180384455451137118948899229218560975415693135785055187619528235788445407286043790074139893082980121487516980182720228252348348341253668878576678033766820948782611431802143288245370696180224257916404836720405563643274847074280484462792856619595395342734972129413376568485370109868430749664814544057733196926907746147944441351103267663544158693913681996381415022972214194508614869558267408364583458776356280657582621319898467454650942923480777976181539825363542798226112640816571625085
c3 = 15194896408422329349097203922984853539796539042396962682928825971639634289915198422526326699329221743935756075832684757156104224403096789177888915888790372996186864868789904311364598941890579199097275770150167924962104169815778269068808139194191084491234769445814413965811841852418714420595102451833188863426675614856326169365067436560482404384456791121052021790125294462638764703163172896622687008944536337112985412723093557710269680319322392550882893019792045009403259290732356071247859307688862775413212889975009217976243917113012068908828077088593164525817183467671913093855316041182221108152893068637787554643712

n = [n1, n2, n3]
c = [c1, c2, c3]
p = [0, 0, 0]
for i in range(len(n)):
    for j in range(len(n)):
        if i!=j and gcd(n[i], n[j])!=1:
            p[i] = gcd(n[i], n[j])
            break

q = [n[i]//p[i] for i in range(len(n))]
d = [invmod(e, (p[i]-1)*(q[i]-1)) for i in range(len(p))]
m = [pow(c[i], d[i], n[i]) for i in range(len(n))]
flag = [n2s(x).decode() for x in m]
# ['first part of the flag :flag{n0_CRT_4nd', 'second part of the flag :nO_facTOR_db_', 'third part of the flag: bUT_gcD_1s_r1ght!}']
flag = ''.join(x[x.find(':')+1:] for x in flag).replace(' ', '')
print(flag) # flag{n0_CRT_4ndnO_facTOR_db_bUT_gcD_1s_r1ght!}
```

------

## CTFShow

### crypto4

打开`.txt`文件后发现给出了`p=447685307`, `q=2037`, `e=17`, 求`d`, `flag{d}`。编写`Python`代码即可得到`flag`：`flag{53616899001}`。

```python
from gmpy2 import *

p = mpz(447685307)
q = mpz(2037)
e = mpz(17)
phi_n = (p-1)*(q-1) 
d = invert(e, phi_n)
flag = 'flag{' + str(d) + '}'
print(flag)
```

------

### crypto5

打开`.txt`文件后发现给出`p=447685307`, `q=2037`, `e=17`, `c=704796792`, 求`m`, `flag{m}`。

编写`Python`代码即可得到`flag`：`flag{904332399012}`。

```python
from gmpy2 import *

p = mpz(447685307)
q = mpz(2037)
e = mpz(17)
c = mpz(704796792)
n = p*q
phi_n = (p-1)*(q-1)
d = invert(e, phi_n)
m = powmod(c, d, n)  # m = c^d%n
flag = 'flag{' + str(m) + '}' 
print(flag)
```

------

### easyrsa1

打开`.txt`文件后发现给出`e=65537`, `n=1455925529734358105461406532259911790807347616464991065301847`, `c=69380371057914246192606760686152233225659503366319332065009`, 求`m`。

使用http://www.factordb.com/对`n=1455925529734358105461406532259911790807347616464991065301847`进行整数分解，可以得到：

```python
p = 1201147059438530786835365194567
q = 1212112637077862917192191913841
```

编写`Python`代码即可得到`flag`：`flag{fact0r_sma11_N}`。

```python
from gmpy2 import *
import binascii

e = mpz(65537)
n = mpz(1455925529734358105461406532259911790807347616464991065301847)
c = mpz(69380371057914246192606760686152233225659503366319332065009)
p = mpz(1201147059438530786835365194567)
q = mpz(1212112637077862917192191913841)
phi_n = (p-1)*(q-1)
d = invert(e, phi_n) 
m = powmod(c, d, n)  # m = c^d%n
flag = binascii.unhexlify(hex(m)[2:]).decode('utf-8')
print(flag) # flag{fact0r_sma11_N}
```

------

### easyrsa2

打开`.txt`文件后发现以下信息：

```python
e = 65537
n = 23686563925537577753047229040754282953352221724154495390687358877775380147605152455537988563490716943872517593212858326146811511103311865753018329109314623702207073882884251372553225986112006827111351501044972239272200616871716325265416115038890805114829315111950319183189591283821793237999044427887934536835813526748759612963103377803089900662509399569819785571492828112437312659229879806168758843603248823629821851053775458651933952183988482163950039248487270453888288427540305542824179951734412044985364866532124803746008139763081886781361488304666575456680411806505094963425401175510416864929601220556158569443747
c = 1627484142237897613944607828268981193911417408064824540711945192035649088104133038147400224070588410335190662682231189997580084680424209495303078061205122848904648319219646588720994019249279863462981015329483724747823991513714172478886306703290044871781158393304147301058706003793357846922086994952763485999282741595204008663847963539422096343391464527068599046946279309037212859931303335507455146001390326550668531665493245293839009832468668390820282664984066399051403227990068032226382222173478078505888238749583237980643698405005689247922901342204142833875409505180847943212126302482358445768662608278731750064815
```

使用http://www.factordb.com/对`n`进行整数分解得到：

```python
p = 149751992878258417619955913803349588855907883795437275015624379454686823076475394292360761230383018058515386650339444595246524276345367505681814522035068825010950620582957883108812048922184886717309007677307472277565963907119402324227023856527902596769190955018836727291623263893333224367236239361837356140243
q = 158171944628434297901073909637722153795182500207437382406943949068719041821522249518991083268349210029996372436712077867872196821502572326830142173784785697378334976861590406851563704862868317200039579262508714027560242806981225550090918382144776028695390747339519174603519115397094447596926441933797085906929
```

编写`Python`代码即可得到`flag`：`flag{m0_bv_hv_sv}`。

```python
from gmpy2 import *
import binascii

e = mpz(65537)
n = mpz(23686563925537577753047229040754282953352221724154495390687358877775380147605152455537988563490716943872517593212858326146811511103311865753018329109314623702207073882884251372553225986112006827111351501044972239272200616871716325265416115038890805114829315111950319183189591283821793237999044427887934536835813526748759612963103377803089900662509399569819785571492828112437312659229879806168758843603248823629821851053775458651933952183988482163950039248487270453888288427540305542824179951734412044985364866532124803746008139763081886781361488304666575456680411806505094963425401175510416864929601220556158569443747)
c = mpz(1627484142237897613944607828268981193911417408064824540711945192035649088104133038147400224070588410335190662682231189997580084680424209495303078061205122848904648319219646588720994019249279863462981015329483724747823991513714172478886306703290044871781158393304147301058706003793357846922086994952763485999282741595204008663847963539422096343391464527068599046946279309037212859931303335507455146001390326550668531665493245293839009832468668390820282664984066399051403227990068032226382222173478078505888238749583237980643698405005689247922901342204142833875409505180847943212126302482358445768662608278731750064815)
p = mpz(149751992878258417619955913803349588855907883795437275015624379454686823076475394292360761230383018058515386650339444595246524276345367505681814522035068825010950620582957883108812048922184886717309007677307472277565963907119402324227023856527902596769190955018836727291623263893333224367236239361837356140243)
q = mpz(158171944628434297901073909637722153795182500207437382406943949068719041821522249518991083268349210029996372436712077867872196821502572326830142173784785697378334976861590406851563704862868317200039579262508714027560242806981225550090918382144776028695390747339519174603519115397094447596926441933797085906929)
phi_n = (p-1)*(q-1)
d = invert(e, phi_n) 
m = powmod(c, d, n)  # m = c^d%n
flag = binascii.unhexlify(hex(m)[2:]).decode('utf-8')
print(flag) # flag{m0_bv_hv_sv}
```

------

### easyrsa3

打开`.txt`文件后发现以下信息：

```python
e = 797
n = 15944475431088053285580229796309956066521520107276817969079550919586650535459242543036143360865780730044733026945488511390818947440767542658956272380389388112372084760689777141392370253850735307578445988289714647332867935525010482197724228457592150184979819463711753058569520651205113690397003146105972408452854948512223702957303406577348717348753106868356995616116867724764276234391678899662774272419841876652126127684683752880568407605083606688884120054963974930757275913447908185712204577194274834368323239143008887554264746068337709465319106886618643849961551092377843184067217615903229068010117272834602469293571
c = 11157593264920825445770016357141996124368529899750745256684450189070288181107423044846165593218013465053839661401595417236657920874113839974471883493099846397002721270590059414981101686668721548330630468951353910564696445509556956955232059386625725883038103399028010566732074011325543650672982884236951904410141077728929261477083689095161596979213961494716637502980358298944316636829309169794324394742285175377601826473276006795072518510850734941703194417926566446980262512429590253643561098275852970461913026108090608491507300365391639081555316166526932233787566053827355349022396563769697278239577184503627244170930

e = 521
n = 15944475431088053285580229796309956066521520107276817969079550919586650535459242543036143360865780730044733026945488511390818947440767542658956272380389388112372084760689777141392370253850735307578445988289714647332867935525010482197724228457592150184979819463711753058569520651205113690397003146105972408452854948512223702957303406577348717348753106868356995616116867724764276234391678899662774272419841876652126127684683752880568407605083606688884120054963974930757275913447908185712204577194274834368323239143008887554264746068337709465319106886618643849961551092377843184067217615903229068010117272834602469293571
c = 6699274351853330023117840396450375948797682409595670560999898826038378040157859939888021861338431350172193961054314487476965030228381372659733197551597730394275360811462401853988404006922710039053586471244376282019487691307865741621991977539073601368892834227191286663809236586729196876277005838495318639365575638989137572792843310915220039476722684554553337116930323671829220528562573169295901496437858327730504992799753724465760161805820723578087668737581704682158991028502143744445435775458296907671407184921683317371216729214056381292474141668027801600327187443375858394577015394108813273774641427184411887546849
```

可以观察到使用了相同的模数n，但是用了不同的密钥e和c来加密同一信息m，这是一种共模攻击。

```python
c1 = m^e1 % n
c2 = m^e2 % n
# 根据扩展的欧几里得算法，可以得到
e1*s1 + e2*s2 = gcd(e1, e2) = 1 # s1、s2皆为整数，但是一正一负
(c1^s1*c2^s2)%n = ((m^e1%n)^s1*(m^e2%n)^s2)%n
//化简为((m^e1)^s1*(m^e2)^s2)%n = (m^(e1^s1+e2^s2))%n
(c1^s1*c2^s2)%n = m%n
# 最后化简可得
c1^s1*c2^s2 = m
```

编写`Python`代码即可得到`flag`：` flag{sh4r3_N}`。

```python
from gmpy2 import *
import binascii

n = mpz(15944475431088053285580229796309956066521520107276817969079550919586650535459242543036143360865780730044733026945488511390818947440767542658956272380389388112372084760689777141392370253850735307578445988289714647332867935525010482197724228457592150184979819463711753058569520651205113690397003146105972408452854948512223702957303406577348717348753106868356995616116867724764276234391678899662774272419841876652126127684683752880568407605083606688884120054963974930757275913447908185712204577194274834368323239143008887554264746068337709465319106886618643849961551092377843184067217615903229068010117272834602469293571)
e1 = mpz(797)
c1 = mpz(11157593264920825445770016357141996124368529899750745256684450189070288181107423044846165593218013465053839661401595417236657920874113839974471883493099846397002721270590059414981101686668721548330630468951353910564696445509556956955232059386625725883038103399028010566732074011325543650672982884236951904410141077728929261477083689095161596979213961494716637502980358298944316636829309169794324394742285175377601826473276006795072518510850734941703194417926566446980262512429590253643561098275852970461913026108090608491507300365391639081555316166526932233787566053827355349022396563769697278239577184503627244170930)
e2 = mpz(521)
c2 = mpz(6699274351853330023117840396450375948797682409595670560999898826038378040157859939888021861338431350172193961054314487476965030228381372659733197551597730394275360811462401853988404006922710039053586471244376282019487691307865741621991977539073601368892834227191286663809236586729196876277005838495318639365575638989137572792843310915220039476722684554553337116930323671829220528562573169295901496437858327730504992799753724465760161805820723578087668737581704682158991028502143744445435775458296907671407184921683317371216729214056381292474141668027801600327187443375858394577015394108813273774641427184411887546849)
s = gcdext(e1, e2)  #扩展欧几里得算法
m1 = powmod(c1, s[1], n)
m2 = powmod(c2, s[2], n)
m = (m1*m2)%n
flag = binascii.unhexlify(hex(m)[2:]).decode('utf-8')
print(flag) # flag{sh4r3_N}
```

------

### easyrsa4

打开`.txt`文件后发现以下信息：

```python
e = 3
n = 18970053728616609366458286067731288749022264959158403758357985915393383117963693827568809925770679353765624810804904382278845526498981422346319417938434861558291366738542079165169736232558687821709937346503480756281489775859439254614472425017554051177725143068122185961552670646275229009531528678548251873421076691650827507829859299300272683223959267661288601619845954466365134077547699819734465321345758416957265682175864227273506250707311775797983409090702086309946790711995796789417222274776215167450093735639202974148778183667502150202265175471213833685988445568819612085268917780718945472573765365588163945754761
c = 150409620528139732054476072280993764527079006992643377862720337847060335153837950368208902491767027770946661
```

题中`e=3`相对于`n`和`c`来说极小，故可得知是低加密指数攻击。

- 当$$m^{3} < n$$时，$$C = m^{3}$$，即`m`的值可以由`C`开三次方得到。

- 当$$m^{3} > n$$时，$$C = m^{3} - i * n$$，即$$m = \sqrt[3]{C + i * n}$$，只要找到那个能让`c+i*n`开三次方的`i`就能得到`m`。

编写`Python`代码即可得到`flag`：`flag{Sm4ll_eee}`。

```python
from gmpy2 import *
import binascii

e = mpz(3)
n = mpz(18970053728616609366458286067731288749022264959158403758357985915393383117963693827568809925770679353765624810804904382278845526498981422346319417938434861558291366738542079165169736232558687821709937346503480756281489775859439254614472425017554051177725143068122185961552670646275229009531528678548251873421076691650827507829859299300272683223959267661288601619845954466365134077547699819734465321345758416957265682175864227273506250707311775797983409090702086309946790711995796789417222274776215167450093735639202974148778183667502150202265175471213833685988445568819612085268917780718945472573765365588163945754761)
c = mpz(150409620528139732054476072280993764527079006992643377862720337847060335153837950368208902491767027770946661)

i = 0
while True:
    t = iroot((c+i*n), 3)
    if t[1] == True:
        m = t[0]
        break
    i += 1

flag = binascii.unhexlify(hex(m)[2:]).decode('utf-8')
print(flag) # flag{Sm4ll_eee}
```

------

### easyrsa5

打开`.txt`文件后发现以下信息：

```python
e = 284100478693161642327695712452505468891794410301906465434604643365855064101922252698327584524956955373553355814138784402605517536436009073372339264422522610010012877243630454889127160056358637599704871937659443985644871453345576728414422489075791739731547285138648307770775155312545928721094602949588237119345
n = 468459887279781789188886188573017406548524570309663876064881031936564733341508945283407498306248145591559137207097347130203582813352382018491852922849186827279111555223982032271701972642438224730082216672110316142528108239708171781850491578433309964093293907697072741538649347894863899103340030347858867705231
c = 350429162418561525458539070186062788413426454598897326594935655762503536409897624028778814302849485850451243934994919418665502401195173255808119461832488053305530748068788500746791135053620550583421369214031040191188956888321397450005528879987036183922578645840167009612661903399312419253694928377398939392827
```

使用http://www.factordb.com/对`n`进行整数分解得到：

```python
p = 18489327396055733397216193236128138397765028288613793035021305599301380136673327250408422592244732819005905679957567952974717041052102175277835219391448987
q = 25336772790324258952117622504537139442881120269760383961991795601846585772802865528712760553670210656524156997774484665833049279421936394718949688217533213
```

编写`Python`代码即可得到`flag`：`flag{very_biiiiig_e}`。

```python
from gmpy2 import *
import binascii

e = mpz(284100478693161642327695712452505468891794410301906465434604643365855064101922252698327584524956955373553355814138784402605517536436009073372339264422522610010012877243630454889127160056358637599704871937659443985644871453345576728414422489075791739731547285138648307770775155312545928721094602949588237119345)
n = mpz(468459887279781789188886188573017406548524570309663876064881031936564733341508945283407498306248145591559137207097347130203582813352382018491852922849186827279111555223982032271701972642438224730082216672110316142528108239708171781850491578433309964093293907697072741538649347894863899103340030347858867705231)
c = mpz(350429162418561525458539070186062788413426454598897326594935655762503536409897624028778814302849485850451243934994919418665502401195173255808119461832488053305530748068788500746791135053620550583421369214031040191188956888321397450005528879987036183922578645840167009612661903399312419253694928377398939392827)
p = mpz(18489327396055733397216193236128138397765028288613793035021305599301380136673327250408422592244732819005905679957567952974717041052102175277835219391448987)
q = mpz(25336772790324258952117622504537139442881120269760383961991795601846585772802865528712760553670210656524156997774484665833049279421936394718949688217533213)
phi_n = (p-1)*(q-1)
d = invert(e, phi_n) 
m = powmod(c, d, n)  # m = c^d%n
flag = binascii.unhexlify(hex(m)[2:]).decode('utf-8')
print(flag) # flag{very_biiiiig_e}
```

------

### easyrsa6

本题给出了一个`.py`文件，源码如下：

```python
import gmpy2,libnum
from Crypto.Util.number import getPrime
from secret import flag

e = 0x10001
p = getPrime(1024)
q = gmpy2.next_prime(p)
n = p * q
print("n =",n)
m = libnum.s2n(flag)
c = pow(m,e,n)
print("c =", c)

# n = 26737417831000820542131903300607349805884383394154602685589253691058592906354935906805134188533804962897170211026684453428204518730064406526279112572388086653330354347467824800159214965211971007509161988095657918569122896402683130342348264873834798355125176339737540844380018932257326719850776549178097196650971801959829891897782953799819540258181186971887122329746532348310216818846497644520553218363336194855498009339838369114649453618101321999347367800581959933596734457081762378746706371599215668686459906553007018812297658015353803626409606707460210905216362646940355737679889912399014237502529373804288304270563
# c = 18343406988553647441155363755415469675162952205929092244387144604220598930987120971635625205531679665588524624774972379282080365368504475385813836796957675346369136362299791881988434459126442243685599469468046961707420163849755187402196540739689823324440860766040276525600017446640429559755587590377841083082073283783044180553080312093936655426279610008234238497453986740658015049273023492032325305925499263982266317509342604959809805578180715819784421086649380350482836529047761222588878122181300629226379468397199620669975860711741390226214613560571952382040172091951384219283820044879575505273602318856695503917257
```

可以看到`p`和`q`很接近，使用http://www.factordb.com/对`n`进行整数分解得到：

```python
p = 163515803000813412334620775647541652549604895368507102613553057136855632963322853570924931001138446030409251690646645635800254129997200577719209532684847732809399187385176309169421205833279943214621695444496660249881675974141488357432373412184140130503562295159152949524373214358417567189638680209172147385163
q = 163515803000813412334620775647541652549604895368507102613553057136855632963322853570924931001138446030409251690646645635800254129997200577719209532684847732809399187385176309169421205833279943214621695444496660249881675974141488357432373412184140130503562295159152949524373214358417567189638680209172147385801
```

编写`Python`代码即可得到`flag`：`flag{p&q_4re_t00_c1o5ed}`。

```python
from gmpy2 import *
import binascii

e = mpz(0x10001)
n = mpz(26737417831000820542131903300607349805884383394154602685589253691058592906354935906805134188533804962897170211026684453428204518730064406526279112572388086653330354347467824800159214965211971007509161988095657918569122896402683130342348264873834798355125176339737540844380018932257326719850776549178097196650971801959829891897782953799819540258181186971887122329746532348310216818846497644520553218363336194855498009339838369114649453618101321999347367800581959933596734457081762378746706371599215668686459906553007018812297658015353803626409606707460210905216362646940355737679889912399014237502529373804288304270563)
p = mpz(163515803000813412334620775647541652549604895368507102613553057136855632963322853570924931001138446030409251690646645635800254129997200577719209532684847732809399187385176309169421205833279943214621695444496660249881675974141488357432373412184140130503562295159152949524373214358417567189638680209172147385163)
q = mpz(163515803000813412334620775647541652549604895368507102613553057136855632963322853570924931001138446030409251690646645635800254129997200577719209532684847732809399187385176309169421205833279943214621695444496660249881675974141488357432373412184140130503562295159152949524373214358417567189638680209172147385801)
c = mpz(18343406988553647441155363755415469675162952205929092244387144604220598930987120971635625205531679665588524624774972379282080365368504475385813836796957675346369136362299791881988434459126442243685599469468046961707420163849755187402196540739689823324440860766040276525600017446640429559755587590377841083082073283783044180553080312093936655426279610008234238497453986740658015049273023492032325305925499263982266317509342604959809805578180715819784421086649380350482836529047761222588878122181300629226379468397199620669975860711741390226214613560571952382040172091951384219283820044879575505273602318856695503917257)
phi_n = (p-1)*(q-1)
d = invert(e, phi_n) 
m = powmod(c, d, n)  # m = c^d%n
flag = binascii.unhexlify(hex(m)[2:]).decode('utf-8')
print(flag) # flag{p&q_4re_t00_c1o5ed}
```

------

### ♥ easyrsa7

附件给了一个`.txt`文件，内容如下：

```python
e = 0x10001
p>>128<<128 = 0xd1c520d9798f811e87f4ff406941958bab8fc24b19a32c3ad89b0b73258ed3541e9ca696fd98ce15255264c39ae8c6e8db5ee89993fa44459410d30a0a8af700ae3aee8a9a1d6094f8c757d3b79a8d1147e85be34fb260a970a52826c0a92b46cefb5dfaf2b5a31edf867f8d34d2222900000000000000000000000000000000
n = 0x79e0bf9b916e59286163a1006f8cefd4c1b080387a6ddb98a3f3984569a4ebb48b22ac36dff7c98e4ebb90ffdd9c07f53a20946f57634fb01f4489fcfc8e402865e152820f3e2989d4f0b5ef1fb366f212e238881ea1da017f754d7840fc38236edba144674464b661d36cdaf52d1e5e7c3c21770c5461a7c1bc2db712a61d992ebc407738fc095cd8b6b64e7e532187b11bf78a8d3ddf52da6f6a67c7e88bef5563cac1e5ce115f3282d5ff9db02278859f63049d1b934d918f46353fea1651d96b2ddd874ec8f1e4b9d487d8849896d1c21fb64029f0d6f47e560555b009b96bfd558228929a6cdf3fb6d47a956829fb1e638fcc1bdfad4ec2c3590dea1ed3
c = 0x1b2b4f9afed5fb5f9876757e959c183c2381ca73514b1918d2f123e386bebe9832835350f17ac439ac570c9b2738f924ef49afea02922981fad702012d69ea3a3c7d1fc8efc80e541ca2622d7741090b9ccd590906ac273ffcc66a7b8c0d48b7d62d6cd6dd4cd75747c55aac28f8be3249eb255d8750482ebf492692121ab4b27b275a0f69b15baef20bf812f3cbf581786128b51694331be76f80d6fb1314d8b280eaa16c767821b9c2ba05dfde5451feef22ac3cb3dfbc88bc1501765506f0c05045184292a75c475486b680f726f44ef8ddfe3c48f75bb03c8d44198ac70e6b7c885f53000654db22c8cee8eb4f65eaeea2da13887aaf53d8c254d2945691
```

已知`p`的高位，低`128`位数据丢失，不要慌问题不大，可以用`sagemath`来恢复数据。

```bash
sudo apt-get install sagemath # 安装sagemath
sage # 直接用
```

得到`p`后就是常规`RSA`题求解啦，运行得到`flag{Kn0wn_Hi9h_Bit5}`，提交即可。

```python
import binascii
n = 0x79e0bf9b916e59286163a1006f8cefd4c1b080387a6ddb98a3f3984569a4ebb48b22ac36dff7c98e4ebb90ffdd9c07f53a20946f57634fb01f4489fcfc8e402865e152820f3e2989d4f0b5ef1fb366f212e238881ea1da017f754d7840fc38236edba144674464b661d36cdaf52d1e5e7c3c21770c5461a7c1bc2db712a61d992ebc407738fc095cd8b6b64e7e532187b11bf78a8d3ddf52da6f6a67c7e88bef5563cac1e5ce115f3282d5ff9db02278859f63049d1b934d918f46353fea1651d96b2ddd874ec8f1e4b9d487d8849896d1c21fb64029f0d6f47e560555b009b96bfd558228929a6cdf3fb6d47a956829fb1e638fcc1bdfad4ec2c3590dea1ed3
c = 0x1b2b4f9afed5fb5f9876757e959c183c2381ca73514b1918d2f123e386bebe9832835350f17ac439ac570c9b2738f924ef49afea02922981fad702012d69ea3a3c7d1fc8efc80e541ca2622d7741090b9ccd590906ac273ffcc66a7b8c0d48b7d62d6cd6dd4cd75747c55aac28f8be3249eb255d8750482ebf492692121ab4b27b275a0f69b15baef20bf812f3cbf581786128b51694331be76f80d6fb1314d8b280eaa16c767821b9c2ba05dfde5451feef22ac3cb3dfbc88bc1501765506f0c05045184292a75c475486b680f726f44ef8ddfe3c48f75bb03c8d44198ac70e6b7c885f53000654db22c8cee8eb4f65eaeea2da13887aaf53d8c254d2945691
e = 0x10001
p_fake = 0xd1c520d9798f811e87f4ff406941958bab8fc24b19a32c3ad89b0b73258ed3541e9ca696fd98ce15255264c39ae8c6e8db5ee89993fa44459410d30a0a8af700ae3aee8a9a1d6094f8c757d3b79a8d1147e85be34fb260a970a52826c0a92b46cefb5dfaf2b5a31edf867f8d34d2222900000000000000000000000000000000
p_bits = 1024
k_bits = 128
PR.<x> = PolynomialRing(Zmod(n))
f = x + p_fake
x0 = f.small_roots(X=2^k_bits, beta=0.4)[0]
p = int(x0) + p_fake
print('p =', p)
# p =  147305526294483975294006704928271118039370615054437206404408410848858740256154476278591035455064149531353089038270283281541411458250950936656537283482331598521457077465891874559349872035197398406708610440618635013091489698011474611145014167945729411970665381793142591665313979405475889978830728651549052207969
q = n // p
print('q =', q)
# q =  104447286451939566076017797038369998283019120860149982200602344749600436385708441695230995780714906769626731151644722579252428917819367256207463696691033967714073069435280785389775459281272218174741165454138432242201951151298026448827619971129737985262978620243577274864410816225725466321200461416855483876019
d = inverse_mod(e, (p-1)*(q-1))
m = pow(c, d, n)
print('m =', m)
# m = 149691910197805776133774875425761425579759130391933
flag = binascii.unhexlify(hex(m)[2:]).decode('utf-8')
print(flag) # flag{Kn0wn_Hi9h_Bit5}
```

------

### ♥ easyrsa8

附件解压缩后得到`public.key`和`flag.enc`。这题和[Poor RSA](#Poor RSA)很相似，编写`Python`代码进行求解，首先用`Crypto.PublicKey`的`RSA`模块来获取公钥对`<n, e>`，然后调用`requests`库在线请求 http://factordb.com 分解模数`n`，得到`p`和`q`，算出 `φ(n) = (p-1)(q-1)`，进而得到私钥的解密质数`d`，至此私钥已经拿到。用`Crypto.PublicKey`的`PKCS1_OAEP`模块生成私钥对`flag.enc`进行`RSA`解密，可以得到明文`flag{p_1s_5mall_num6er}`，提交即可。

```python
import requests
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Util.number import inverse

def factorize(n):
    l = []
    url="http://factordb.com/api?query="+str(n)
    r = requests.get(url)
    data = r.json()
    for factor in data['factors']:
        l.append(int(factor[0]))
    return l

with open('public.key', 'rb') as f:
    public_key = RSA.importKey(f.read())

n = public_key.n
e = public_key.e
q, p = factorize(n)
d = inverse(e, (p-1)*(q-1))
key_info = RSA.construct((n, e, d, p, q))
private_key = PKCS1_OAEP.new(key_info)

with open('flag.enc', 'rb') as f:
    flag = private_key.decrypt(f.read()).decode()

print(flag) # flag{p_1s_5mall_num6er}
```

------

### ♥ unusualrsa1

附件`unusualrsa1.py`源码如下：

```python
# ********************
# @Author: Lazzaro
# ********************

from Crypto.Util.number import getPrime,bytes_to_long,long_to_bytes
from random import randint
from secret import flag

p = getPrime(1024)
q = getPrime(1024)
n = p*q
print(n)

m = bytes_to_long(long_to_bytes(randint(0,30))*208+flag)
assert(m.bit_length()==2044)
print((m>>315)<<315)
c = pow(m,3,n)
print(c)

#14113948189208713011909396304970377626324044633561155020366406284451614054260708934598840781397326960921718892801653205159753091559901114082556464576477585198060530094478860626532455065960136263963965819002575418616768412539016154873800614138683106056209070597212668250136909436974469812231498651367459717175769611385545792201291192023843434476550550829737236225181770896867698281325858412643953550465132756142888893550007041167700300621499970661661288422834479368072744930285128061160879720771910458653611076539210357701565156322144818787619821653007453741709031635862923191561438148729294430924288173571196757351837
#1520800285708753284739523608878585974609134243280728660335545667177630830064371336150456537012842986526527904043383436211487979254140749228004148347597566264500276581990635110200009305900689510908049771218073767918907869112593870878204145615928290375086195098919355531430003571366638390993296583488184959318678321571278510231561645872308920917404996519309473979203661442792048291421574603018835698487725981963573816645574675640357569465990665689618997534740389987351864738104038598104713275375385003471306823348792559733332094774873827383320058176803218213042061965933143968710199376164960850951030741280074168795136
#6635663565033382363211849843446648120305449056573116171933923595209656581213410699649926913276685818674688954045817246263487415328838542489103709103428412175252447323358040041217431171817865818374522191881448865227314554997131690963910348820833080760482835650538394814181656599175839964284713498394589419605748581347163389157651739759144560719049281761889094518791244702056048080280278984031050608249265997808217512349309696532160108250480622956599732443714546043439089844571655280770141647694859907985919056009576606333143546094941635324929407538860140272562570973340199814409134962729885962133342668270226853146819
```

注意到关键代码`(m>>315)<<315`，已知`m`的高位，低`315`位数据丢失，用`sagemath`进行数据恢复。

```python
n = 14113948189208713011909396304970377626324044633561155020366406284451614054260708934598840781397326960921718892801653205159753091559901114082556464576477585198060530094478860626532455065960136263963965819002575418616768412539016154873800614138683106056209070597212668250136909436974469812231498651367459717175769611385545792201291192023843434476550550829737236225181770896867698281325858412643953550465132756142888893550007041167700300621499970661661288422834479368072744930285128061160879720771910458653611076539210357701565156322144818787619821653007453741709031635862923191561438148729294430924288173571196757351837
m_fake = 1520800285708753284739523608878585974609134243280728660335545667177630830064371336150456537012842986526527904043383436211487979254140749228004148347597566264500276581990635110200009305900689510908049771218073767918907869112593870878204145615928290375086195098919355531430003571366638390993296583488184959318678321571278510231561645872308920917404996519309473979203661442792048291421574603018835698487725981963573816645574675640357569465990665689618997534740389987351864738104038598104713275375385003471306823348792559733332094774873827383320058176803218213042061965933143968710199376164960850951030741280074168795136
c = 6635663565033382363211849843446648120305449056573116171933923595209656581213410699649926913276685818674688954045817246263487415328838542489103709103428412175252447323358040041217431171817865818374522191881448865227314554997131690963910348820833080760482835650538394814181656599175839964284713498394589419605748581347163389157651739759144560719049281761889094518791244702056048080280278984031050608249265997808217512349309696532160108250480622956599732443714546043439089844571655280770141647694859907985919056009576606333143546094941635324929407538860140272562570973340199814409134962729885962133342668270226853146819
e = 3
k_bits = 315
PR.<x> = PolynomialRing(Zmod(n))
f = (x + m_fake)^e-c
x0 = f.small_roots(X=2^k_bits)[0]
m = int(x0) + m_fake
# m = 1520800285708753284739523608878585974609134243280728660335545667177630830064371336150456537012842986526527904043383436211487979254140749228004148347597566264500276581990635110200009305900689510908049771218073767918907869112593870878204145615928290375086195098919355531430003571366638390993296583488184959318678321571278510231561645872308920917404996519309473979203661442792048291421574603018835698487725981963573816645574675640357569465990665689618997534740389987351864738104038598104713275375385003471306823348792559733393609593321367463114703873343853590413300366406780333184299791982772652326424221774382732443261
```

用`libnum`中的`n2s`将`m`转换成字符串，去除多余的空格后得到`flag{r54__c0pp3r5m17h_p4r714l_m_4774ck_15_c00l~}`，提交即可。

```python
from libnum import n2s

m = 1520800285708753284739523608878585974609134243280728660335545667177630830064371336150456537012842986526527904043383436211487979254140749228004148347597566264500276581990635110200009305900689510908049771218073767918907869112593870878204145615928290375086195098919355531430003571366638390993296583488184959318678321571278510231561645872308920917404996519309473979203661442792048291421574603018835698487725981963573816645574675640357569465990665689618997534740389987351864738104038598104713275375385003471306823348792559733393609593321367463114703873343853590413300366406780333184299791982772652326424221774382732443261
flag = n2s(m).decode().strip()
print(flag) # flag{r54__c0pp3r5m17h_p4r714l_m_4774ck_15_c00l~}
```

------

## CTFHub

### 2020-BJDCTF-Crypto-sign in

打开`.txt`文件可以看到以下信息：

> welcome to crypto world！！
> 密文：424a447b57653163306d655f74345f424a444354467d

显然这是`16`进制的`ASCII`码，编写`Python`代码进行解码即可得到`BJD{We1c0me_t4_BJDCTF}`。

```python
flag = bytes.fromhex('424a447b57653163306d655f74345f424a444354467d').decode('utf-8')
print(flag)
```

------

## Bugku

#### ♥ [Double](https://ctf.bugku.com/challenges/detail/id/214.html)

附件解压缩后得到`Double.sage`，源码如下：

```python
from Crypto.Util.number import bytes_to_long
from secrets import k, P, flag

E = EllipticCurve(QQ,[0,2021,0,310,-2783])
assert P.xy()[1] == E.lift_x(2)
Q = k * P
R = Q + P

p = Q[0].numerator()
q = R[0].numerator()
e = 0x10001
n = p * q
assert k < n.bit_length()

m = bytes_to_long(flag)
c = pow(m, e, n)

print(f'n = {n}')
print(f'c = {c}')

#n = 2627832721798532654645633759787364870195582649392807630554510880534973280751482201937816738488273589173932960856611147584617677312265144131447658399933331448791094639659769069406481681017795446858858181106274806005669388289349727511470680972
#c = 96830301447792999743877932210925094490214669785432172099311147672020980136112114653571739648595225131425493319224428213036136642899189859618195566355934768513439007527385261977662612094503054618556883356183687422846428828606638722387070581
```

已知`n`，`e`，`c`，求`m`。编写`Python`进行求解，首先调用`requests`库在线请求 http://factordb.com 分解模数`n`，得到一系列因数后，根据$\phi(n)=\prod_{i=1}^{k}(p_{i}-1)$算出 `φ(n)`，进而得到解密质数`d`，最后算出加密前的明文`m`，`n2s`转换后得到`flag`。

```python
import requests
from libnum import *

def factorize(n):
    l = []
    url="http://factordb.com/api?query="+str(n)
    r = requests.get(url)
    data = r.json()   
    for factor in data['factors']:
        for i in range(int(factor[1])):
            l.append(int(factor[0]))
    return l

def getPhi(p_list):
    phi = 1
    for p in p_list:
        phi *= (p-1)
    return phi

n = 2627832721798532654645633759787364870195582649392807630554510880534973280751482201937816738488273589173932960856611147584617677312265144131447658399933331448791094639659769069406481681017795446858858181106274806005669388289349727511470680972
c = 96830301447792999743877932210925094490214669785432172099311147672020980136112114653571739648595225131425493319224428213036136642899189859618195566355934768513439007527385261977662612094503054618556883356183687422846428828606638722387070581
e = 0x10001
phi = getPhi(factorize(n))
d = invmod(e, phi)
m = pow(c, d, n)
flag = n2s(m).decode()
print(flag) # flag{D4mn_e45y_eCC_4Nd_R54_m1XeD}
```

------

#### ♥ [给你私钥吧](https://ctf.bugku.com/challenges/detail/id/194.html)

附件解压缩后共有四个文件：`flag.enc`，`privatekey.pem`，`pubkey.pem`，`rsaencrypt.py`。其中`rsaencrypt.py`的源码如下：

```python
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64
from flag import flag


f=open(r"pubkey.pem","r")
key=RSA.importKey(f.read())
cipher=PKCS1_OAEP.new(key)
cipher_txt=base64.b64encode(cipher.encrypt(flag))

with open(r"flag.enc","wb") as f:
    f.write(cipher_txt)
    f.close()
```

编写`Python`代码进行求解，首先用`Crypto.PublicKey`的`RSA`模块读入`pubkey.pem`，获取公钥对`<n, e>`，得到`n`和`e`，然后调用`requests`库在线请求 http://factordb.com 分解模数`n`，得到`p`和`q`，算出 `φ(n) = (p-1)(q-1)`，进而得到私钥的解密质数`d`，至此私钥已经拿到。用`Crypto.PublicKey`的`PKCS1_OAEP`模块生成私钥对`base64`解码后的`flag.enc`进行`RSA`解密，可以得到明文`bugku{tw0_Tig3rs_l0V3_d4nc1ng~ei!}}`，提交即可。

```python
import requests
from base64 import b64decode
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Util.number import inverse

def factorize(n):
    l = []
    url="http://factordb.com/api?query="+str(n)
    r = requests.get(url)
    data = r.json()
    for factor in data['factors']:
        l.append(int(factor[0]))
    return l

with open('pubkey.pem', 'rb') as f:
    public_key = RSA.import_key(f.read())


n = public_key.n
e = public_key.e
q, p = factorize(n)
d = inverse(e, (p-1)*(q-1))
key_info = RSA.construct((n, e, d, p, q))
private_key = PKCS1_OAEP.new(key_info)

with open('flag.enc', 'rb') as f:
    cipher_text = b64decode(f.read())
    flag = private_key.decrypt(cipher_text).decode()

print(flag) # bugku{tw0_Tig3rs_l0V3_d4nc1ng~ei!}
```

------

#### [where is flag 5](https://ctf.bugku.com/challenges/detail/id/366.html)

附件解压缩后得到`.txt`文件，内容如下：

```
Gx8EAA8SCBIfHQARCxMUHwsAHRwRHh8BEQwaFBQfGwMYCBYRHx4SBRQdGR8HAQ0QFQ==
```

进行`base64`解码得到：

```
\x1b\x1f\x04\x00\x0f\x12\x08\x12\x1f\x1d\x00\x11\x0b\x13\x14\x1f\x0b\x00\x1d\x1c\x11\x1e\x1f\x01\x11\x0c\x1a\x14\x14\x1f\x1b\x03\x18\x08\x16\x11\x1f\x1e\x12\x05\x14\x1d\x19\x1f\x07\x01\r\x10\x15
```

解码内容看似`16`进制，但是`\x1b`,`\x1f`，`\x04`等等又不在`ASCII`码字母范围内。转二进制后，左边补齐`0`，共五组，每组`49`位，每七位转`ASCII`码，拼接后得到`bugku{ce26f61d40fea75fc0b980d7588e}`。

```python
import base64
s = "Gx8EAA8SCBIfHQARCxMUHwsAHRwRHh8BEQwaFBQfGwMYCBYRHx4SBRQdGR8HAQ0QFQ=="
s = base64.b64decode(s)
l = [bin(i).replace('0b', '').rjust(5, '0') for i in s]
flag = ''
for i in range(5):
    s = ''.join([x[i] for x in l])
    flag += ''.join([chr(int(s[i:i+7], 2)) for i in range(0, len(s), 7)])

print(flag) # bugku{ce26f61d40fea75fc0b980d7588e}
```

------

#### ♥ [RSSSSSA](https://ctf.bugku.com/challenges/detail/id/365.html)

附件解压缩后内容如下：

```python
e = 29
n = [30327806559308143170251580709344293187241377730282921872781575442079759214585250363018838833645033147048274099882927502135822532658361986843089038971809699440265951177983452623836631182131316783838858410002798162604085127069663694047960859197275399255233610031615817404372364349637055800705223698180870067436988096453852212302215116141417320041306889953482862584091194471138823690888819261753453934793173621702326066309884946089600954181869152898879815596750534117681142535676578782280108274188679221706983417414010745084946761574988283779791817969892384961589321416872995532377690950727835973399647956491090102555409, 21201945432185822273274384690776217497058902883149769388717005633136179247488270702594230376181288768858812012728332675867062647184506694171059959523739358150427193785288862325490483145892589156285417654675409522395461778047750713685913892924628709666682898716590870448590373784915689173142592010032611604863227130433544024508077340982534157235155525782725897976772958969688875400789351919632303930452916408599309209320071861151825269791353531470198408880292345886431587538581009065968803858039954194364023302947597373427552936469472639511930960050054058074397349282354505376836608524919420271358644040625272611834141, 22066722902445052583751020956045490471001229482392491124491605354676847417172264621341464938604744547196288089839857467414993454346487337649230414610787992018112868327537703873968574017809192037003789320466268844177192403612544118218277599434212247848173311593650429895564484864389688450385022488374534161927558878171030816097844863947341831453646609936063871558801826304657779664413322335636640541461530342335752307248094073705764721946570652851209785138013258495645549732438232440380725327458972312411697319199017195198686877941387699409525165884596929130086232751883272627080260637468553554114550895128931332556731, 22201854184449819277142185267444382273897841368693102934683821764656962395743826157719287435432760269046740745554089225345079284556882054478011586504345324432037743900501514661174050074095054738909658615769021337525829263909874107830437595890817773992121956416657353703784722839247395770361048793369307710079965231303120658766595423843609770605074056488132086912631857454296414163240447182566834479775710868231123976843543989150070863055009604342636257860806777650229259057896505901924417615469387152636729167180379751548900559610148369495057752373605259839922528981148145028120068953655171238962097381144518051147647, 23083840233620992224264526611828536460163558999895002497626591923027006640369297896797243966752151170505775381864181314027021495993588967339108820520528972816379841269197877268187639445751437743759925034716110259215833511647315164717603384871571434294945499053929574035111488209616165563966647430661297795173473421242368063748311843339991310650516321423828411278303633083702771322000349673510635860126984256969661571754688788776209025080804889751723316765593984981235995307564443348633486717797511234178142487310778666548407208267425343907584339092352000989025888560813696453621147789642611872568202165905056714548393, 23218822553600624275851570918327600443202628196986792799225558073420180848161120578874626283971398879263850567245985782927539083923897342980706479709569579629418591343916765139087666874177802508777776627037319228004136490718510415593236575453393195566284309655647871922536044561206875353630359295663312099218766232095780724182736486077598036512073334536846225792741359530446751954255489310204542643379502811042809497521182466190499994814904710462792494798490083908932248164953870969612782940162469775904944210724177461134898671189252356405455733124848794067548040801451291259009951270923040763880342053172756399581161, 15537621716770448782502134748692657546482394987891814167799488723003580500457315182184780510271452262025473252065075152671351786862081823121704341999623090322622893909472600153140827895279392030437881151726836273881483138361166633444702898613389403354997826623821941237846412179222285546753657710048063757827302566538233983504273873252358216792306525072453406699162260561047287090285490165275142295462447156551127598082848917540871566229207376989948730655600666112133543582179171414297735210520886697976984424647098383547804465263579778326244367614695099540268893495474464880528394459062149362976029449912614166126761]
c = [6046094125227689870033870506917812276305436053796436442363822401342062726188042561670757795460948077415972706427946093618320717744079441259077874700893204459036501380012163686628771354515016380758564221578468509762354597066344146672996248499856111282865676568650895987550682149774776905594210993204175895358464315828610392955454920047755436033052407392579110231386427222684373442110938309074563238848319417352567379700597401198483471415807726938645013860932841996827926718400267742249916874079269259123794751964917045940979213140450626289795549071713337129466329394763935853156424248229732551544822323764365359825485, 5845552286578226566598806127534836409831300694599972428266617271147189508983086233231766595846029052663890341733882461545982026551439575193608090205669127833427025577685774642780332691084053603909859869193052420285065348378657385164191605378649460509586471212644006322411828860570889277856429353408252263239239828396565949357208821626888694650997167695580553398057963048443171407094467284923234982142222808183498767632834628360161922076588397865384233638848062174627983119799111822718694488311274624762022407317556646065445367315918249540635444036633880194363965914260210883151429898423440605220973034396774973125632, 15903392352203298605877945674465143966769721737532685945162112598239954843499500918942681985964024463454447115748161245918002002655617193080894539813344429249706695035313266913563071057661003650948948239324748886703222675088558181086755212852968181312257303494407773363350004731534848190264255069536036133029778028229221293469762527695954265711168400217935692988501544247020837424584759831204521029707454822146517072769268420888169838807185669690437151962231817248323732857623620673773191557407520247312964435867860663874242179929967218588152288202476576081222176785925045418916462303292404117304143574686336544149629, 9669717038949021329020108540640237663067756966280810642417630134992373130879787768749181913381401511774773393506456589516952861294673561533008751071662723277608866325874519278507984666760149692092823573606053373801025601646795839172562607132726532904679698936251789947925155456255628127932509101557747423647220724762995217296493861282238350001729340519429193525028741636093329396359178973155083792632330011484299821599210312002159965537430090985352568581714148228760952230630659713444400585630168629530652207170759737992501963831886075598264013355139219445863531555822055994574891400262563108434859568651780227557975, 7914090642636266923294026791261427849044695562739254282481166732020837928041454353817133871854948761397284836379753705671724947241779482598081203575216043223216563037754382992648875469848870865515423794755447621640988585802308628444956443228403796584499863761840901610073862093944795357445536465073500157568848798543720484354000858578319564737563857043549861785205215491288782410945294230845471220683129677585701046542907136512616807429274294758158965956146717352157078092334387660733724142855367118044193694310952976603009653011262032422467651663006916850935081716939520365535884320814471253649009945816472423048447, 11988310991395265980081594718856590638441631362665678269045945813797124375621091172731397011814305000162712601455584541005431841875115788140698346738764417691906578333694503756521160780120138569779573589730959145320537390172280626510886154211649716255438845119004751973530199741765756641003306339421117668796100661313571568100843237996562080095649017634551873879219917272328238629844657368364890324594141674498942544827428056492747949043332622214494766621587698339619576784948756333563714427524714670635509179215190783959390410232309595570890592221268445440689742423642145049491551659385729937300897657450196112613804, 13758385300968829470189169449584800778823082473607121434049610051116374924292341244419430157132107552964735632092568046439074559673147580828760077490267517852677562615547566840913903686439783964549498803731879665085652815249977620067028187162008373600851339874309707587214786555705953533197711132611955125553398328736012543728815790951625456481002420603689802771155816294782083229750332438335093308789359642911367376579780093093577929312234635979675059828551040384269343053231849182709709271027703443106568079145606579815607660891685636327906452992083196131013003312334278998794497774078191519059014857427818993752773]
```

题目给出了加密指数`e`还有一系列`n`和`c`。加密指数`e`的值很小，`m`相同，推出本题的考察点是低加密指数广播攻击，可以使用中国剩余定理求解。编写`Python`代码进行求解得到`flag{b3f4fe99-7b70-4fde-bac6-3243eff89f0b}`。

```python
import gmpy2
from functools import reduce
from Crypto.Util.number import long_to_bytes

def CRT(mi, ai):
    assert(reduce(gmpy2.gcd,mi)==1)
    assert (isinstance(mi, list) and isinstance(ai, list))
    M = reduce(lambda x, y: x * y, mi)
    ai_ti_Mi = [a * (M // m) * gmpy2.invert(M // m, m) for (m, a) in zip(mi, ai)]
    return reduce(lambda x, y: x + y, ai_ti_Mi) % M


e = 29
n = [30327806559308143170251580709344293187241377730282921872781575442079759214585250363018838833645033147048274099882927502135822532658361986843089038971809699440265951177983452623836631182131316783838858410002798162604085127069663694047960859197275399255233610031615817404372364349637055800705223698180870067436988096453852212302215116141417320041306889953482862584091194471138823690888819261753453934793173621702326066309884946089600954181869152898879815596750534117681142535676578782280108274188679221706983417414010745084946761574988283779791817969892384961589321416872995532377690950727835973399647956491090102555409, 21201945432185822273274384690776217497058902883149769388717005633136179247488270702594230376181288768858812012728332675867062647184506694171059959523739358150427193785288862325490483145892589156285417654675409522395461778047750713685913892924628709666682898716590870448590373784915689173142592010032611604863227130433544024508077340982534157235155525782725897976772958969688875400789351919632303930452916408599309209320071861151825269791353531470198408880292345886431587538581009065968803858039954194364023302947597373427552936469472639511930960050054058074397349282354505376836608524919420271358644040625272611834141, 22066722902445052583751020956045490471001229482392491124491605354676847417172264621341464938604744547196288089839857467414993454346487337649230414610787992018112868327537703873968574017809192037003789320466268844177192403612544118218277599434212247848173311593650429895564484864389688450385022488374534161927558878171030816097844863947341831453646609936063871558801826304657779664413322335636640541461530342335752307248094073705764721946570652851209785138013258495645549732438232440380725327458972312411697319199017195198686877941387699409525165884596929130086232751883272627080260637468553554114550895128931332556731, 22201854184449819277142185267444382273897841368693102934683821764656962395743826157719287435432760269046740745554089225345079284556882054478011586504345324432037743900501514661174050074095054738909658615769021337525829263909874107830437595890817773992121956416657353703784722839247395770361048793369307710079965231303120658766595423843609770605074056488132086912631857454296414163240447182566834479775710868231123976843543989150070863055009604342636257860806777650229259057896505901924417615469387152636729167180379751548900559610148369495057752373605259839922528981148145028120068953655171238962097381144518051147647, 23083840233620992224264526611828536460163558999895002497626591923027006640369297896797243966752151170505775381864181314027021495993588967339108820520528972816379841269197877268187639445751437743759925034716110259215833511647315164717603384871571434294945499053929574035111488209616165563966647430661297795173473421242368063748311843339991310650516321423828411278303633083702771322000349673510635860126984256969661571754688788776209025080804889751723316765593984981235995307564443348633486717797511234178142487310778666548407208267425343907584339092352000989025888560813696453621147789642611872568202165905056714548393, 23218822553600624275851570918327600443202628196986792799225558073420180848161120578874626283971398879263850567245985782927539083923897342980706479709569579629418591343916765139087666874177802508777776627037319228004136490718510415593236575453393195566284309655647871922536044561206875353630359295663312099218766232095780724182736486077598036512073334536846225792741359530446751954255489310204542643379502811042809497521182466190499994814904710462792494798490083908932248164953870969612782940162469775904944210724177461134898671189252356405455733124848794067548040801451291259009951270923040763880342053172756399581161, 15537621716770448782502134748692657546482394987891814167799488723003580500457315182184780510271452262025473252065075152671351786862081823121704341999623090322622893909472600153140827895279392030437881151726836273881483138361166633444702898613389403354997826623821941237846412179222285546753657710048063757827302566538233983504273873252358216792306525072453406699162260561047287090285490165275142295462447156551127598082848917540871566229207376989948730655600666112133543582179171414297735210520886697976984424647098383547804465263579778326244367614695099540268893495474464880528394459062149362976029449912614166126761]
c = [6046094125227689870033870506917812276305436053796436442363822401342062726188042561670757795460948077415972706427946093618320717744079441259077874700893204459036501380012163686628771354515016380758564221578468509762354597066344146672996248499856111282865676568650895987550682149774776905594210993204175895358464315828610392955454920047755436033052407392579110231386427222684373442110938309074563238848319417352567379700597401198483471415807726938645013860932841996827926718400267742249916874079269259123794751964917045940979213140450626289795549071713337129466329394763935853156424248229732551544822323764365359825485, 5845552286578226566598806127534836409831300694599972428266617271147189508983086233231766595846029052663890341733882461545982026551439575193608090205669127833427025577685774642780332691084053603909859869193052420285065348378657385164191605378649460509586471212644006322411828860570889277856429353408252263239239828396565949357208821626888694650997167695580553398057963048443171407094467284923234982142222808183498767632834628360161922076588397865384233638848062174627983119799111822718694488311274624762022407317556646065445367315918249540635444036633880194363965914260210883151429898423440605220973034396774973125632, 15903392352203298605877945674465143966769721737532685945162112598239954843499500918942681985964024463454447115748161245918002002655617193080894539813344429249706695035313266913563071057661003650948948239324748886703222675088558181086755212852968181312257303494407773363350004731534848190264255069536036133029778028229221293469762527695954265711168400217935692988501544247020837424584759831204521029707454822146517072769268420888169838807185669690437151962231817248323732857623620673773191557407520247312964435867860663874242179929967218588152288202476576081222176785925045418916462303292404117304143574686336544149629, 9669717038949021329020108540640237663067756966280810642417630134992373130879787768749181913381401511774773393506456589516952861294673561533008751071662723277608866325874519278507984666760149692092823573606053373801025601646795839172562607132726532904679698936251789947925155456255628127932509101557747423647220724762995217296493861282238350001729340519429193525028741636093329396359178973155083792632330011484299821599210312002159965537430090985352568581714148228760952230630659713444400585630168629530652207170759737992501963831886075598264013355139219445863531555822055994574891400262563108434859568651780227557975, 7914090642636266923294026791261427849044695562739254282481166732020837928041454353817133871854948761397284836379753705671724947241779482598081203575216043223216563037754382992648875469848870865515423794755447621640988585802308628444956443228403796584499863761840901610073862093944795357445536465073500157568848798543720484354000858578319564737563857043549861785205215491288782410945294230845471220683129677585701046542907136512616807429274294758158965956146717352157078092334387660733724142855367118044193694310952976603009653011262032422467651663006916850935081716939520365535884320814471253649009945816472423048447, 11988310991395265980081594718856590638441631362665678269045945813797124375621091172731397011814305000162712601455584541005431841875115788140698346738764417691906578333694503756521160780120138569779573589730959145320537390172280626510886154211649716255438845119004751973530199741765756641003306339421117668796100661313571568100843237996562080095649017634551873879219917272328238629844657368364890324594141674498942544827428056492747949043332622214494766621587698339619576784948756333563714427524714670635509179215190783959390410232309595570890592221268445440689742423642145049491551659385729937300897657450196112613804, 13758385300968829470189169449584800778823082473607121434049610051116374924292341244419430157132107552964735632092568046439074559673147580828760077490267517852677562615547566840913903686439783964549498803731879665085652815249977620067028187162008373600851339874309707587214786555705953533197711132611955125553398328736012543728815790951625456481002420603689802771155816294782083229750332438335093308789359642911367376579780093093577929312234635979675059828551040384269343053231849182709709271027703443106568079145606579815607660891685636327906452992083196131013003312334278998794497774078191519059014857427818993752773]
m = gmpy2.iroot(CRT(n, c), e)[0]
flag = long_to_bytes(int(m)).decode()
print(flag) # flag{b3f4fe99-7b70-4fde-bac6-3243eff89f0b}
```

本题的出题脚本为：

```python
import libnum
#生成随机素数
def rsa_def(e,m):
    p=libnum.generate_prime(1024)
    q=libnum.generate_prime(1024)
    #字符串转数字
    m=libnum.s2n(m)
    n=p*q
    c=pow(m,e,n)
    n_lt.append(n)
    c_lt.append(c)

n_lt=[]
c_lt=[]
e=23
m='flag{b3f4fe99-7b70-4fde-bac6-3243eff89f0b}'
for i in range(7):
    rsa_def(e,m)

print("e=",e)
print("n=",n_lt)
print("c=",c_lt)
```

------

#### [Funny Number](https://ctf.bugku.com/challenges/detail/id/200.html)

附件解压缩后得到`task.py`，源码如下：

```python
#######################
# @Author: Lazzaro
#######################

from secret import flag

print(int(str(int.from_bytes(str(flag).encode(), byteorder='little') << 10000)[-175:]))

#5390734306631855467986187436983737752151008395372308788862499432056740530367025683371238030400935613581745610066222336578420939008918998541409247659187704647583389480103444480
```

数论题，编写`Python`代码进行求解得到`flag{NuM8eR_7HE0rY_1s_S0_Funny~}`。

```python
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
```

------

#### [No Ciphertext RSA](https://ctf.bugku.com/challenges/detail/id/376.html)

附件解压缩后得到`task.py`，源码如下：

```python
from Crypto.Util.number import *
import libnum
from secret import flag,p,q
e=65537
m=libnum.s2n(flag)
n=p*q
phi_n=(p-1)*(q-1)
d=libnum.invmod(e,phi_n)
dp=d%(p-1)
c=pow(m,e,n)
print("e =",e)
print("n =",n)
print("dp = ",dp)
leak_c1=c%p
leak_c2=c%q
print("leak_c1 =",leak_c1)
print("leak_c2 =",leak_c2)
"""
e = 65537
n = 20446305236294581881140725938833605520023786992590821920806811572505477606387830733060901955371457846738863889279107367753914707053108524516947943610226964107558978693717655472431318403586269727573489946433389159145602800207787382180423611018458189828931572992863289292613405218278949739073786959411566919119158325510346523951336418479951932209799501108477995314359188860274532542630968951457343647522078553891223764285682602714616115281040492374167771746275218863543545907073818468841626731849010162645256595641473022327747346052186526727216525426337190917106751151745388854749923598231196090790074682287345100965373
dp =  158325084409606165134868956023907667507671677832027168046364315703295407017343206432691817272550256085313093440797443736742051552429653661451417133052016647805226890534559578502154540190596419643135611407218228612201386225040438407799879719366484669372051153511312310009858718254183049095347658106745575535469
leak_c1 = 116908580792713727509554342060190793142033425411766631165842865699167747112494944492849392371565838125428644563687571660329763478509815200537676368326781342382868082294015200439334832938068779547847851748337854603115134732593759473453640093195977206450633212921689957303431235603192670553553803757864481012599
leak_c2 = 18319344794671185787719339480953236221170603508712466350928025351527616335735433941953520711516118072282425397883638101260674452825151245435529613074796106769481242318321469286177813223159476396555044378245229663195991557031227024085316255781963813911437991309663376270820486723382786632243229800891705679245
"""
```

先利用`n`和`dp`求解出`p`，`q = n//p`，算出 `φ(n) = (p-1)(q-1)`，得到私钥的解密质数`d`，题目给出`leak_c1`和`leak_c2`，结合中国剩余定理能求出密文`c`，进而得到明文`m`，转换成字符串后得到`flag`，提交`bugku{d583310f-2add-4559-957e-8f6193eeb8f7}`即可。

```python
from gmpy2 import *
from functools import reduce

def CRT(mi, ai):
    assert(reduce(gcd,mi)==1)
    assert (isinstance(mi, list) and isinstance(ai, list))
    M = reduce(lambda x, y: x * y, mi)
    ai_ti_Mi = [a * (M // m) * invert(M // m, m) for (m, a) in zip(mi, ai)]
    return reduce(lambda x, y: x + y, ai_ti_Mi) % M


e = 65537
n = 20446305236294581881140725938833605520023786992590821920806811572505477606387830733060901955371457846738863889279107367753914707053108524516947943610226964107558978693717655472431318403586269727573489946433389159145602800207787382180423611018458189828931572992863289292613405218278949739073786959411566919119158325510346523951336418479951932209799501108477995314359188860274532542630968951457343647522078553891223764285682602714616115281040492374167771746275218863543545907073818468841626731849010162645256595641473022327747346052186526727216525426337190917106751151745388854749923598231196090790074682287345100965373
dp = 158325084409606165134868956023907667507671677832027168046364315703295407017343206432691817272550256085313093440797443736742051552429653661451417133052016647805226890534559578502154540190596419643135611407218228612201386225040438407799879719366484669372051153511312310009858718254183049095347658106745575535469
leak_c1 = 116908580792713727509554342060190793142033425411766631165842865699167747112494944492849392371565838125428644563687571660329763478509815200537676368326781342382868082294015200439334832938068779547847851748337854603115134732593759473453640093195977206450633212921689957303431235603192670553553803757864481012599
leak_c2 = 18319344794671185787719339480953236221170603508712466350928025351527616335735433941953520711516118072282425397883638101260674452825151245435529613074796106769481242318321469286177813223159476396555044378245229663195991557031227024085316255781963813911437991309663376270820486723382786632243229800891705679245
for i in range(1, e):
    p = (dp*e-1)//i+1
    if n%p == 0:
        q = n//p
        break
print(p, q)
d = invert(e, (p-1)*(q-1))
c = CRT([p, q], [leak_c1, leak_c2])
m = pow(c, d, n)
flag = bytes.fromhex(hex(m)[2:]).decode()
print(flag) # bugku{d583310f-2add-4559-957e-8f6193eeb8f7}
```

------

## BUUCTF

### [[AFCTF2018]Morse](https://buuoj.cn/challenges#[AFCTF2018]Morse)

编写`Python`代码进行求解，提交`flag{61666374667b317327745f73305f333435797d}`即可。

```python
def morse(ciphertext:str, sign:str) -> str:
    '''
    ciphertext => 密文
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
    for code in ciphertext.split(sign):
        plaintext += MorseList[code]
    return plaintext

if __name__ == '__main__':
    # Case 1: https://adworld.xctf.org.cn/task/answer?type=crypto&number=5&grade=0&id=5111
    text = '-..../.----/-..../-..../-..../...--/--.../....-/-..../-..../--.../-.../...--/.----/--.../...--/..---/--.../--.../....-/...../..-./--.../...--/...--/-----/...../..-./...--/...--/...--/....-/...--/...../--.../----./--.../-..'
    flag = morse(text, '/')  
    # flag = f'flag{{{flag.lower()}}}' # fake flag
    flag = bytes.fromhex(flag).decode().replace('afctf', 'flag')
    print(flag) # flag{1s't_s0_345y}
```

------

### [异性相吸](https://buuoj.cn/challenges#%E5%BC%82%E6%80%A7%E7%9B%B8%E5%90%B8)

附件解压缩后得到`key.txt`和`密文.txt`。异性相吸？暗示异或求解？！编写`Python`代码进行异或操作。好家伙！还真是异或。提交`flag{ea1bc0988992276b7f95b54a7435e89e}`即可。

```python
key = open("key.txt", 'rb').read()
cipher = open("密文.txt", "rb").read()

flag = ''.join(chr(x^y) for x,y in zip(key,cipher))
print(flag) # flag{ea1bc0988992276b7f95b54a7435e89e}
```

------

### [还原大师](https://buuoj.cn/challenges#%E8%BF%98%E5%8E%9F%E5%A4%A7%E5%B8%88)

> 我们得到了一串神秘字符串：TASC?O3RJMV?WDJKX?ZM,问号部分是未知大写字母，为了确定这个神秘字符串，我们通过了其他途径获得了这个字串的32位MD5码。但是我们获得它的32位MD5码也是残缺不全，E903???4DAB????08?????51?80??8A?,请猜出神秘字符串的原本模样，并且提交这个字串的32位MD5码作为答案。 注意：得到的 flag 请包上 flag{} 提交。

编写`Python`代码爆破求解，得到`E9032994DABAC08080091151380478A2`，提交`flag{E9032994DABAC08080091151380478A2}`即可。

```python
import hashlib
#print hashlib.md5(s).hexdigest().upper()
k = 'TASC?O3RJMV?WDJKX?ZM'
for i in range(26):
    temp1 = k.replace('?',str(chr(65+i)),1) #用ascii开始，从A开始查
    for j in range(26):
        temp2 = temp1.replace('?',chr(65+j),1)
        for n in range(26):
            temp3 = temp2.replace('?',chr(65+n),1)
            s = hashlib.md5(temp3.encode('utf8')).hexdigest().upper()#注意大小写
            if s[:4] == 'E903':#检查元素
                flag = f'flag{{{s}}}'

print(flag) # flag{E9032994DABAC08080091151380478A2}
```

------

### [传感器](https://buuoj.cn/challenges#%E4%BC%A0%E6%84%9F%E5%99%A8)

附件解压缩后得到`.txt`文件，内容如下：

> 5555555595555A65556AA696AA6666666955
> 这是某压力传感器无线数据包解调后但未解码的报文(hex)
>
> 已知其ID为0xFED31F，请继续将报文完整解码，提交hex。
>
> 提示1：曼联

由提示`1`想到曼彻斯特编码，编写`Python`代码进行求解，得到`flag{FFFFFED31F645055F9}`。

```python
cipher='5555555595555A65556AA696AA6666666955'

tmp = ''
for i in range(len(cipher)):
    a = bin(eval('0x'+cipher[i]))[2:].zfill(4)
    tmp = tmp+a[1]+a[3]
    # print(tmp)
plain = [hex(int(tmp[i:i+8][::-1],2))[2:] for i in range(0,len(tmp),8)]
flag = ''.join(plain).upper()
print(f'flag{{{flag}}}') # flag{FFFFFED31F645055F9}
```

------

### [SameMod](https://buuoj.cn/challenges#SameMod)

> When people use same mod ,what's wrong? 注意：得到的 flag 请包上 flag{} 提交。

附件解压缩后得到`.txt`文件，内容如下：

```
{6266565720726907265997241358331585417095726146341989755538017122981360742813498401533594757088796536341941659691259323065631249,773}
{6266565720726907265997241358331585417095726146341989755538017122981360742813498401533594757088796536341941659691259323065631249,839}

message1=3453520592723443935451151545245025864232388871721682326408915024349804062041976702364728660682912396903968193981131553111537349
message2=5672818026816293344070119332536629619457163570036305296869053532293105379690793386019065754465292867769521736414170803238309535
```

题目名称叫`SameMod`，给定的公钥`{n1,e1}`和`{n2,e2}`中的模数`n`相同，推测出是`RSA`共模攻击。

编写`Python`代码即可得到`flag`：`flag{whenwethinkitispossible}`。

```python
from gmpy2 import *
import binascii

n = 6266565720726907265997241358331585417095726146341989755538017122981360742813498401533594757088796536341941659691259323065631249
e1 = 773
e2 = 839
c1=3453520592723443935451151545245025864232388871721682326408915024349804062041976702364728660682912396903968193981131553111537349
c2=5672818026816293344070119332536629619457163570036305296869053532293105379690793386019065754465292867769521736414170803238309535
s = gcdext(e1, e2)

s1, s2 = s[1], s[2]
if s1 < 0:
    s1 = -s1
    c1 = invert(c1, n)
elif s2 < 0:
    s2 = -s2
    c2 = invert(c2, n)

m1 = powmod(c1, s1, n)
m2 = powmod(c2, s2, n)
m = (m1*m2)%n
# 1021089710312311910410111011910111610410511010710511610511511211111511510598108101125
# flag = binascii.unhexlify(hex(m)[2:]).decode('utf-8')
tmp = str(m)
i = 0
flag = ''
while i < len(tmp):
    if tmp[i] == '1':
        flag += chr(int(tmp[i:i+3]))
        i += 3
    else:
        flag += chr(int(tmp[i:i+2]))
        i += 2

print(flag) # flag{whenwethinkitispossible}
```

------

### [RSA](https://buuoj.cn/challenges#RSA)

> 在一次RSA密钥对生成中，假设p=473398607161，q=4511491，e=17
> 求解出d作为flag提交

编写`Python`代码进行求解，可计算出`d`的值为`125631357777427553`，提交`flag{125631357777427553}`即可。

```python
from Crypto.Util.number import *

p = 473398607161
q = 4511491
e = 17
d = inverse(e, (p-1)*(q-1))
flag = f'flag{{{d}}}'
print(flag) # flag{125631357777427553}
```

------

### [丢失的MD5](https://buuoj.cn/challenges#%E4%B8%A2%E5%A4%B1%E7%9A%84MD5)

附件解压缩后得到`md5.py`，源码如下：

```python
import hashlib   
for i in range(32,127):
    for j in range(32,127):
        for k in range(32,127):
            m=hashlib.md5()
            m.update('TASC'+chr(i)+'O3RJMV'+chr(j)+'WDJKX'+chr(k)+'ZM')
            des=m.hexdigest()
            if 'e9032' in des and 'da' in des and '911513' in des:
                print des
```

直接运行会报错：`TypeError: Strings must be encoded before hashing`。
修改代码运行得到`e9032994dabac08080091151380478a2`，提交`flag{e9032994dabac08080091151380478a2}`即可。

```python
import hashlib   
for i in range(32,127):
    for j in range(32,127):
        for k in range(32,127):
            m=hashlib.md5()
            m.update(b'TASC'+chr(i).encode('utf-8')+b'O3RJMV'+chr(j).encode('utf-8')+b'WDJKX'+chr(k).encode('utf-8')+b'ZM')
            des=m.hexdigest()
            if 'e9032' in des and 'da' in des and '911513' in des:
                print(des)
                flag = f'flag{{{des}}}'
print(flag)
```

------

### [Alice与Bob](https://buuoj.cn/challenges#Alice%E4%B8%8EBob)

题目描述如下：

> 密码学历史中，有两位知名的杰出人物，Alice和Bob。他们的爱情经过置换和轮加密也难以混淆，即使是没有身份认证也可以知根知底。就像在数学王国中的素数一样，孤傲又热情。下面是一个大整数:98554799767,请分解为两个素数，分解后，小的放前面，大的放后面，合成一个新的数字，进行md5的32位小写哈希，提交答案。 注意：得到的 flag 请包上 flag{} 提交。

编写`Python`代码进行求解，提交`flag{d450209323a847c8d01c6be47c81811a}`即可。

```python
import libnum
from hashlib import md5

factor = sorted(list(libnum.factorize(98554799767).keys()))
s = ''.join(str(x) for x in factor)
flag = md5(s.encode('utf-8')).hexdigest().lower()
print(f'flag{{{flag}}}') # flag{d450209323a847c8d01c6be47c81811a}
```

------

### [rsarsa](https://buuoj.cn/challenges#rsarsa)

附件解压缩后得到`.txt`文件，内容如下：

```python
Math is cool! Use the RSA algorithm to decode the secret message, c, p, q, and e are parameters for the RSA algorithm.

p = 9648423029010515676590551740010426534945737639235739800643989352039852507298491399561035009163427050370107570733633350911691280297777160200625281665378483
q = 11874843837980297032092405848653656852760910154543380907650040190704283358909208578251063047732443992230647903887510065547947313543299303261986053486569407
e = 65537
c = 83208298995174604174773590298203639360540024871256126892889661345742403314929861939100492666605647316646576486526217457006376842280869728581726746401583705899941768214138742259689334840735633553053887641847651173776251820293087212885670180367406807406765923638973161375817392737747832762751690104423869019034

Use RSA to find the secret message
```

编写`Python`代码进行求解，提交`flag{5577446633554466577768879988}`即可。

```python
from gmpy2 import *

p = 9648423029010515676590551740010426534945737639235739800643989352039852507298491399561035009163427050370107570733633350911691280297777160200625281665378483
q = 11874843837980297032092405848653656852760910154543380907650040190704283358909208578251063047732443992230647903887510065547947313543299303261986053486569407
e = 65537
c = 83208298995174604174773590298203639360540024871256126892889661345742403314929861939100492666605647316646576486526217457006376842280869728581726746401583705899941768214138742259689334840735633553053887641847651173776251820293087212885670180367406807406765923638973161375817392737747832762751690104423869019034
d = invert(e, (p-1)*(q-1))
m = powmod(c, d, p*q)
flag = f'flag{{{m}}}'
print(flag)
```

------

### [RSA](https://buuoj.cn/challenges#RSA)

附件解压缩后得到`flag.enc`和`pub.key`文件，其中`pub.key`的内容如下：

```
-----BEGIN PUBLIC KEY-----
MDwwDQYJKoZIhvcNAQEBBQADKwAwKAIhAMAzLFxkrkcYL2wch21CM2kQVFpY9+7+
/AvKr1rzQczdAgMBAAE=
-----END PUBLIC KEY-----
```

使用`openssl`查看公钥，可以从得知模数`hex(n) = C0332C5C64AE47182F6C1C876D42336910545A58F7EEFEFC0BCAAF5AF341CCDD `，指数`e = 65537`。使用 http://factordb.com 在线因数分解`n`，可得`p = 285960468890451637935629440372639283459`，`q = 304008741604601924494328155975272418463`。

![](https://paper.tanyaodan.com/BUUCTF/RSA/1.png)

编写`Python`代码，以二进制读取方式打开`flag.enc`读取密文，将公钥加密结果用私钥进行`rsa`解密后可以得到`flag{decrypt_256}`。

```python
from gmpy2 import invert
import rsa

n = int('C0332C5C64AE47182F6C1C876D42336910545A58F7EEFEFC0BCAAF5AF341CCDD',16)
# n = 86934482296048119190666062003494800588905656017203025617216654058378322103517
p = 285960468890451637935629440372639283459
q = 304008741604601924494328155975272418463
e = 65537

d = int(invert(e, (p-1)*(q-1)))
# d = 81176168860169991027846870170527607562179635470395365333547868786951080991441
key = rsa.PrivateKey(n, e, d, p, q)
with open('flag.enc', 'rb') as f:
    flag = rsa.decrypt(f.read(), key).decode()
print(flag) # flag{decrypt_256}
```

------

### [RSA1](https://buuoj.cn/challenges#RSA1)

附件解压缩后得到`.txt`文件，内容如下：

```python
p = 8637633767257008567099653486541091171320491509433615447539162437911244175885667806398411790524083553445158113502227745206205327690939504032994699902053229 
q = 12640674973996472769176047937170883420927050821480010581593137135372473880595613737337630629752577346147039284030082593490776630572584959954205336880228469 
dp = 6500795702216834621109042351193261530650043841056252930930949663358625016881832840728066026150264693076109354874099841380454881716097778307268116910582929 
dq = 783472263673553449019532580386470672380574033551303889137911760438881683674556098098256795673512201963002175438762767516968043599582527539160811120550041 
c = 24722305403887382073567316467649080662631552905960229399079107995602154418176056335800638887527614164073530437657085079676157350205351945222989351316076486573599576041978339872265925062764318536089007310270278526159678937431903862892400747915525118983959970607934142974736675784325993445942031372107342103852
```

编写`Python`代码进行求解，运行得到`noxCTF{W31c0m3_70_Ch1n470wn}`，提交`flag{W31c0m3_70_Ch1n470wn}`即可。

```python
from Crypto.Util.number import inverse, long_to_bytes

p = 8637633767257008567099653486541091171320491509433615447539162437911244175885667806398411790524083553445158113502227745206205327690939504032994699902053229 
q = 12640674973996472769176047937170883420927050821480010581593137135372473880595613737337630629752577346147039284030082593490776630572584959954205336880228469 
dp = 6500795702216834621109042351193261530650043841056252930930949663358625016881832840728066026150264693076109354874099841380454881716097778307268116910582929 
dq = 783472263673553449019532580386470672380574033551303889137911760438881683674556098098256795673512201963002175438762767516968043599582527539160811120550041 
c = 24722305403887382073567316467649080662631552905960229399079107995602154418176056335800638887527614164073530437657085079676157350205351945222989351316076486573599576041978339872265925062764318536089007310270278526159678937431903862892400747915525118983959970607934142974736675784325993445942031372107342103852
I = inverse(q,p)
mp = pow(c,dp,p)
mq = pow(c,dq,q)             
m = (((mp-mq)*I)%p)*q+mq  
flag = long_to_bytes(m).decode()
print(flag) # noxCTF{W31c0m3_70_Ch1n470wn}
```

------

### [RSA2](https://buuoj.cn/challenges#RSA2)

附件解压缩后得到`.txt`文件，内容如下：

```python
e = 65537
n = 248254007851526241177721526698901802985832766176221609612258877371620580060433101538328030305219918697643619814200930679612109885533801335348445023751670478437073055544724280684733298051599167660303645183146161497485358633681492129668802402065797789905550489547645118787266601929429724133167768465309665906113
dp = 905074498052346904643025132879518330691925174573054004621877253318682675055421970943552016695528560364834446303196939207056642927148093290374440210503657

c = 140423670976252696807533673586209400575664282100684119784203527124521188996403826597436883766041879067494280957410201958935737360380801845453829293997433414188838725751796261702622028587211560353362847191060306578510511380965162133472698713063592621028959167072781482562673683090590521214218071160287665180751
```

使用 http://factordb.com 在线因数分解`n`，可得：

```python
p = 13468634736343473907717969603434376212206335187555458742257940406618189481177835992217885676243155145465521141546915941147336786447889325606555333350540003
q = 18432009829596386103558375461387837845170621179295293289126504231317130550979989727125205467379713835047300158256398009229511746203459540859429194971855371
```

编写`Python`代码求解，得到`flag{wow_leaking_dp_breaks_rsa?_98924743502}`。

```python
from gmpy2 import *
from Crypto.Util.number import long_to_bytes

e = 65537
n = 248254007851526241177721526698901802985832766176221609612258877371620580060433101538328030305219918697643619814200930679612109885533801335348445023751670478437073055544724280684733298051599167660303645183146161497485358633681492129668802402065797789905550489547645118787266601929429724133167768465309665906113
c = 140423670976252696807533673586209400575664282100684119784203527124521188996403826597436883766041879067494280957410201958935737360380801845453829293997433414188838725751796261702622028587211560353362847191060306578510511380965162133472698713063592621028959167072781482562673683090590521214218071160287665180751
p = 13468634736343473907717969603434376212206335187555458742257940406618189481177835992217885676243155145465521141546915941147336786447889325606555333350540003
q = 18432009829596386103558375461387837845170621179295293289126504231317130550979989727125205467379713835047300158256398009229511746203459540859429194971855371
d = invert(e, (p-1)*(q-1))
m = powmod(c, d, p*q)
flag = long_to_bytes(m).decode()
print(flag) # flag{wow_leaking_dp_breaks_rsa?_98924743502}
```

上述代码是`RSA`题最常规的求解方式，这题想考察的应该是`dp`泄露。

```python
from gmpy2 import *
from Crypto.Util.number import long_to_bytes

e = 65537
n = 248254007851526241177721526698901802985832766176221609612258877371620580060433101538328030305219918697643619814200930679612109885533801335348445023751670478437073055544724280684733298051599167660303645183146161497485358633681492129668802402065797789905550489547645118787266601929429724133167768465309665906113
dp = 905074498052346904643025132879518330691925174573054004621877253318682675055421970943552016695528560364834446303196939207056642927148093290374440210503657
c = 140423670976252696807533673586209400575664282100684119784203527124521188996403826597436883766041879067494280957410201958935737360380801845453829293997433414188838725751796261702622028587211560353362847191060306578510511380965162133472698713063592621028959167072781482562673683090590521214218071160287665180751
for i in range(1, e):
    if (dp*e-1)%i == 0:
        p = (dp*e-1)//i+1 
        if n % p == 0:
            q = n//p
            d = invert(e, (p-1)*(q-1))
            m = pow(c, d, n)
            flag = long_to_bytes(m).decode()
            break

print(flag) # flag{wow_leaking_dp_breaks_rsa?_98924743502}
```

------

### [RSA3](https://buuoj.cn/challenges#RSA3)

附件解压缩后得到`.txt`文件，内容如下：

```python
c1=22322035275663237041646893770451933509324701913484303338076210603542612758956262869640822486470121149424485571361007421293675516338822195280313794991136048140918842471219840263536338886250492682739436410013436651161720725855484866690084788721349555662019879081501113222996123305533009325964377798892703161521852805956811219563883312896330156298621674684353919547558127920925706842808914762199011054955816534977675267395009575347820387073483928425066536361482774892370969520740304287456555508933372782327506569010772537497541764311429052216291198932092617792645253901478910801592878203564861118912045464959832566051361
n=22708078815885011462462049064339185898712439277226831073457888403129378547350292420267016551819052430779004755846649044001024141485283286483130702616057274698473611149508798869706347501931583117632710700787228016480127677393649929530416598686027354216422565934459015161927613607902831542857977859612596282353679327773303727004407262197231586324599181983572622404590354084541788062262164510140605868122410388090174420147752408554129789760902300898046273909007852818474030770699647647363015102118956737673941354217692696044969695308506436573142565573487583507037356944848039864382339216266670673567488871508925311154801
e1=11187289
c2=18702010045187015556548691642394982835669262147230212731309938675226458555210425972429418449273410535387985931036711854265623905066805665751803269106880746769003478900791099590239513925449748814075904017471585572848473556490565450062664706449128415834787961947266259789785962922238701134079720414228414066193071495304612341052987455615930023536823801499269773357186087452747500840640419365011554421183037505653461286732740983702740822671148045619497667184586123657285604061875653909567822328914065337797733444640351518775487649819978262363617265797982843179630888729407238496650987720428708217115257989007867331698397
e2=9647291
```

模数`n`相同，推测出是`RSA`共模攻击。编写`Python`代码求解，得到`flag{49d91077a1abcb14f1a9d546c80be9ef}`。

```python
from gmpy2 import *
import binascii

n=22708078815885011462462049064339185898712439277226831073457888403129378547350292420267016551819052430779004755846649044001024141485283286483130702616057274698473611149508798869706347501931583117632710700787228016480127677393649929530416598686027354216422565934459015161927613607902831542857977859612596282353679327773303727004407262197231586324599181983572622404590354084541788062262164510140605868122410388090174420147752408554129789760902300898046273909007852818474030770699647647363015102118956737673941354217692696044969695308506436573142565573487583507037356944848039864382339216266670673567488871508925311154801
c1=22322035275663237041646893770451933509324701913484303338076210603542612758956262869640822486470121149424485571361007421293675516338822195280313794991136048140918842471219840263536338886250492682739436410013436651161720725855484866690084788721349555662019879081501113222996123305533009325964377798892703161521852805956811219563883312896330156298621674684353919547558127920925706842808914762199011054955816534977675267395009575347820387073483928425066536361482774892370969520740304287456555508933372782327506569010772537497541764311429052216291198932092617792645253901478910801592878203564861118912045464959832566051361
e1=11187289
c2=18702010045187015556548691642394982835669262147230212731309938675226458555210425972429418449273410535387985931036711854265623905066805665751803269106880746769003478900791099590239513925449748814075904017471585572848473556490565450062664706449128415834787961947266259789785962922238701134079720414228414066193071495304612341052987455615930023536823801499269773357186087452747500840640419365011554421183037505653461286732740983702740822671148045619497667184586123657285604061875653909567822328914065337797733444640351518775487649819978262363617265797982843179630888729407238496650987720428708217115257989007867331698397
e2=9647291
s = gcdext(e1, e2)

s1, s2 = s[1], s[2]
if s1 < 0:
    s1 = -s1
    c1 = invert(c1, n)
elif s2 < 0:
    s2 = -s2
    c2 = invert(c2, n)

m1 = powmod(c1, s1, n)
m2 = powmod(c2, s2, n)
m = (m1*m2)%n
# 13040004482819947212936436796507286940525898188874967465457845309271472287032383337801279101
flag = binascii.unhexlify(hex(m)[2:]).decode()
print(flag) # flag{49d91077a1abcb14f1a9d546c80be9ef}
```

------

### [RSAROLL](https://buuoj.cn/challenges#RSAROLL)

附件解压缩后得到`题目.txt`和`data.txt`两个文件，其中题目描述如下：

> RSA roll！roll！roll！
> Only number and a-z
> （don't use editor
> which MS provide）

由`data.txt`可知公钥`{n,e}`，知道`n = 920139713 `和`e = 19`后，就可以删去第一行数据，保存剩余的那些密文。

```
{920139713,19}

704796792
752211152
274704164
18414022
368270835
483295235
263072905
459788476
483295235
459788476
663551792
475206804
459788476
428313374
475206804
459788476
425392137
704796792
458265677
341524652
483295235
534149509
425392137
428313374
425392137
341524652
458265677
263072905
483295235
828509797
341524652
425392137
475206804
428313374
483295235
475206804
459788476
306220148
```

编写`Python`代码求解，`rsa`解密每行密文后连在一起，即可得到`flag{13212je2ue28fy71w8u87y31r78eu1e2}`。

```python
import gmpy2
import libnum

n, e = 920139713, 19
p, q = list(libnum.factorize(n).keys()) # 49891 18443
d = gmpy2.invert(e, (p-1)*(q-1))
flag = ''
with open('data.txt', 'r') as f:
    for c in f.readlines():
        m = pow(int(c), d, n)
        flag += chr(m)

print(flag) # flag{13212je2ue28fy71w8u87y31r78eu1e2}
```

------

### [[WUSTCTF2020]babyrsa](https://buuoj.cn/challenges#[WUSTCTF2020]babyrsa)

附件内容如下：

```
c = 28767758880940662779934612526152562406674613203406706867456395986985664083182
n = 73069886771625642807435783661014062604264768481735145873508846925735521695159
e = 65537
```

调用`requests`库在线请求 http://factordb.com 分解模数`n`，得到`p`和`q`，算出 `φ(n) = (p-1)(q-1)`，进而得到私钥的解密质数`d`。

编写`Python`代码求解，得到`wctf2020{just_@_piece_0f_cak3}`，提交错误，提交`flag{just_@_piece_0f_cak3}`通过。

```python
import requests
from libnum import *

def factorize(n):
    l = []
    url="http://factordb.com/api?query="+str(n)
    r = requests.get(url)
    data = r.json()
    for factor in data['factors']:
        l.append(int(factor[0]))
    return l

c = 28767758880940662779934612526152562406674613203406706867456395986985664083182
n = 73069886771625642807435783661014062604264768481735145873508846925735521695159
e = 65537
q, p = factorize(n)
d = invmod(e, (p-1)*(q-1))
m = pow(c, d, n)
flag = n2s(m).decode()
print(flag)  # wctf2020{just_@_piece_0f_cak3}
```

------

### [[GUET-CTF2019]BabyRSA](https://buuoj.cn/challenges#[GUET-CTF2019]BabyRSA)

附件内容如下：

```python
p+q : 0x1232fecb92adead91613e7d9ae5e36fe6bb765317d6ed38ad890b4073539a6231a6620584cea5730b5af83a3e80cf30141282c97be4400e33307573af6b25e2ea
(p+1)(q+1) : 0x5248becef1d925d45705a7302700d6a0ffe5877fddf9451a9c1181c4d82365806085fd86fbaab08b6fc66a967b2566d743c626547203b34ea3fdb1bc06dd3bb765fd8b919e3bd2cb15bc175c9498f9d9a0e216c2dde64d81255fa4c05a1ee619fc1fc505285a239e7bc655ec6605d9693078b800ee80931a7a0c84f33c851740
e : 0xe6b1bee47bd63f615c7d0a43c529d219
d : 0x2dde7fbaed477f6d62838d55b0d0964868cf6efb2c282a5f13e6008ce7317a24cb57aec49ef0d738919f47cdcd9677cd52ac2293ec5938aa198f962678b5cd0da344453f521a69b2ac03647cdd8339f4e38cec452d54e60698833d67f9315c02ddaa4c79ebaa902c605d7bda32ce970541b2d9a17d62b52df813b2fb0c5ab1a5
enc_flag : 0x50ae00623211ba6089ddfae21e204ab616f6c9d294e913550af3d66e85d0c0693ed53ed55c46d8cca1d7c2ad44839030df26b70f22a8567171a759b76fe5f07b3c5a6ec89117ed0a36c0950956b9cde880c575737f779143f921d745ac3bb0e379c05d9a3cc6bf0bea8aa91e4d5e752c7eb46b2e023edbc07d24a7c460a34a9a
```

已知`p+q`和`(p+1)(p+1)`，由`(p+1)(q+1) = p×q+p+q+1`可得`n = p×q`，即`n = (p+1)(q+1)-(p+q)-1`。

编写`Python`代码求解，得到`flag{cc7490e-78ab-11e9-b422-8ba97e5da1fd}`，提交即可。

```python
import libnum

a = 0x1232fecb92adead91613e7d9ae5e36fe6bb765317d6ed38ad890b4073539a6231a6620584cea5730b5af83a3e80cf30141282c97be4400e33307573af6b25e2ea
b = 0x5248becef1d925d45705a7302700d6a0ffe5877fddf9451a9c1181c4d82365806085fd86fbaab08b6fc66a967b2566d743c626547203b34ea3fdb1bc06dd3bb765fd8b919e3bd2cb15bc175c9498f9d9a0e216c2dde64d81255fa4c05a1ee619fc1fc505285a239e7bc655ec6605d9693078b800ee80931a7a0c84f33c851740
e = 0xe6b1bee47bd63f615c7d0a43c529d219
d = 0x2dde7fbaed477f6d62838d55b0d0964868cf6efb2c282a5f13e6008ce7317a24cb57aec49ef0d738919f47cdcd9677cd52ac2293ec5938aa198f962678b5cd0da344453f521a69b2ac03647cdd8339f4e38cec452d54e60698833d67f9315c02ddaa4c79ebaa902c605d7bda32ce970541b2d9a17d62b52df813b2fb0c5ab1a5
enc_flag = 0x50ae00623211ba6089ddfae21e204ab616f6c9d294e913550af3d66e85d0c0693ed53ed55c46d8cca1d7c2ad44839030df26b70f22a8567171a759b76fe5f07b3c5a6ec89117ed0a36c0950956b9cde880c575737f779143f921d745ac3bb0e379c05d9a3cc6bf0bea8aa91e4d5e752c7eb46b2e023edbc07d24a7c460a34a9a

n = b-a-1
m = pow(enc_flag,d,n)
flag = libnum.n2s(m).decode()
print(flag) # flag{cc7490e-78ab-11e9-b422-8ba97e5da1fd}
```

------

### ❤[[GWCTF 2019]BabyRSA](https://buuoj.cn/challenges#[GWCTF%202019]BabyRSA)

附件解压缩后得到`encrypt.py`和`secret`，其中`encrypt.py`源码如下：

```python
import hashlib
import sympy
from Crypto.Util.number import *

flag = 'GWHT{******}'
secret = '******'

assert(len(flag) == 38)

half = len(flag) / 2

flag1 = flag[:half]
flag2 = flag[half:]

secret_num = getPrime(1024) * bytes_to_long(secret)

p = sympy.nextprime(secret_num)
q = sympy.nextprime(p)

N = p * q

e = 0x10001

F1 = bytes_to_long(flag1)
F2 = bytes_to_long(flag2)

c1 = F1 + F2
c2 = pow(F1, 3) + pow(F2, 3)
assert(c2 < N)

m1 = pow(c1, e, N)
m2 = pow(c2, e, N)

output = open('secret', 'w')
output.write('N=' + str(N) + '\n')
output.write('m1=' + str(m1) + '\n')
output.write('m2=' + str(m2) + '\n')
output.close()
```

`secret`中的内容如下：

```python
N=636585149594574746909030160182690866222909256464847291783000651837227921337237899651287943597773270944384034858925295744880727101606841413640006527614873110651410155893776548737823152943797884729130149758279127430044739254000426610922834573094957082589539445610828279428814524313491262061930512829074466232633130599104490893572093943832740301809630847541592548921200288222432789208650949937638303429456468889100192613859073752923812454212239908948930178355331390933536771065791817643978763045030833712326162883810638120029378337092938662174119747687899484603628344079493556601422498405360731958162719296160584042671057160241284852522913676264596201906163
m1=90009974341452243216986938028371257528604943208941176518717463554774967878152694586469377765296113165659498726012712288670458884373971419842750929287658640266219686646956929872115782173093979742958745121671928568709468526098715927189829600497283118051641107305128852697032053368115181216069626606165503465125725204875578701237789292966211824002761481815276666236869005129138862782476859103086726091860497614883282949955023222414333243193268564781621699870412557822404381213804026685831221430728290755597819259339616650158674713248841654338515199405532003173732520457813901170264713085107077001478083341339002069870585378257051150217511755761491021553239
m2=487443985757405173426628188375657117604235507936967522993257972108872283698305238454465723214226871414276788912058186197039821242912736742824080627680971802511206914394672159240206910735850651999316100014691067295708138639363203596244693995562780286637116394738250774129759021080197323724805414668042318806010652814405078769738548913675466181551005527065309515364950610137206393257148357659666687091662749848560225453826362271704292692847596339533229088038820532086109421158575841077601268713175097874083536249006018948789413238783922845633494023608865256071962856581229890043896939025613600564283391329331452199062858930374565991634191495137939574539546
```

加密算法中首先给定`flag`长度是`38`个字符，再将`flag`分成两部分；接着用`nextprime()`生成两个素数`p`和`q`，其中`q`是`p`的下一个素数。这两个质数非常接近，就没必要用http://factordb.com来分解模数`N`得到`p`和`q`啦。这题可以把`N`开平方，所得结果的`nextprime()`就是`q`，而`p = N//q`，`RSA`求解得到`c1`和`c2`，再通过`sympy`求解两个关系式得到`F1`和`F2`，最后把它们转换成字符串拼接即可得到`GWHT{f709e0e2cfe7e530ca8972959a1033b2}`，提交`flag{f709e0e2cfe7e530ca8972959a1033b2}`。

```python
import sympy
from libnum import *
from math import isqrt

N=636585149594574746909030160182690866222909256464847291783000651837227921337237899651287943597773270944384034858925295744880727101606841413640006527614873110651410155893776548737823152943797884729130149758279127430044739254000426610922834573094957082589539445610828279428814524313491262061930512829074466232633130599104490893572093943832740301809630847541592548921200288222432789208650949937638303429456468889100192613859073752923812454212239908948930178355331390933536771065791817643978763045030833712326162883810638120029378337092938662174119747687899484603628344079493556601422498405360731958162719296160584042671057160241284852522913676264596201906163
m1=90009974341452243216986938028371257528604943208941176518717463554774967878152694586469377765296113165659498726012712288670458884373971419842750929287658640266219686646956929872115782173093979742958745121671928568709468526098715927189829600497283118051641107305128852697032053368115181216069626606165503465125725204875578701237789292966211824002761481815276666236869005129138862782476859103086726091860497614883282949955023222414333243193268564781621699870412557822404381213804026685831221430728290755597819259339616650158674713248841654338515199405532003173732520457813901170264713085107077001478083341339002069870585378257051150217511755761491021553239
m2=487443985757405173426628188375657117604235507936967522993257972108872283698305238454465723214226871414276788912058186197039821242912736742824080627680971802511206914394672159240206910735850651999316100014691067295708138639363203596244693995562780286637116394738250774129759021080197323724805414668042318806010652814405078769738548913675466181551005527065309515364950610137206393257148357659666687091662749848560225453826362271704292692847596339533229088038820532086109421158575841077601268713175097874083536249006018948789413238783922845633494023608865256071962856581229890043896939025613600564283391329331452199062858930374565991634191495137939574539546
e = 0x10001
x = isqrt(N)
q = sympy.nextprime(x)
p = N//q
# print(p, q)
# p = 797862863902421984951231350430312260517773269684958456342860983236184129602390919026048496119757187702076499551310794177917920137646835888862706126924088411570997141257159563952725882214181185531209186972351469946269508511312863779123205322378452194261217016552527754513215520329499967108196968833163329724620251096080377747699

# q = 797862863902421984951231350430312260517773269684958456342860983236184129602390919026048496119757187702076499551310794177917920137646835888862706126924088411570997141257159563952725882214181185531209186972351469946269508511312863779123205322378452194261217016552527754513215520329499967108196968833163329724620251096080377748737
d = invmod(e, (p-1)*(q-1))
c1 = pow(m1, d, N)
c2 = pow(m2, d, N)
F1 = sympy.Symbol('F1')
F2 = sympy.Symbol('F2')
f1 = F1+F2-c1
f2 = pow(F1, 3)+pow(F2, 3)-c2
result = sympy.solve([f1,f2],[F1,F2])
flag1 = n2s(int(result[1][0]))
flag2 = n2s(int(result[1][1]))
flag = flag1+flag2
print(flag.decode()) # GWHT{f709e0e2cfe7e530ca8972959a1033b2}
```

------

### [[HDCTF2019]basic rsa](https://buuoj.cn/challenges#[HDCTF2019]basic%20rsa)

附件解压缩后得到`.py`文件，源码如下：

```python
import gmpy2
from Crypto.Util.number import *
from binascii import a2b_hex,b2a_hex

flag = "*****************"

p = 262248800182277040650192055439906580479
q = 262854994239322828547925595487519915551

e = 65533
n = p*q

c = pow(int(b2a_hex(flag),16),e,n)

print c

# 27565231154623519221597938803435789010285480123476977081867877272451638645710
```

已知`p`，`q`，`e`和`c`，真的是很基础、很常规的`RSA`题。编写`Python`代码进行求解，得到`flag{B4by_Rs4}`。

```python
from libnum import *

p = 262248800182277040650192055439906580479
q = 262854994239322828547925595487519915551
e = 65533
c = 27565231154623519221597938803435789010285480123476977081867877272451638645710
n = p*q
d = invmod(e, (p-1)*(q-1))
m = pow(c, d, n)
flag = n2s(m).decode()
print(flag) # flag{B4by_Rs4}
```

------

### [Dangerous RSA](https://buuoj.cn/challenges#Dangerous%20RSA)

附件解压缩后，内容如下：

```python
#n:  0x52d483c27cd806550fbe0e37a61af2e7cf5e0efb723dfc81174c918a27627779b21fa3c851e9e94188eaee3d5cd6f752406a43fbecb53e80836ff1e185d3ccd7782ea846c2e91a7b0808986666e0bdadbfb7bdd65670a589a4d2478e9adcafe97c6ee23614bcb2ecc23580f4d2e3cc1ecfec25c50da4bc754dde6c8bfd8d1fc16956c74d8e9196046a01dc9f3024e11461c294f29d7421140732fedacac97b8fe50999117d27943c953f18c4ff4f8c258d839764078d4b6ef6e8591e0ff5563b31a39e6374d0d41c8c46921c25e5904a817ef8e39e5c9b71225a83269693e0b7e3218fc5e5a1e8412ba16e588b3d6ac536dce39fcdfce81eec79979ea6872793
#e:  0x3
#c:0x10652cdfaa6b63f6d7bd1109da08181e500e5643f5b240a9024bfa84d5f2cac9310562978347bb232d63e7289283871efab83d84ff5a7b64a94a79d34cfbd4ef121723ba1f663e514f83f6f01492b4e13e1bb4296d96ea5a353d3bf2edd2f449c03c4a3e995237985a596908adc741f32365
so,how to get the message?
```

已知`n`，`e`和`c`，可以对`n`进行因数分解得到`p`和`q`，然后用常规`RSA`题求解方法获取`flag`。但是这题想考察的是低加密指数攻击，因为公钥中的加密指数`e = 3`很小，但是模数`n`又很大。低加密指数攻击的原理如下：

> RSA加密公式：c = m^e%n
>
> 1. 当 m^e < n 时，c = m^e 
>
>    因此，对密文 c 开 e 次方根就能得到明文 m
>
> 2. 当 m^e > n 时，假设 m^e / n 的商为 i，余数为c，则 Ｍ^e = i×n + C
>
>    对 i 进行爆破，当满足 ( i*n + c) 开 e 次方根时就得到了明文 m

编写`Python`代码进行求解，得到`flag{25df8caf006ee5db94d48144c33b2c3b}`，提交即可。

```python
from gmpy2 import *
from libnum import n2s

n = 0x52d483c27cd806550fbe0e37a61af2e7cf5e0efb723dfc81174c918a27627779b21fa3c851e9e94188eaee3d5cd6f752406a43fbecb53e80836ff1e185d3ccd7782ea846c2e91a7b0808986666e0bdadbfb7bdd65670a589a4d2478e9adcafe97c6ee23614bcb2ecc23580f4d2e3cc1ecfec25c50da4bc754dde6c8bfd8d1fc16956c74d8e9196046a01dc9f3024e11461c294f29d7421140732fedacac97b8fe50999117d27943c953f18c4ff4f8c258d839764078d4b6ef6e8591e0ff5563b31a39e6374d0d41c8c46921c25e5904a817ef8e39e5c9b71225a83269693e0b7e3218fc5e5a1e8412ba16e588b3d6ac536dce39fcdfce81eec79979ea6872793L
e = 0x3
c = 0x10652cdfaa6b63f6d7bd1109da08181e500e5643f5b240a9024bfa84d5f2cac9310562978347bb232d63e7289283871efab83d84ff5a7b64a94a79d34cfbd4ef121723ba1f663e514f83f6f01492b4e13e1bb4296d96ea5a353d3bf2edd2f449c03c4a3e995237985a596908adc741f32365
i = 0
while True:
    m, ok = iroot(c+i*n, e)
    if ok:
        flag = n2s(int(m)).decode()
        break
    i += 1

print(flag) # flag{25df8caf006ee5db94d48144c33b2c3b}
```

------

### [rsa2](https://buuoj.cn/challenges#rsa2)

这题是[Rsa-1](#Rsa-1)的`PLUS`版，很相似的两道题。附件解压缩后得到的`.py`文件源码如下：

```python
N = 101991809777553253470276751399264740131157682329252673501792154507006158434432009141995367241962525705950046253400188884658262496534706438791515071885860897552736656899566915731297225817250639873643376310103992170646906557242832893914902053581087502512787303322747780420210884852166586717636559058152544979471
e = 46731919563265721307105180410302518676676135509737992912625092976849075262192092549323082367518264378630543338219025744820916471913696072050291990620486581719410354385121760761374229374847695148230596005409978383369740305816082770283909611956355972181848077519920922059268376958811713365106925235218265173085

import hashlib
flag = "flag{" + hashlib.md5(hex(d)).hexdigest() + "}"
```

调用`requests`库在线请求 http://factordb.com 分解模数`n`，得到`p`和`q`，算出 `φ(n) = (p-1)(q-1)`，进而得到私钥的解密质数`d`。

编写`Python`代码进行求解得到`flag{8159e6c4abdd3b94ce461ed9a1a24017}`，提交报错！后来了解到是因为 `python3 `和 `python2 `的 `hex(d) `运算结果差了一个字符 `'L' `，所以 `md5()`结果值不一样，补上即可，提交`flag{47bf28da384590448e0b0d23909a25a4}`正确。

```python
import requests
from gmpy2 import invert

def factorize(n):
    l = []
    url="http://factordb.com/api?query="+str(n)
    r = requests.get(url)
    data = r.json()
    for factor in data['factors']:
        l.append(int(factor[0]))
    return l

N = 101991809777553253470276751399264740131157682329252673501792154507006158434432009141995367241962525705950046253400188884658262496534706438791515071885860897552736656899566915731297225817250639873643376310103992170646906557242832893914902053581087502512787303322747780420210884852166586717636559058152544979471
e = 46731919563265721307105180410302518676676135509737992912625092976849075262192092549323082367518264378630543338219025744820916471913696072050291990620486581719410354385121760761374229374847695148230596005409978383369740305816082770283909611956355972181848077519920922059268376958811713365106925235218265173085
q, p = factorize(N)
d = invert(e, (p-1)*(q-1))

import hashlib
flag = "flag{" + hashlib.md5(hex(d).encode()).hexdigest() + "}"
print(flag) # flag{8159e6c4abdd3b94ce461ed9a1a24017} 提交报错 fake flag!
# 因为python3和python2的hex(d)运算结果差了一个字符'L' 所以md5值不一样 补上即可
flag = "flag{" + hashlib.md5((hex(d)+'L').encode()).hexdigest() + "}"
print(flag) # flag{47bf28da384590448e0b0d23909a25a4}
```

------

### [RSA5](https://buuoj.cn/challenges#RSA5)

附件解压缩后得到`.txt`，内容如下：

```python
m = xxxxxxxx
e = 65537
========== n c ==========
n = 20474918894051778533305262345601880928088284471121823754049725354072477155873778848055073843345820697886641086842612486541250183965966001591342031562953561793332341641334302847996108417466360688139866505179689516589305636902137210185624650854906780037204412206309949199080005576922775773722438863762117750429327585792093447423980002401200613302943834212820909269713876683465817369158585822294675056978970612202885426436071950214538262921077409076160417436699836138801162621314845608796870206834704116707763169847387223307828908570944984416973019427529790029089766264949078038669523465243837675263858062854739083634207
c = 974463908243330865728978769213595400782053398596897741316275722596415018912929508637393850919224969271766388710025195039896961956062895570062146947736340342927974992616678893372744261954172873490878805483241196345881721164078651156067119957816422768524442025688079462656755605982104174001635345874022133045402344010045961111720151990412034477755851802769069309069018738541854130183692204758761427121279982002993939745343695671900015296790637464880337375511536424796890996526681200633086841036320395847725935744757993013352804650575068136129295591306569213300156333650910795946800820067494143364885842896291126137320

n = 20918819960648891349438263046954902210959146407860980742165930253781318759285692492511475263234242002509419079545644051755251311392635763412553499744506421566074721268822337321637265942226790343839856182100575539845358877493718334237585821263388181126545189723429262149630651289446553402190531135520836104217160268349688525168375213462570213612845898989694324269410202496871688649978370284661017399056903931840656757330859626183773396574056413017367606446540199973155630466239453637232936904063706551160650295031273385619470740593510267285957905801566362502262757750629162937373721291789527659531499435235261620309759
c = 15819636201971185538694880505120469332582151856714070824521803121848292387556864177196229718923770810072104155432038682511434979353089791861087415144087855679134383396897817458726543883093567600325204596156649305930352575274039425470836355002691145864435755333821133969266951545158052745938252574301327696822347115053614052423028835532509220641378760800693351542633860702225772638930501021571415907348128269681224178300248272689705308911282208685459668200507057183420662959113956077584781737983254788703048275698921427029884282557468334399677849962342196140864403989162117738206246183665814938783122909930082802031855

n = 25033254625906757272369609119214202033162128625171246436639570615263949157363273213121556825878737923265290579551873824374870957467163989542063489416636713654642486717219231225074115269684119428086352535471683359486248203644461465935500517901513233739152882943010177276545128308412934555830087776128355125932914846459470221102007666912211992310538890654396487111705385730502843589727289829692152177134753098649781412247065660637826282055169991824099110916576856188876975621376606634258927784025787142263367152947108720757222446686415627479703666031871635656314282727051189190889008763055811680040315277078928068816491
c = 4185308529416874005831230781014092407198451385955677399668501833902623478395669279404883990725184332709152443372583701076198786635291739356770857286702107156730020004358955622511061410661058982622055199736820808203841446796305284394651714430918690389486920560834672316158146453183789412140939029029324756035358081754426645160033262924330248675216108270980157049705488620263485129480952814764002865280019185127662449318324279383277766416258142275143923532168798413011028271543085249029048997452212503111742302302065401051458066585395360468447460658672952851643547193822775218387853623453638025492389122204507555908862

n = 21206968097314131007183427944486801953583151151443627943113736996776787181111063957960698092696800555044199156765677935373149598221184792286812213294617749834607696302116136745662816658117055427803315230042700695125718401646810484873064775005221089174056824724922160855810527236751389605017579545235876864998419873065217294820244730785120525126565815560229001887622837549118168081685183371092395128598125004730268910276024806808565802081366898904032509920453785997056150497645234925528883879419642189109649009132381586673390027614766605038951015853086721168018787523459264932165046816881682774229243688581614306480751
c = 4521038011044758441891128468467233088493885750850588985708519911154778090597136126150289041893454126674468141393472662337350361712212694867311622970440707727941113263832357173141775855227973742571088974593476302084111770625764222838366277559560887042948859892138551472680654517814916609279748365580610712259856677740518477086531592233107175470068291903607505799432931989663707477017904611426213770238397005743730386080031955694158466558475599751940245039167629126576784024482348452868313417471542956778285567779435940267140679906686531862467627238401003459101637191297209422470388121802536569761414457618258343550613

n = 22822039733049388110936778173014765663663303811791283234361230649775805923902173438553927805407463106104699773994158375704033093471761387799852168337898526980521753614307899669015931387819927421875316304591521901592823814417756447695701045846773508629371397013053684553042185725059996791532391626429712416994990889693732805181947970071429309599614973772736556299404246424791660679253884940021728846906344198854779191951739719342908761330661910477119933428550774242910420952496929605686154799487839923424336353747442153571678064520763149793294360787821751703543288696726923909670396821551053048035619499706391118145067
c = 15406498580761780108625891878008526815145372096234083936681442225155097299264808624358826686906535594853622687379268969468433072388149786607395396424104318820879443743112358706546753935215756078345959375299650718555759698887852318017597503074317356745122514481807843745626429797861463012940172797612589031686718185390345389295851075279278516147076602270178540690147808314172798987497259330037810328523464851895621851859027823681655934104713689539848047163088666896473665500158179046196538210778897730209572708430067658411755959866033531700460551556380993982706171848970460224304996455600503982223448904878212849412357

n = 21574139855341432908474064784318462018475296809327285532337706940126942575349507668289214078026102682252713757703081553093108823214063791518482289846780197329821139507974763780260290309600884920811959842925540583967085670848765317877441480914852329276375776405689784571404635852204097622600656222714808541872252335877037561388406257181715278766652824786376262249274960467193961956690974853679795249158751078422296580367506219719738762159965958877806187461070689071290948181949561254144310776943334859775121650186245846031720507944987838489723127897223416802436021278671237227993686791944711422345000479751187704426369
c = 20366856150710305124583065375297661819795242238376485264951185336996083744604593418983336285185491197426018595031444652123288461491879021096028203694136683203441692987069563513026001861435722117985559909692670907347563594578265880806540396777223906955491026286843168637367593400342814725694366078337030937104035993569672959361347287894143027186846856772983058328919716702982222142848848117768499996617588305301483085428547267337070998767412540225911508196842253134355901263861121500650240296746702967594224401650220168780537141654489215019142122284308116284129004257364769474080721001708734051264841350424152506027932

n = 25360227412666612490102161131174584819240931803196448481224305250583841439581008528535930814167338381983764991296575637231916547647970573758269411168219302370541684789125112505021148506809643081950237623703181025696585998044695691322012183660424636496897073045557400768745943787342548267386564625462143150176113656264450210023925571945961405709276631990731602198104287528528055650050486159837612279600415259486306154947514005408907590083747758953115486124865486720633820559135063440942528031402951958557630833503775112010715604278114325528993771081233535247118481765852273252404963430792898948219539473312462979849137
c = 19892772524651452341027595619482734356243435671592398172680379981502759695784087900669089919987705675899945658648623800090272599154590123082189645021800958076861518397325439521139995652026377132368232502108620033400051346127757698623886142621793423225749240286511666556091787851683978017506983310073524398287279737680091787333547538239920607761080988243639547570818363788673249582783015475682109984715293163137324439862838574460108793714172603672477766831356411304446881998674779501188163600664488032943639694828698984739492200699684462748922883550002652913518229322945040819064133350314536378694523704793396169065179

n = 22726855244632356029159691753451822163331519237547639938779517751496498713174588935566576167329576494790219360727877166074136496129927296296996970048082870488804456564986667129388136556137013346228118981936899510687589585286517151323048293150257036847475424044378109168179412287889340596394755257704938006162677656581509375471102546261355748251869048003600520034656264521931808651038524134185732929570384705918563982065684145766427962502261522481994191989820110575981906998431553107525542001187655703534683231777988419268338249547641335718393312295800044734534761692799403469497954062897856299031257454735945867491191
c = 6040119795175856407541082360023532204614723858688636724822712717572759793960246341800308149739809871234313049629732934797569781053000686185666374833978403290525072598774001731350244744590772795701065129561898116576499984185920661271123665356132719193665474235596884239108030605882777868856122378222681140570519180321286976947154042272622411303981011302586225630859892731724640574658125478287115198406253847367979883768000812605395482952698689604477719478947595442185921480652637868335673233200662100621025061500895729605305665864693122952557361871523165300206070325660353095592778037767395360329231331322823610060006

n = 23297333791443053297363000786835336095252290818461950054542658327484507406594632785712767459958917943095522594228205423428207345128899745800927319147257669773812669542782839237744305180098276578841929496345963997512244219376701787616046235397139381894837435562662591060768476997333538748065294033141610502252325292801816812268934171361934399951548627267791401089703937389012586581080223313060159456238857080740699528666411303029934807011214953984169785844714159627792016926490955282697877141614638806397689306795328344778478692084754216753425842557818899467945102646776342655167655384224860504086083147841252232760941
c = 5418120301208378713115889465579964257871814114515046096090960159737859076829258516920361577853903925954198406843757303687557848302302200229295916902430205737843601806700738234756698575708612424928480440868739120075888681672062206529156566421276611107802917418993625029690627196813830326369874249777619239603300605876865967515719079797115910578653562787899019310139945904958024882417833736304894765433489476234575356755275147256577387022873348906900149634940747104513850154118106991137072643308620284663108283052245750945228995387803432128842152251549292698947407663643895853432650029352092018372834457054271102816934

n = 28873667904715682722987234293493200306976947898711255064125115933666968678742598858722431426218914462903521596341771131695619382266194233561677824357379805303885993804266436810606263022097900266975250431575654686915049693091467864820512767070713267708993899899011156106766178906700336111712803362113039613548672937053397875663144794018087017731949087794894903737682383916173267421403408140967713071026001874733487295007501068871044649170615709891451856792232315526696220161842742664778581287321318748202431466508948902745314372299799561625186955234673012098210919745879882268512656931714326782335211089576897310591491
c = 9919880463786836684987957979091527477471444996392375244075527841865509160181666543016317634963512437510324198702416322841377489417029572388474450075801462996825244657530286107428186354172836716502817609070590929769261932324275353289939302536440310628698349244872064005700644520223727670950787924296004296883032978941200883362653993351638545860207179022472492671256630427228461852668118035317021428675954874947015197745916918197725121122236369382741533983023462255913924692806249387449016629865823316402366017657844166919846683497851842388058283856219900535567427103603869955066193425501385255322097901531402103883869

n = 22324685947539653722499932469409607533065419157347813961958075689047690465266404384199483683908594787312445528159635527833904475801890381455653807265501217328757871352731293000303438205315816792663917579066674842307743845261771032363928568844669895768092515658328756229245837025261744260614860746997931503548788509983868038349720225305730985576293675269073709022350700836510054067641753713212999954307022524495885583361707378513742162566339010134354907863733205921845038918224463903789841881400814074587261720283879760122070901466517118265422863420376921536734845502100251460872499122236686832189549698020737176683019
c = 1491527050203294989882829248560395184804977277747126143103957219164624187528441047837351263580440686474767380464005540264627910126483129930668344095814547592115061057843470131498075060420395111008619027199037019925701236660166563068245683975787762804359520164701691690916482591026138582705558246869496162759780878437137960823000043988227303003876410503121370163303711603359430764539337597866862508451528158285103251810058741879687875218384160282506172706613359477657215420734816049393339593755489218588796607060261897905233453268671411610631047340459487937479511933450369462213795738933019001471803157607791738538467

n = 27646746423759020111007828653264027999257847645666129907789026054594393648800236117046769112762641778865620892443423100189619327585811384883515424918752749559627553637785037359639801125213256163008431942593727931931898199727552768626775618479833029101249692573716030706695702510982283555740851047022672485743432464647772882314215176114732257497240284164016914018689044557218920300262234652840632406067273375269301008409860193180822366735877288205783314326102263756503786736122321348320031950012144905869556204017430593656052867939493633163499580242224763404338807022510136217187779084917996171602737036564991036724299
c = 21991524128957260536043771284854920393105808126700128222125856775506885721971193109361315961129190814674647136464887087893990660894961612838205086401018885457667488911898654270235561980111174603323721280911197488286585269356849579263043456316319476495888696219344219866516861187654180509247881251251278919346267129904739277386289240394384575124331135655943513831009934023397457082184699737734388823763306805326430395849935770213817533387235486307008892410920611669932693018165569417445885810825749609388627231235840912644654685819620931663346297596334834498661789016450371769203650109994771872404185770230172934013971

n = 20545487405816928731738988374475012686827933709789784391855706835136270270933401203019329136937650878386117187776530639342572123237188053978622697282521473917978282830432161153221216194169879669541998840691383025487220850872075436064308499924958517979727954402965612196081404341651517326364041519250125036424822634354268773895465698920883439222996581226358595873993976604699830613932320720554130011671297944433515047180565484495191003887599891289037982010216357831078328159028953222056918189365840711588671093333013117454034313622855082795813122338562446223041211192277089225078324682108033843023903550172891959673551
c = 14227439188191029461250476692790539654619199888487319429114414557975376308688908028140817157205579804059783807641305577385724758530138514972962209062230576107406142402603484375626077345190883094097636019771377866339531511965136650567412363889183159616188449263752475328663245311059988337996047359263288837436305588848044572937759424466586870280512424336807064729894515840552404756879590698797046333336445465120445087587621743906624279621779634772378802959109714400516183718323267273824736540168545946444437586299214110424738159957388350785999348535171553569373088251552712391288365295267665691357719616011613628772175

n = 27359727711584277234897157724055852794019216845229798938655814269460046384353568138598567755392559653460949444557879120040796798142218939251844762461270251672399546774067275348291003962551964648742053215424620256999345448398805278592777049668281558312871773979931343097806878701114056030041506690476954254006592555275342579529625231194321357904668512121539514880704046969974898412095675082585315458267591016734924646294357666924293908418345508902112711075232047998775303603175363964055048589769318562104883659754974955561725694779754279606726358588862479198815999276839234952142017210593887371950645418417355912567987
c = 3788529784248255027081674540877016372807848222776887920453488878247137930578296797437647922494510483767651150492933356093288965943741570268943861987024276610712717409139946409513963043114463933146088430004237747163422802959250296602570649363016151581364006795894226599584708072582696996740518887606785460775851029814280359385763091078902301957226484620428513604630585131511167015763190591225884202772840456563643159507805711004113901417503751181050823638207803533111429510911616160851391754754434764819568054850823810901159821297849790005646102129354035735350124476838786661542089045509656910348676742844957008857457

n = 27545937603751737248785220891735796468973329738076209144079921449967292572349424539010502287564030116831261268197384650511043068738911429169730640135947800885987171539267214611907687570587001933829208655100828045651391618089603288456570334500533178695238407684702251252671579371018651675054368606282524673369983034682330578308769886456335818733827237294570476853673552685361689144261552895758266522393004116017849397346259119221063821663280935820440671825601452417487330105280889520007917979115568067161590058277418371493228631232457972494285014767469893647892888681433965857496916110704944758070268626897045014782837
c = 14069112970608895732417039977542732665796601893762401500878786871680645798754783315693511261740059725171342404186571066972546332813667711135661176659424619936101038903439144294886379322591635766682645179888058617577572409307484708171144488708410543462972008179994594087473935638026612679389759756811490524127195628741262871304427908481214992471182859308828778119005750928935764927967212343526503410515793717201360360437981322576798056276657140363332700714732224848346808963992302409037706094588964170239521193589470070839790404597252990818583717869140229811712295005710540476356743378906642267045723633874011649259842

n = 25746162075697911560263181791216433062574178572424600336856278176112733054431463253903433128232709054141607100891177804285813783247735063753406524678030561284491481221681954564804141454666928657549670266775659862814924386584148785453647316864935942772919140563506305666207816897601862713092809234429096584753263707828899780979223118181009293655563146526792388913462557306433664296966331469906428665127438829399703002867800269947855869262036714256550075520193125987011945192273531732276641728008406855871598678936585324782438668746810516660152018244253008092470066555687277138937298747951929576231036251316270602513451
c = 17344284860275489477491525819922855326792275128719709401292545608122859829827462088390044612234967551682879954301458425842831995513832410355328065562098763660326163262033200347338773439095709944202252494552172589503915965931524326523663289777583152664722241920800537867331030623906674081852296232306336271542832728410803631170229642717524942332390842467035143631504401140727083270732464237443915263865880580308776111219718961746378842924644142127243573824972533819479079381023103585862099063382129757560124074676150622288706094110075567706403442920696472627797607697962873026112240527498308535903232663939028587036724

n = 23288486934117120315036919418588136227028485494137930196323715336208849327833965693894670567217971727921243839129969128783853015760155446770590696037582684845937132790047363216362087277861336964760890214059732779383020349204803205725870225429985939570141508220041286857810048164696707018663758416807708910671477407366098883430811861933014973409390179948577712579749352299440310543689035651465399867908428885541237776143404376333442949397063249223702355051571790555151203866821867908531733788784978667478707672984539512431549558672467752712004519300318999208102076732501412589104904734983789895358753664077486894529499
c = 10738254418114076548071448844964046468141621740603214384986354189105236977071001429271560636428075970459890958274941762528116445171161040040833357876134689749846940052619392750394683504816081193432350669452446113285638982551762586656329109007214019944975816434827768882704630460001209452239162896576191876324662333153835533956600295255158377025198426950944040643235430211011063586032467724329735785947372051759042138171054165854842472990583800899984893232549092766400510300083585513014171220423103452292891496141806956300396540682381668367564569427813092064053993103537635994311143010708814851867239706492577203899024

n = 19591441383958529435598729113936346657001352578357909347657257239777540424811749817783061233235817916560689138344041497732749011519736303038986277394036718790971374656832741054547056417771501234494768509780369075443550907847298246275717420562375114406055733620258777905222169702036494045086017381084272496162770259955811174440490126514747876661317750649488774992348005044389081101686016446219264069971370646319546429782904810063020324704138495608761532563310699753322444871060383693044481932265801505819646998535192083036872551683405766123968487907648980900712118052346174533513978009131757167547595857552370586353973
c = 3834917098887202931981968704659119341624432294759361919553937551053499607440333234018189141970246302299385742548278589896033282894981200353270637127213483172182529890495903425649116755901631101665876301799865612717750360089085179142750664603454193642053016384714515855868368723508922271767190285521137785688075622832924829248362774476456232826885801046969384519549385428259591566716890844604696258783639390854153039329480726205147199247183621535172450825979047132495439603840806501254997167051142427157381799890725323765558803808030109468048682252028720241357478614704610089120810367192414352034177484688502364022887

n = 19254242571588430171308191757871261075358521158624745702744057556054652332495961196795369630484782930292003238730267396462491733557715379956969694238267908985251699834707734400775311452868924330866502429576951934279223234676654749272932769107390976321208605516299532560054081301829440688796904635446986081691156842271268059970762004259219036753174909942343204432795076377432107630203621754552804124408792358220071862369443201584155711893388877350138023238624566616551246804054720492816226651467017802504094070614892556444425915920269485861799532473383304622064493223627552558344088839860178294589481899206318863310603
c = 6790553533991297205804561991225493105312398825187682250780197510784765226429663284220400480563039341938599783346724051076211265663468643826430109013245014035811178295081939958687087477312867720289964506097819762095244479129359998867671811819738196687884696680463458661374310994610760009474264115750204920875527434486437536623589684519411519100170291423367424938566820315486507444202022408003879118465761273916755290898112991525546114191064022991329724370064632569903856189236177894007766690782630247443895358893983735822824243487181851098787271270256780891094405121947631088729917398317652320497765101790132679171889

n = 26809700251171279102974962949184411136459372267620535198421449833298448092580497485301953796619185339316064387798092220298630428207556482805739803420279056191194360049651767412572609187680508073074653291350998253938793269214230457117194434853888765303403385824786231859450351212449404870776320297419712486574804794325602760347306432927281716160368830187944940128907971027838510079519466846176106565164730963988892400240063089397720414921398936399927948235195085202171264728816184532651138221862240969655185596628285814057082448321749567943946273776184657698104465062749244327092588237927996419620170254423837876806659
c = 386213556608434013769864727123879412041991271528990528548507451210692618986652870424632219424601677524265011043146748309774067894985069288067952546139416819404039688454756044862784630882833496090822568580572859029800646671301748901528132153712913301179254879877441322285914544974519727307311002330350534857867516466612474769753577858660075830592891403551867246057397839688329172530177187042229028685862036140779065771061933528137423019407311473581832405899089709251747002788032002094495379614686544672969073249309703482556386024622814731015767810042969813752548617464974915714425595351940266077021672409858645427346
```

给出了加密指数`e`和多组`n`和`c`，并且这些`n`和`c`都共有同一个明文`m`。循环遍历所有的`n`，两两计算找最大公约数，从而得到`p`和`q`，接着就是`RSA`常规求解啦。编写`Python`代码进行求解，得到`flag{abdcbe5fd94e23b3de429223ab9c2fdf}`，提交即可。

```python
from libnum import *

n0 = 20474918894051778533305262345601880928088284471121823754049725354072477155873778848055073843345820697886641086842612486541250183965966001591342031562953561793332341641334302847996108417466360688139866505179689516589305636902137210185624650854906780037204412206309949199080005576922775773722438863762117750429327585792093447423980002401200613302943834212820909269713876683465817369158585822294675056978970612202885426436071950214538262921077409076160417436699836138801162621314845608796870206834704116707763169847387223307828908570944984416973019427529790029089766264949078038669523465243837675263858062854739083634207
c0 = 974463908243330865728978769213595400782053398596897741316275722596415018912929508637393850919224969271766388710025195039896961956062895570062146947736340342927974992616678893372744261954172873490878805483241196345881721164078651156067119957816422768524442025688079462656755605982104174001635345874022133045402344010045961111720151990412034477755851802769069309069018738541854130183692204758761427121279982002993939745343695671900015296790637464880337375511536424796890996526681200633086841036320395847725935744757993013352804650575068136129295591306569213300156333650910795946800820067494143364885842896291126137320

n1 = 20918819960648891349438263046954902210959146407860980742165930253781318759285692492511475263234242002509419079545644051755251311392635763412553499744506421566074721268822337321637265942226790343839856182100575539845358877493718334237585821263388181126545189723429262149630651289446553402190531135520836104217160268349688525168375213462570213612845898989694324269410202496871688649978370284661017399056903931840656757330859626183773396574056413017367606446540199973155630466239453637232936904063706551160650295031273385619470740593510267285957905801566362502262757750629162937373721291789527659531499435235261620309759
c1 = 15819636201971185538694880505120469332582151856714070824521803121848292387556864177196229718923770810072104155432038682511434979353089791861087415144087855679134383396897817458726543883093567600325204596156649305930352575274039425470836355002691145864435755333821133969266951545158052745938252574301327696822347115053614052423028835532509220641378760800693351542633860702225772638930501021571415907348128269681224178300248272689705308911282208685459668200507057183420662959113956077584781737983254788703048275698921427029884282557468334399677849962342196140864403989162117738206246183665814938783122909930082802031855

n2 = 25033254625906757272369609119214202033162128625171246436639570615263949157363273213121556825878737923265290579551873824374870957467163989542063489416636713654642486717219231225074115269684119428086352535471683359486248203644461465935500517901513233739152882943010177276545128308412934555830087776128355125932914846459470221102007666912211992310538890654396487111705385730502843589727289829692152177134753098649781412247065660637826282055169991824099110916576856188876975621376606634258927784025787142263367152947108720757222446686415627479703666031871635656314282727051189190889008763055811680040315277078928068816491
c2 = 4185308529416874005831230781014092407198451385955677399668501833902623478395669279404883990725184332709152443372583701076198786635291739356770857286702107156730020004358955622511061410661058982622055199736820808203841446796305284394651714430918690389486920560834672316158146453183789412140939029029324756035358081754426645160033262924330248675216108270980157049705488620263485129480952814764002865280019185127662449318324279383277766416258142275143923532168798413011028271543085249029048997452212503111742302302065401051458066585395360468447460658672952851643547193822775218387853623453638025492389122204507555908862

n3 = 21206968097314131007183427944486801953583151151443627943113736996776787181111063957960698092696800555044199156765677935373149598221184792286812213294617749834607696302116136745662816658117055427803315230042700695125718401646810484873064775005221089174056824724922160855810527236751389605017579545235876864998419873065217294820244730785120525126565815560229001887622837549118168081685183371092395128598125004730268910276024806808565802081366898904032509920453785997056150497645234925528883879419642189109649009132381586673390027614766605038951015853086721168018787523459264932165046816881682774229243688581614306480751
c3 = 4521038011044758441891128468467233088493885750850588985708519911154778090597136126150289041893454126674468141393472662337350361712212694867311622970440707727941113263832357173141775855227973742571088974593476302084111770625764222838366277559560887042948859892138551472680654517814916609279748365580610712259856677740518477086531592233107175470068291903607505799432931989663707477017904611426213770238397005743730386080031955694158466558475599751940245039167629126576784024482348452868313417471542956778285567779435940267140679906686531862467627238401003459101637191297209422470388121802536569761414457618258343550613

n4 = 22822039733049388110936778173014765663663303811791283234361230649775805923902173438553927805407463106104699773994158375704033093471761387799852168337898526980521753614307899669015931387819927421875316304591521901592823814417756447695701045846773508629371397013053684553042185725059996791532391626429712416994990889693732805181947970071429309599614973772736556299404246424791660679253884940021728846906344198854779191951739719342908761330661910477119933428550774242910420952496929605686154799487839923424336353747442153571678064520763149793294360787821751703543288696726923909670396821551053048035619499706391118145067
c4 = 15406498580761780108625891878008526815145372096234083936681442225155097299264808624358826686906535594853622687379268969468433072388149786607395396424104318820879443743112358706546753935215756078345959375299650718555759698887852318017597503074317356745122514481807843745626429797861463012940172797612589031686718185390345389295851075279278516147076602270178540690147808314172798987497259330037810328523464851895621851859027823681655934104713689539848047163088666896473665500158179046196538210778897730209572708430067658411755959866033531700460551556380993982706171848970460224304996455600503982223448904878212849412357

n5 = 21574139855341432908474064784318462018475296809327285532337706940126942575349507668289214078026102682252713757703081553093108823214063791518482289846780197329821139507974763780260290309600884920811959842925540583967085670848765317877441480914852329276375776405689784571404635852204097622600656222714808541872252335877037561388406257181715278766652824786376262249274960467193961956690974853679795249158751078422296580367506219719738762159965958877806187461070689071290948181949561254144310776943334859775121650186245846031720507944987838489723127897223416802436021278671237227993686791944711422345000479751187704426369
c5 = 20366856150710305124583065375297661819795242238376485264951185336996083744604593418983336285185491197426018595031444652123288461491879021096028203694136683203441692987069563513026001861435722117985559909692670907347563594578265880806540396777223906955491026286843168637367593400342814725694366078337030937104035993569672959361347287894143027186846856772983058328919716702982222142848848117768499996617588305301483085428547267337070998767412540225911508196842253134355901263861121500650240296746702967594224401650220168780537141654489215019142122284308116284129004257364769474080721001708734051264841350424152506027932

n6 = 25360227412666612490102161131174584819240931803196448481224305250583841439581008528535930814167338381983764991296575637231916547647970573758269411168219302370541684789125112505021148506809643081950237623703181025696585998044695691322012183660424636496897073045557400768745943787342548267386564625462143150176113656264450210023925571945961405709276631990731602198104287528528055650050486159837612279600415259486306154947514005408907590083747758953115486124865486720633820559135063440942528031402951958557630833503775112010715604278114325528993771081233535247118481765852273252404963430792898948219539473312462979849137
c6 = 19892772524651452341027595619482734356243435671592398172680379981502759695784087900669089919987705675899945658648623800090272599154590123082189645021800958076861518397325439521139995652026377132368232502108620033400051346127757698623886142621793423225749240286511666556091787851683978017506983310073524398287279737680091787333547538239920607761080988243639547570818363788673249582783015475682109984715293163137324439862838574460108793714172603672477766831356411304446881998674779501188163600664488032943639694828698984739492200699684462748922883550002652913518229322945040819064133350314536378694523704793396169065179

n7 = 22726855244632356029159691753451822163331519237547639938779517751496498713174588935566576167329576494790219360727877166074136496129927296296996970048082870488804456564986667129388136556137013346228118981936899510687589585286517151323048293150257036847475424044378109168179412287889340596394755257704938006162677656581509375471102546261355748251869048003600520034656264521931808651038524134185732929570384705918563982065684145766427962502261522481994191989820110575981906998431553107525542001187655703534683231777988419268338249547641335718393312295800044734534761692799403469497954062897856299031257454735945867491191
c7 = 6040119795175856407541082360023532204614723858688636724822712717572759793960246341800308149739809871234313049629732934797569781053000686185666374833978403290525072598774001731350244744590772795701065129561898116576499984185920661271123665356132719193665474235596884239108030605882777868856122378222681140570519180321286976947154042272622411303981011302586225630859892731724640574658125478287115198406253847367979883768000812605395482952698689604477719478947595442185921480652637868335673233200662100621025061500895729605305665864693122952557361871523165300206070325660353095592778037767395360329231331322823610060006

n8 = 23297333791443053297363000786835336095252290818461950054542658327484507406594632785712767459958917943095522594228205423428207345128899745800927319147257669773812669542782839237744305180098276578841929496345963997512244219376701787616046235397139381894837435562662591060768476997333538748065294033141610502252325292801816812268934171361934399951548627267791401089703937389012586581080223313060159456238857080740699528666411303029934807011214953984169785844714159627792016926490955282697877141614638806397689306795328344778478692084754216753425842557818899467945102646776342655167655384224860504086083147841252232760941
c8 = 5418120301208378713115889465579964257871814114515046096090960159737859076829258516920361577853903925954198406843757303687557848302302200229295916902430205737843601806700738234756698575708612424928480440868739120075888681672062206529156566421276611107802917418993625029690627196813830326369874249777619239603300605876865967515719079797115910578653562787899019310139945904958024882417833736304894765433489476234575356755275147256577387022873348906900149634940747104513850154118106991137072643308620284663108283052245750945228995387803432128842152251549292698947407663643895853432650029352092018372834457054271102816934

n9 = 28873667904715682722987234293493200306976947898711255064125115933666968678742598858722431426218914462903521596341771131695619382266194233561677824357379805303885993804266436810606263022097900266975250431575654686915049693091467864820512767070713267708993899899011156106766178906700336111712803362113039613548672937053397875663144794018087017731949087794894903737682383916173267421403408140967713071026001874733487295007501068871044649170615709891451856792232315526696220161842742664778581287321318748202431466508948902745314372299799561625186955234673012098210919745879882268512656931714326782335211089576897310591491
c9 = 9919880463786836684987957979091527477471444996392375244075527841865509160181666543016317634963512437510324198702416322841377489417029572388474450075801462996825244657530286107428186354172836716502817609070590929769261932324275353289939302536440310628698349244872064005700644520223727670950787924296004296883032978941200883362653993351638545860207179022472492671256630427228461852668118035317021428675954874947015197745916918197725121122236369382741533983023462255913924692806249387449016629865823316402366017657844166919846683497851842388058283856219900535567427103603869955066193425501385255322097901531402103883869

n10 = 22324685947539653722499932469409607533065419157347813961958075689047690465266404384199483683908594787312445528159635527833904475801890381455653807265501217328757871352731293000303438205315816792663917579066674842307743845261771032363928568844669895768092515658328756229245837025261744260614860746997931503548788509983868038349720225305730985576293675269073709022350700836510054067641753713212999954307022524495885583361707378513742162566339010134354907863733205921845038918224463903789841881400814074587261720283879760122070901466517118265422863420376921536734845502100251460872499122236686832189549698020737176683019
c10 = 1491527050203294989882829248560395184804977277747126143103957219164624187528441047837351263580440686474767380464005540264627910126483129930668344095814547592115061057843470131498075060420395111008619027199037019925701236660166563068245683975787762804359520164701691690916482591026138582705558246869496162759780878437137960823000043988227303003876410503121370163303711603359430764539337597866862508451528158285103251810058741879687875218384160282506172706613359477657215420734816049393339593755489218588796607060261897905233453268671411610631047340459487937479511933450369462213795738933019001471803157607791738538467

n11 = 27646746423759020111007828653264027999257847645666129907789026054594393648800236117046769112762641778865620892443423100189619327585811384883515424918752749559627553637785037359639801125213256163008431942593727931931898199727552768626775618479833029101249692573716030706695702510982283555740851047022672485743432464647772882314215176114732257497240284164016914018689044557218920300262234652840632406067273375269301008409860193180822366735877288205783314326102263756503786736122321348320031950012144905869556204017430593656052867939493633163499580242224763404338807022510136217187779084917996171602737036564991036724299
c11 = 21991524128957260536043771284854920393105808126700128222125856775506885721971193109361315961129190814674647136464887087893990660894961612838205086401018885457667488911898654270235561980111174603323721280911197488286585269356849579263043456316319476495888696219344219866516861187654180509247881251251278919346267129904739277386289240394384575124331135655943513831009934023397457082184699737734388823763306805326430395849935770213817533387235486307008892410920611669932693018165569417445885810825749609388627231235840912644654685819620931663346297596334834498661789016450371769203650109994771872404185770230172934013971

n12 = 20545487405816928731738988374475012686827933709789784391855706835136270270933401203019329136937650878386117187776530639342572123237188053978622697282521473917978282830432161153221216194169879669541998840691383025487220850872075436064308499924958517979727954402965612196081404341651517326364041519250125036424822634354268773895465698920883439222996581226358595873993976604699830613932320720554130011671297944433515047180565484495191003887599891289037982010216357831078328159028953222056918189365840711588671093333013117454034313622855082795813122338562446223041211192277089225078324682108033843023903550172891959673551
c12 = 14227439188191029461250476692790539654619199888487319429114414557975376308688908028140817157205579804059783807641305577385724758530138514972962209062230576107406142402603484375626077345190883094097636019771377866339531511965136650567412363889183159616188449263752475328663245311059988337996047359263288837436305588848044572937759424466586870280512424336807064729894515840552404756879590698797046333336445465120445087587621743906624279621779634772378802959109714400516183718323267273824736540168545946444437586299214110424738159957388350785999348535171553569373088251552712391288365295267665691357719616011613628772175

n13 = 27359727711584277234897157724055852794019216845229798938655814269460046384353568138598567755392559653460949444557879120040796798142218939251844762461270251672399546774067275348291003962551964648742053215424620256999345448398805278592777049668281558312871773979931343097806878701114056030041506690476954254006592555275342579529625231194321357904668512121539514880704046969974898412095675082585315458267591016734924646294357666924293908418345508902112711075232047998775303603175363964055048589769318562104883659754974955561725694779754279606726358588862479198815999276839234952142017210593887371950645418417355912567987
c13 = 3788529784248255027081674540877016372807848222776887920453488878247137930578296797437647922494510483767651150492933356093288965943741570268943861987024276610712717409139946409513963043114463933146088430004237747163422802959250296602570649363016151581364006795894226599584708072582696996740518887606785460775851029814280359385763091078902301957226484620428513604630585131511167015763190591225884202772840456563643159507805711004113901417503751181050823638207803533111429510911616160851391754754434764819568054850823810901159821297849790005646102129354035735350124476838786661542089045509656910348676742844957008857457

n14 = 27545937603751737248785220891735796468973329738076209144079921449967292572349424539010502287564030116831261268197384650511043068738911429169730640135947800885987171539267214611907687570587001933829208655100828045651391618089603288456570334500533178695238407684702251252671579371018651675054368606282524673369983034682330578308769886456335818733827237294570476853673552685361689144261552895758266522393004116017849397346259119221063821663280935820440671825601452417487330105280889520007917979115568067161590058277418371493228631232457972494285014767469893647892888681433965857496916110704944758070268626897045014782837
c14 = 14069112970608895732417039977542732665796601893762401500878786871680645798754783315693511261740059725171342404186571066972546332813667711135661176659424619936101038903439144294886379322591635766682645179888058617577572409307484708171144488708410543462972008179994594087473935638026612679389759756811490524127195628741262871304427908481214992471182859308828778119005750928935764927967212343526503410515793717201360360437981322576798056276657140363332700714732224848346808963992302409037706094588964170239521193589470070839790404597252990818583717869140229811712295005710540476356743378906642267045723633874011649259842

n15 = 25746162075697911560263181791216433062574178572424600336856278176112733054431463253903433128232709054141607100891177804285813783247735063753406524678030561284491481221681954564804141454666928657549670266775659862814924386584148785453647316864935942772919140563506305666207816897601862713092809234429096584753263707828899780979223118181009293655563146526792388913462557306433664296966331469906428665127438829399703002867800269947855869262036714256550075520193125987011945192273531732276641728008406855871598678936585324782438668746810516660152018244253008092470066555687277138937298747951929576231036251316270602513451
c15 = 17344284860275489477491525819922855326792275128719709401292545608122859829827462088390044612234967551682879954301458425842831995513832410355328065562098763660326163262033200347338773439095709944202252494552172589503915965931524326523663289777583152664722241920800537867331030623906674081852296232306336271542832728410803631170229642717524942332390842467035143631504401140727083270732464237443915263865880580308776111219718961746378842924644142127243573824972533819479079381023103585862099063382129757560124074676150622288706094110075567706403442920696472627797607697962873026112240527498308535903232663939028587036724

n16 = 23288486934117120315036919418588136227028485494137930196323715336208849327833965693894670567217971727921243839129969128783853015760155446770590696037582684845937132790047363216362087277861336964760890214059732779383020349204803205725870225429985939570141508220041286857810048164696707018663758416807708910671477407366098883430811861933014973409390179948577712579749352299440310543689035651465399867908428885541237776143404376333442949397063249223702355051571790555151203866821867908531733788784978667478707672984539512431549558672467752712004519300318999208102076732501412589104904734983789895358753664077486894529499
c16 = 10738254418114076548071448844964046468141621740603214384986354189105236977071001429271560636428075970459890958274941762528116445171161040040833357876134689749846940052619392750394683504816081193432350669452446113285638982551762586656329109007214019944975816434827768882704630460001209452239162896576191876324662333153835533956600295255158377025198426950944040643235430211011063586032467724329735785947372051759042138171054165854842472990583800899984893232549092766400510300083585513014171220423103452292891496141806956300396540682381668367564569427813092064053993103537635994311143010708814851867239706492577203899024

n17 = 19591441383958529435598729113936346657001352578357909347657257239777540424811749817783061233235817916560689138344041497732749011519736303038986277394036718790971374656832741054547056417771501234494768509780369075443550907847298246275717420562375114406055733620258777905222169702036494045086017381084272496162770259955811174440490126514747876661317750649488774992348005044389081101686016446219264069971370646319546429782904810063020324704138495608761532563310699753322444871060383693044481932265801505819646998535192083036872551683405766123968487907648980900712118052346174533513978009131757167547595857552370586353973
c17 = 3834917098887202931981968704659119341624432294759361919553937551053499607440333234018189141970246302299385742548278589896033282894981200353270637127213483172182529890495903425649116755901631101665876301799865612717750360089085179142750664603454193642053016384714515855868368723508922271767190285521137785688075622832924829248362774476456232826885801046969384519549385428259591566716890844604696258783639390854153039329480726205147199247183621535172450825979047132495439603840806501254997167051142427157381799890725323765558803808030109468048682252028720241357478614704610089120810367192414352034177484688502364022887

n18 = 19254242571588430171308191757871261075358521158624745702744057556054652332495961196795369630484782930292003238730267396462491733557715379956969694238267908985251699834707734400775311452868924330866502429576951934279223234676654749272932769107390976321208605516299532560054081301829440688796904635446986081691156842271268059970762004259219036753174909942343204432795076377432107630203621754552804124408792358220071862369443201584155711893388877350138023238624566616551246804054720492816226651467017802504094070614892556444425915920269485861799532473383304622064493223627552558344088839860178294589481899206318863310603
c18 = 6790553533991297205804561991225493105312398825187682250780197510784765226429663284220400480563039341938599783346724051076211265663468643826430109013245014035811178295081939958687087477312867720289964506097819762095244479129359998867671811819738196687884696680463458661374310994610760009474264115750204920875527434486437536623589684519411519100170291423367424938566820315486507444202022408003879118465761273916755290898112991525546114191064022991329724370064632569903856189236177894007766690782630247443895358893983735822824243487181851098787271270256780891094405121947631088729917398317652320497765101790132679171889

n19 = 26809700251171279102974962949184411136459372267620535198421449833298448092580497485301953796619185339316064387798092220298630428207556482805739803420279056191194360049651767412572609187680508073074653291350998253938793269214230457117194434853888765303403385824786231859450351212449404870776320297419712486574804794325602760347306432927281716160368830187944940128907971027838510079519466846176106565164730963988892400240063089397720414921398936399927948235195085202171264728816184532651138221862240969655185596628285814057082448321749567943946273776184657698104465062749244327092588237927996419620170254423837876806659
c19 = 386213556608434013769864727123879412041991271528990528548507451210692618986652870424632219424601677524265011043146748309774067894985069288067952546139416819404039688454756044862784630882833496090822568580572859029800646671301748901528132153712913301179254879877441322285914544974519727307311002330350534857867516466612474769753577858660075830592891403551867246057397839688329172530177187042229028685862036140779065771061933528137423019407311473581832405899089709251747002788032002094495379614686544672969073249309703482556386024622814731015767810042969813752548617464974915714425595351940266077021672409858645427346

e = 65537
n = [n0,n1,n2,n3,n4,n5,n6,n7,n8,n9,n10,n11,n12,n13,n14,n15,n16,n17,n18,n19]
c = [c0,c1,c2,c3,c4,c5,c6,c7,c8,c9,c10,c11,c12,c13,c14,c15,c16,c17,c18,c19]

for i in range(len(n)):
    for j in range(len(n)):
        if i!=j and gcd(n[i], n[j])!=1:
            # print(i, j) # 4, 17
            N, C = n[i], c[i]
            p = gcd(n[i], n[j])
            break

q = N//p
d = invmod(e, (p-1)*(q-1))
m = pow(C, d, N)
flag = n2s(m).decode()
print(flag) # flag{abdcbe5fd94e23b3de429223ab9c2fdf}
```

------

### [RSA4](https://buuoj.cn/challenges#RSA4)

附件解压缩后得到`.txt`，内容如下：

```python
N = 331310324212000030020214312244232222400142410423413104441140203003243002104333214202031202212403400220031202142322434104143104244241214204444443323000244130122022422310201104411044030113302323014101331214303223312402430402404413033243132101010422240133122211400434023222214231402403403200012221023341333340042343122302113410210110221233241303024431330001303404020104442443120130000334110042432010203401440404010003442001223042211442001413004 
c = 310020004234033304244200421414413320341301002123030311202340222410301423440312412440240244110200112141140201224032402232131204213012303204422003300004011434102141321223311243242010014140422411342304322201241112402132203101131221223004022003120002110230023341143201404311340311134230140231412201333333142402423134333211302102413111111424430032440123340034044314223400401224111323000242234420441240411021023100222003123214343030122032301042243

N = 302240000040421410144422133334143140011011044322223144412002220243001141141114123223331331304421113021231204322233120121444434210041232214144413244434424302311222143224402302432102242132244032010020113224011121043232143221203424243134044314022212024343100042342002432331144300214212414033414120004344211330224020301223033334324244031204240122301242232011303211220044222411134403012132420311110302442344021122101224411230002203344140143044114 
c = 112200203404013430330214124004404423210041321043000303233141423344144222343401042200334033203124030011440014210112103234440312134032123400444344144233020130110134042102220302002413321102022414130443041144240310121020100310104334204234412411424420321211112232031121330310333414423433343322024400121200333330432223421433344122023012440013041401423202210124024431040013414313121123433424113113414422043330422002314144111134142044333404112240344

N = 332200324410041111434222123043121331442103233332422341041340412034230003314420311333101344231212130200312041044324431141033004333110021013020140020011222012300020041342040004002220210223122111314112124333211132230332124022423141214031303144444134403024420111423244424030030003340213032121303213343020401304243330001314023030121034113334404440421242240113103203013341231330004332040302440011324004130324034323430143102401440130242321424020323 
c = 10013444120141130322433204124002242224332334011124210012440241402342100410331131441303242011002101323040403311120421304422222200324402244243322422444414043342130111111330022213203030324422101133032212042042243101434342203204121042113212104212423330331134311311114143200011240002111312122234340003403312040401043021433112031334324322123304112340014030132021432101130211241134422413442312013042141212003102211300321404043012124332013240431242
```

题目只给出了`3`组`n`和`c`，而且给的`n`和`c`都是五进制数，根据中国剩余定理有：

> 将以上的三组数分别记为n1,n2,n3 和 c1,c2,c3
> c1 = m^e mod n1
> c2 = m^e mod n2
> c3 = m^e mod n3
> N = n1×n2×n3
> N1 = N/n1
> N2 = N/n2
> N3 = N/n3
> m^e = c1×N1×invert(N1,n1)+c2×N2×invert(N2,n2)+c3×N3×invert(N3,n3) mod N # invert(N,n)是N对n的逆元
> m = iroot(m^e, e) # 对m^e开e次方根即可得到m

编写`Python`代码进行求解，得到`flag{D4mn_y0u_h4s74d_wh47_4_b100dy_b4s74rd!}`，提交即可。

```python
from operator import invert
from gmpy2 import *
import libnum

n0 = '331310324212000030020214312244232222400142410423413104441140203003243002104333214202031202212403400220031202142322434104143104244241214204444443323000244130122022422310201104411044030113302323014101331214303223312402430402404413033243132101010422240133122211400434023222214231402403403200012221023341333340042343122302113410210110221233241303024431330001303404020104442443120130000334110042432010203401440404010003442001223042211442001413004'
c0 = '310020004234033304244200421414413320341301002123030311202340222410301423440312412440240244110200112141140201224032402232131204213012303204422003300004011434102141321223311243242010014140422411342304322201241112402132203101131221223004022003120002110230023341143201404311340311134230140231412201333333142402423134333211302102413111111424430032440123340034044314223400401224111323000242234420441240411021023100222003123214343030122032301042243'

n1 = '302240000040421410144422133334143140011011044322223144412002220243001141141114123223331331304421113021231204322233120121444434210041232214144413244434424302311222143224402302432102242132244032010020113224011121043232143221203424243134044314022212024343100042342002432331144300214212414033414120004344211330224020301223033334324244031204240122301242232011303211220044222411134403012132420311110302442344021122101224411230002203344140143044114'
c1 = '112200203404013430330214124004404423210041321043000303233141423344144222343401042200334033203124030011440014210112103234440312134032123400444344144233020130110134042102220302002413321102022414130443041144240310121020100310104334204234412411424420321211112232031121330310333414423433343322024400121200333330432223421433344122023012440013041401423202210124024431040013414313121123433424113113414422043330422002314144111134142044333404112240344'

n2 = '332200324410041111434222123043121331442103233332422341041340412034230003314420311333101344231212130200312041044324431141033004333110021013020140020011222012300020041342040004002220210223122111314112124333211132230332124022423141214031303144444134403024420111423244424030030003340213032121303213343020401304243330001314023030121034113334404440421242240113103203013341231330004332040302440011324004130324034323430143102401440130242321424020323'
c2 = '10013444120141130322433204124002242224332334011124210012440241402342100410331131441303242011002101323040403311120421304422222200324402244243322422444414043342130111111330022213203030324422101133032212042042243101434342203204121042113212104212423330331134311311114143200011240002111312122234340003403312040401043021433112031334324322123304112340014030132021432101130211241134422413442312013042141212003102211300321404043012124332013240431242'

n = [int(n0,5), int(n1,5), int(n2,5)]
c = [int(c0,5), int(c1,5), int(c2,5)]

def CRT(remainder, modulus):
    '''
    利用中国剩余定理求解同余方程, 
    remainder 余数, modulus 模数
    '''
    M = 1
    for i in modulus:
        M *= i
    ans = 0
    for i in range(len(modulus)):
        Mi = M//modulus[i]
        ans += remainder[i]*Mi*invert(Mi, modulus[i])
    return ans%M
    
    
m_e = CRT(c, n) # 计算m的e次方
e = 3
m = int(iroot(m_e, e)[0])
flag = libnum.n2s(m).decode()
print(flag) # flag{D4mn_y0u_h4s74d_wh47_4_b100dy_b4s74rd!}
```

------

### caeser

题目描述：

> 听说尤利乌斯发明了一套防止消息泄漏的方法

附件`ciphertext.txt`内容如下：

> synt{uvfgbevpny_pvcure_vf_ihyarenoyr}

凯撒密码，编写`Python`代码求解：

```python
text = 'synt{uvfgbevpny_pvcure_vf_ihyarenoyr}' # 
flag = ''
for i in range(1, 27):
    s = ''
    for x in text:
        if x.isalpha():
            s += chr(ord('a')+(ord(x)-ord('a')+i)%26)
        else:
            s += x
    s = s.lower()
    if 'flag' in s:
        flag = s
        print('{}的移位是{}'.format(s, (ord(text[0])-ord(s[0]))%26))

print(flag) # flag{historical_cipher_is_vulnerable}
```

------

### 吉奥万·巴蒂斯塔·贝拉索先生的密码

题目描述：

> 一个古老的密码, 你能破解它吗

附件`ciphertext.txt`内容如下：

> pqcq{gteygpttmj_kc_zuokwv_kqb_gtofmssi_mnrrjt}
>
> Hint: key length is 3

吉奥万·巴蒂斯塔·贝拉索先生发明的那种多表密码，其实就是那个被后人误认为是维吉尼亚发明的密码，即维吉尼亚密码。维吉尼亚密码的加密原理是将`26`个英文字母（`a-z`）对应`26`个自然数（`0-25`），它只对字母（不区分大小写）进行加密，若文本中出现非字母字符会保留原样。已知`key`的长度为`3`，而明文的前五位必为`flag{`，用密文减去已知的明文可得到密钥，由`flag`与`pqcq`的对应关系可知，`f + 10 = p`，`l + 5 = q`，`a + 2 = c`，`g + 10 = k`，因此密钥`key`为`kfc`，好家伙肯德基记得打钱，编写`Python`代码用密文减去密钥即可得到明文：`flag{bruteforce_is_useful_for_breaking_cipher}`。

```python
cipher = 'pqcq{gteygpttmj_kc_zuokwv_kqb_gtofmssi_mnrrjt}'
s = 'flag{'
key = ''
for i in range(3):
    key += chr(ord('a') + ord(cipher[i])-ord(s[i]))
# key = 'kfc'
flag = ''
j = 0
for i, x in enumerate(cipher):
    if x.isalpha():
        flag += chr(ord('a') + (ord(x) - ord(key[j%len(key)]))%26)
        j += 1
    else:
        flag += x

print(flag) # flag{bruteforce_is_useful_for_breaking_cipher}
```

------

### eazyxor

附件给出了`xor.py`和`output.txt`，其中`xor.py`的源码如下：

```python
from os import urandom
from secret import flag
key = urandom(1)

def xor(plaintext, key):
    ret = []
    for i in range(len(plaintext)):
        ret.append(plaintext[i] ^ key[0])
    return bytes(ret)

ciphertext = xor(flag, key) # '\x9b\x91\x9c\x9a\x86\x85\xcd\x8f\xa2\x94\xc8\xa2\x8c\x88\xcc\x89\xce\xa2\xce\x9c\x87\x84\x80'

print(ciphertext.hex()) # 9b919c9a8685cd8fa294c8a28c88cc89cea2ce9c878480
```

`output.txt`中的内容就是`ciphertext.hex()`

```
9b919c9a8685cd8fa294c8a28c88cc89cea2ce9c878480
```

由于`key`只有一字节，而`flag`的前五个字符是`flag{`，由异或操作可以推出`key`为`b'\xfd'`，即`253`。编写`Python`代码异或求解得到`flag{x0r_i5_qu1t3_3azy}`，提交即可。

```python
s = bytes.fromhex('9b919c9a8685cd8fa294c8a28c88cc89cea2ce9c878480') #  b'\x9b\x91\x9c\x9a\x86\x85\xcd\x8f\xa2\x94\xc8\xa2\x8c\x88\xcc\x89\xce\xa2\xce\x9c\x87\x84\x80'
key = 253 # b'\xfd'
l = []
for i in range(len(s)):
    l.append(s[i]^253)
flag = bytes(l).decode()
print(flag) # flag{x0r_i5_qu1t3_3azy}
```

------

### ♥ RSA_begin

题目给出了俩个附件`task.py`和`output.txt`，其中`task.py`的源码如下：

```python
from Crypto.Util.number import *
from secret import flag

assert len(flag) % 5 == 0
cnt = len(flag) // 5
flags = [flag[cnt*i:cnt*(i+1)] for i in range(5)]

# Try to implement your RSA with primes p and q
def level1(message):
    m = bytes_to_long(message)
    p = getPrime(512)
    q = getPrime(512)
    n = p * q
    e = 0x10001
    assert m < n
    c = pow(m, e, n)
    print(f'c = {c}')
    print(f'p = {p}')
    print(f'q = {q}')

# But how can we attack the RSA when we didn't know the primes?
def level2(message):
    m = bytes_to_long(message)
    p = getPrime(64)
    q = getPrime(64)
    n = p * q
    e = 0x10001
    assert m < n
    c = pow(m, e, n)
    print(f'c = {c}')
    print(f'n = {n}')

# Different e may cause danger?
def level3(message):
    m = bytes_to_long(message)
    p = getPrime(512)
    q = getPrime(512)
    e = 3
    n = p * q
    assert m < n
    c = pow(m, e, n)
    print(f'c = {c}')
    print(f'n = {n}')

# So is there anything wrong with RSA as shown below?
def level4(message):
    m = bytes_to_long(message)
    p = getPrime(512)
    q = getPrime(512)
    d = getPrime(64)
    e = inverse(d, (p-1) * (q-1))
    n = p * q
    assert m < n
    c = pow(m, e, n)
    print(f'c = {c}')
    print(f'e = {e}')
    print(f'n = {n}')

# What about different n? Just have a try with the hint!
def level5(message):
    m = bytes_to_long(message)
    p = getPrime(512)
    q = getPrime(512)
    n = p * p * q
    e = 0x10001
    d = inverse(e, p * (p-1) * (q-1))
    assert m < n
    c = pow(m, e, n)
    hint = pow(d, e, n)
    print(f'c = {c}')
    print(f'hint = {hint}')
    print(f'n = {n}')

print('Level 1:')
level1(flags[0])
print('Level 2:')
level2(flags[1])
print('Level 3:')
level3(flags[2])
print('Level 4:')
level4(flags[3])
print('Level 5:')
level5(flags[4])
```

很(ni)好(ma)！这道`RSA`题把`flag`分为五部分来考，考的很综合，`output.txt`的内容如下：

```python
Level 1:
c = 22160015525054597533062795679117215923801827397299805735087138192137742945881204146337349060934854888054628153923021387981306839951210090523829296521835965212118849043671673133979884712755090374758002677916820953359774554825569218497687506468472278309097929775388010403607769802840990547048001743970754496905
p = 6962443023774446497102092246794613339314677593117417573764609329949026862782472380488956732038459060928443992561763464365758383525259954798321350043810351
q = 9631855759661411029901156175243744760977799976661519182223576693685069000499866459636568713055906075171480855575061732016121299027658733834671035383233163
Level 2:
c = 17250922799297131008803303235771955129
n = 134097988095851988085603926250918812377
Level 3:
c = 2776571135646565181849912433877522437622755332262910824866791711
n = 85793694792655420934945863688968944466300304898903354212780512650924132933351787673979641944071634528676901506049360194331553838080226562532784448832916022442020751986591703547743056267118831445759258041047213294368605599719242059474324548598203039032847591828382166845797857139844445858881218318006747115157
Level 4:
c = 68588738085497640698861260094482876262596289469248772328560280530093163764972313090939471997156632421517452790632223565521726590730640805290182026911025142051864898712501214753986865172996090706657535814234291235489829621372021092488300236623525366939477695283380634188510950335639019458758643273802572617191
e = 51999725233581619348238930320668315462087635295211755849675812266270026439521805156908952855288255992098479180003264827305694330542325533165867427898010879823017054891520626992724274019277478717788189662456052796449734904215067032681345261878977193341769514961038309763898052908572726913209883965288047452751
n = 68816697240190744603903822351423855593899797203703723038363240057913366227564780805815565183450516726498872118491739132110437976570592602837245705802946829337567674506561850972973663435358068441037127926802688722648016352967768929007662772115485020718202683004813042834036078650571763978066558718285783045969
Level 5:
c = 1135954814335407362237156338232840769700916726653557860319741136149066730262056907097728029957898420630256832277578506404721904131425822963948589774909272408535427656986176833063600681390871582834223748797942203560505159946141171210061405977060061656807175913366911284450695116982731157917343650021723054666494528470413522258995220648163505549701953152705111304471498547618002847587649651689203632845303117282630095814054989963116013144483037051076441508388998829
hint = 611144874477135520868450203622074557606421849009025270666985817360484127602945558050689975570970227439583312738313767886380304814871432558985582586031211416586296452510050692235459883608453661597776103386009579351911278185434163016083552988251266501525188362673472772346212970459561496301631587043106524741903627979311997541301471894670374945556313285203740782346029579923650160327646876967315182335114575921178144825057359851607166387868294019144940296084605930
n = 1232865496850144050320992645475166723525103370117149219196294373695624167653495180701004894188767069545579706264513808335877905149818445940067870026924895990672091745229251935876434509430457142930654307044403355838663341948471348893414890261787326255632362887647279204029327042915224570484394917295606592360109952538313570951448278525753313335289675455996833500751672463525151201002407861423542656805624090223118747404488579783372944593022796321473618301206064979
```

先来看`Level1`，重新整理下，方便代码审计。已知`p`，`q`，`e`，`c`，求`m`，这不是白给第一段`flag`吗？

```python
m = bytes_to_long(message)
p = getPrime(512)
q = getPrime(512)
n = p * q
e = 0x10001
assert m < n
c = pow(m, e, n)
print(f'c = {c}')
print(f'p = {p}')
print(f'q = {q}')
'''
c = 22160015525054597533062795679117215923801827397299805735087138192137742945881204146337349060934854888054628153923021387981306839951210090523829296521835965212118849043671673133979884712755090374758002677916820953359774554825569218497687506468472278309097929775388010403607769802840990547048001743970754496905
p = 6962443023774446497102092246794613339314677593117417573764609329949026862782472380488956732038459060928443992561763464365758383525259954798321350043810351
q = 9631855759661411029901156175243744760977799976661519182223576693685069000499866459636568713055906075171480855575061732016121299027658733834671035383233163
'''
```

编写`Python`代码求解拿到`flag{W0w_`。

```python
from gmpy2 import *
from Crypto.Util.number import *

e = 0x10001
c = 22160015525054597533062795679117215923801827397299805735087138192137742945881204146337349060934854888054628153923021387981306839951210090523829296521835965212118849043671673133979884712755090374758002677916820953359774554825569218497687506468472278309097929775388010403607769802840990547048001743970754496905
p = 6962443023774446497102092246794613339314677593117417573764609329949026862782472380488956732038459060928443992561763464365758383525259954798321350043810351
q = 9631855759661411029901156175243744760977799976661519182223576693685069000499866459636568713055906075171480855575061732016121299027658733834671035383233163
n = p*q
d = invert(e, (p-1)*(q-1)) 
m = powmod(c, d, n)  # m = c^d%n
flag = long_to_bytes(m).decode('utf-8')
print(flag) # flag{W0w_
```

接着来看`Level2`，重新整理下，方便代码审计。已知`n`，`e`，`c`，求`m`。调用`requests`库在线请求 http://factordb.com 分解模数`n`，得到`p`和`q`。这里用另一个库`libnum`来进行`RSA`的常规求解。

```python
m = bytes_to_long(message)
p = getPrime(64)
q = getPrime(64)
n = p * q
e = 0x10001
assert m < n
c = pow(m, e, n)
print(f'c = {c}')
print(f'n = {n}')
'''
c = 17250922799297131008803303235771955129
n = 134097988095851988085603926250918812377
'''
```

编写`Python`代码求解拿到`U_ar3_re4`。

```python
import requests
from libnum import *

def factorize(n):
    l = []
    url="http://factordb.com/api?query="+str(n)
    r = requests.get(url)
    data = r.json()
    for factor in data['factors']:
        l.append(int(factor[0]))
    return l

e = 0x10001
c = 17250922799297131008803303235771955129
n = 134097988095851988085603926250918812377
q, p = factorize(n)
d = invmod(e, (p-1)*(q-1))
m = pow(c, d, n)
flag = n2s(m).decode()
print(flag) # U_ar3_re4
```

再来看`Level3`，重新整理下，方便代码审计。已知`n`，`e`和`c`，可以用常规`RSA`题求解方法对`n`进行因数分解得到`p`和`q`，然后求`m`获取`flag`。

```python
m = bytes_to_long(message)
p = getPrime(512)
q = getPrime(512)
e = 3
n = p * q
assert m < n
c = pow(m, e, n)
print(f'c = {c}')
print(f'n = {n}')
'''
c = 2776571135646565181849912433877522437622755332262910824866791711
n = 85793694792655420934945863688968944466300304898903354212780512650924132933351787673979641944071634528676901506049360194331553838080226562532784448832916022442020751986591703547743056267118831445759258041047213294368605599719242059474324548598203039032847591828382166845797857139844445858881218318006747115157
'''
```

但是`Level3`想考察的知识点是低加密指数攻击，因为公钥中的加密指数`e = 3`很小，但是模数`n`又很大。低加密指数攻击的原理如下：

> RSA加密公式：c = m^e%n
>
> 1. 当 m^e < n 时，c = m^e 
>
>    因此，对密文 c 开 e 次方根就能得到明文 m
>
> 2. 当 m^e > n 时，假设 m^e / n 的商为 i，余数为c，则 Ｍ^e = i×n + C
>
>    对 i 进行爆破，当满足 ( i*n + c) 开 e 次方根时就得到了明文 m

编写`Python`代码进行求解拿到`L1y_g0Od_`。

```python
from gmpy2 import *
from libnum import n2s

e = 3
c = 2776571135646565181849912433877522437622755332262910824866791711
n = 85793694792655420934945863688968944466300304898903354212780512650924132933351787673979641944071634528676901506049360194331553838080226562532784448832916022442020751986591703547743056267118831445759258041047213294368605599719242059474324548598203039032847591828382166845797857139844445858881218318006747115157
i = 0
while True:
    m, ok = iroot(c+i*n, e)
    if ok:
        flag = n2s(int(m)).decode()
        break
    i += 1

print(flag) # L1y_g0Od_
```

下面来看`Level4`，重新整理下，方便代码审计。已知`n`，`e`，`c`，求`m`。调用http://factordb.com 分解模数`n`失败了，不要慌，注意到这三个数差不多大（`e`较大），`Level4`想考察的知识点是低解密指数攻击，https://github.com/pablocelayes/rsa-wiener-attack 这是一个很古老的库，可以参考大佬的代码，来进行`RSA`低解密指数攻击。

```python
m = bytes_to_long(message)
p = getPrime(512)
q = getPrime(512)
d = getPrime(64)
e = inverse(d, (p-1) * (q-1))
n = p * q
assert m < n
c = pow(m, e, n)
print(f'c = {c}')
print(f'e = {e}')
print(f'n = {n}')
'''
c = 68588738085497640698861260094482876262596289469248772328560280530093163764972313090939471997156632421517452790632223565521726590730640805290182026911025142051864898712501214753986865172996090706657535814234291235489829621372021092488300236623525366939477695283380634188510950335639019458758643273802572617191
e = 51999725233581619348238930320668315462087635295211755849675812266270026439521805156908952855288255992098479180003264827305694330542325533165867427898010879823017054891520626992724274019277478717788189662456052796449734904215067032681345261878977193341769514961038309763898052908572726913209883965288047452751
n = 68816697240190744603903822351423855593899797203703723038363240057913366227564780805815565183450516726498872118491739132110437976570592602837245705802946829337567674506561850972973663435358068441037127926802688722648016352967768929007662772115485020718202683004813042834036078650571763978066558718285783045969
'''
```

编写`Python`代码进行求解拿到`4t_m4th_4`。

```python
from libnum import *

def rational_to_contfrac(x,y):
    '''
    Converts a rational x/y fraction into
    a list of partial quotients [a0, ..., an]
    '''
    a = x//y
    pquotients = [a]
    while a * y != x:
        x,y = y,x-a*y
        a = x//y
        pquotients.append(a)
    return pquotients

def contfrac_to_rational (frac):
    '''Converts a finite continued fraction [a0, ..., an]
     to an x/y rational.
     '''
    if len(frac) == 0:
        return (0,1)
    num = frac[-1]
    denom = 1
    for _ in range(-2,-len(frac)-1,-1):
        num, denom = frac[_]*num+denom, num
    return (num,denom)

# efficient method that calculates convergents on-the-go, without doing partial quotients first
def convergents_from_contfrac(frac):
    '''
    computes the list of convergents
    using the list of partial quotients
    '''
    convs = [];
    for i in range(len(frac)):
        convs.append(contfrac_to_rational(frac[0:i]))
    return convs

def bitlength(x):
    '''
    Calculates the bitlength of x
    '''
    assert x >= 0
    n = 0
    while x > 0:
        n = n+1
        x = x>>1
    return n

def isqrt(n):
    '''
    Calculates the integer square root
    for arbitrary large nonnegative integers
    '''
    if n < 0:
        raise ValueError('square root not defined for negative numbers')
    if n == 0:
        return 0
    a, b = divmod(bitlength(n), 2)
    x = 2**(a+b)
    while True:
        y = (x + n//x)//2
        if y >= x:
            return x
        x = y

def is_perfect_square(n):
    '''
    If n is a perfect square it returns sqrt(n),
    otherwise returns -1
    '''
    h = n & 0xF; #last hexadecimal "digit"
    if h > 9:
        return -1 # return immediately in 6 cases out of 16.
    # Take advantage of Boolean short-circuit evaluation
    if ( h != 2 and h != 3 and h != 5 and h != 6 and h != 7 and h != 8 ):
        # take square root if you must
        t = isqrt(n)
        if t*t == n:
            return t
        else:
            return -1
    return -1

def hack_RSA(e,n):
    '''
    Finds d knowing (e,n)
    applying the Wiener continued fraction attack
    '''
    frac = rational_to_contfrac(e, n)
    convergents = convergents_from_contfrac(frac)
    
    for (k,d) in convergents:
        
        #check if d is actually the key
        if k!=0 and (e*d-1)%k == 0:
            phi = (e*d-1)//k
            s = n - phi + 1
            # check if the equation x^2 - s*x + n = 0
            # has integer roots
            discr = s*s - 4*n
            if(discr>=0):
                t = is_perfect_square(discr)
                if t!=-1 and (s+t)%2==0:
                    print("Hacked!")
                    return d

c = 68588738085497640698861260094482876262596289469248772328560280530093163764972313090939471997156632421517452790632223565521726590730640805290182026911025142051864898712501214753986865172996090706657535814234291235489829621372021092488300236623525366939477695283380634188510950335639019458758643273802572617191
e = 51999725233581619348238930320668315462087635295211755849675812266270026439521805156908952855288255992098479180003264827305694330542325533165867427898010879823017054891520626992724274019277478717788189662456052796449734904215067032681345261878977193341769514961038309763898052908572726913209883965288047452751
n = 68816697240190744603903822351423855593899797203703723038363240057913366227564780805815565183450516726498872118491739132110437976570592602837245705802946829337567674506561850972973663435358068441037127926802688722648016352967768929007662772115485020718202683004813042834036078650571763978066558718285783045969
d = hack_RSA(e, n) # 12966126097163765179
m = pow(c, d, n)
flag = n2s(m).decode()
print(flag) # 4t_m4th_4
```

最后来看`Level5`，重新整理下，方便代码审计。已知`n`，`e`，`c`，求`m`。调用`requests`库在线请求 http://factordb.com 分解模数`n`，得到`p`和`q`。注意能分解出`2`个相同的`p`，暴力破解都不需要`hint`，知道`p`和`q`的值后直接算`d`然后求`m`得到`flag`。

```python
m = bytes_to_long(message)
p = getPrime(512)
q = getPrime(512)
n = p * p * q
e = 0x10001
d = inverse(e, p * (p-1) * (q-1))
assert m < n
c = pow(m, e, n)
hint = pow(d, e, n)
print(f'c = {c}')
print(f'hint = {hint}')
print(f'n = {n}')
'''
c = 1135954814335407362237156338232840769700916726653557860319741136149066730262056907097728029957898420630256832277578506404721904131425822963948589774909272408535427656986176833063600681390871582834223748797942203560505159946141171210061405977060061656807175913366911284450695116982731157917343650021723054666494528470413522258995220648163505549701953152705111304471498547618002847587649651689203632845303117282630095814054989963116013144483037051076441508388998829
hint = 611144874477135520868450203622074557606421849009025270666985817360484127602945558050689975570970227439583312738313767886380304814871432558985582586031211416586296452510050692235459883608453661597776103386009579351911278185434163016083552988251266501525188362673472772346212970459561496301631587043106524741903627979311997541301471894670374945556313285203740782346029579923650160327646876967315182335114575921178144825057359851607166387868294019144940296084605930
n = 1232865496850144050320992645475166723525103370117149219196294373695624167653495180701004894188767069545579706264513808335877905149818445940067870026924895990672091745229251935876434509430457142930654307044403355838663341948471348893414890261787326255632362887647279204029327042915224570484394917295606592360109952538313570951448278525753313335289675455996833500751672463525151201002407861423542656805624090223118747404488579783372944593022796321473618301206064979
'''
```

编写`Python`代码进行求解拿到`nD_RSA!!}`。

```python
import requests
from libnum import *

def factorize(n):
    l = []
    url="http://factordb.com/api?query="+str(n)
    r = requests.get(url)
    data = r.json()   
    for factor in data['factors']:
        for i in range(int(factor[1])):
            l.append(int(factor[0]))
    return l

e = 0x10001
c = 1135954814335407362237156338232840769700916726653557860319741136149066730262056907097728029957898420630256832277578506404721904131425822963948589774909272408535427656986176833063600681390871582834223748797942203560505159946141171210061405977060061656807175913366911284450695116982731157917343650021723054666494528470413522258995220648163505549701953152705111304471498547618002847587649651689203632845303117282630095814054989963116013144483037051076441508388998829
hint = 611144874477135520868450203622074557606421849009025270666985817360484127602945558050689975570970227439583312738313767886380304814871432558985582586031211416586296452510050692235459883608453661597776103386009579351911278185434163016083552988251266501525188362673472772346212970459561496301631587043106524741903627979311997541301471894670374945556313285203740782346029579923650160327646876967315182335114575921178144825057359851607166387868294019144940296084605930
n = 1232865496850144050320992645475166723525103370117149219196294373695624167653495180701004894188767069545579706264513808335877905149818445940067870026924895990672091745229251935876434509430457142930654307044403355838663341948471348893414890261787326255632362887647279204029327042915224570484394917295606592360109952538313570951448278525753313335289675455996833500751672463525151201002407861423542656805624090223118747404488579783372944593022796321473618301206064979
l = factorize(n)
q, p = l[0], l[2]
d = invmod(e, p*(p-1)*(q-1))
m = pow(c, d, n)
flag = n2s(m).decode()
print(flag) # nD_RSA!!}
```

将字符串拼接后可以得到完整的`flag`，提交`flag{W0w_U_ar3_re4L1y_g0Od_4t_m4th_4nD_RSA!!}`即可。来个这题的综合脚本吧：

```python
import requests
from gmpy2 import *
from libnum import *

def factorize(n):
    l = []
    url="http://factordb.com/api?query="+str(n)
    r = requests.get(url)
    data = r.json()   
    for factor in data['factors']:
        for i in range(int(factor[1])):
            l.append(int(factor[0]))
    return l

def rational_to_contfrac(x,y):
    '''
    Converts a rational x/y fraction into
    a list of partial quotients [a0, ..., an]
    '''
    a = x//y
    pquotients = [a]
    while a * y != x:
        x,y = y,x-a*y
        a = x//y
        pquotients.append(a)
    return pquotients

def contfrac_to_rational (frac):
    '''Converts a finite continued fraction [a0, ..., an]
     to an x/y rational.
     '''
    if len(frac) == 0:
        return (0,1)
    num = frac[-1]
    denom = 1
    for _ in range(-2,-len(frac)-1,-1):
        num, denom = frac[_]*num+denom, num
    return (num,denom)

# efficient method that calculates convergents on-the-go, without doing partial quotients first
def convergents_from_contfrac(frac):
    '''
    computes the list of convergents
    using the list of partial quotients
    '''
    convs = [];
    for i in range(len(frac)):
        convs.append(contfrac_to_rational(frac[0:i]))
    return convs

def bitlength(x):
    '''
    Calculates the bitlength of x
    '''
    assert x >= 0
    n = 0
    while x > 0:
        n = n+1
        x = x>>1
    return n

def isqrt(n):
    '''
    Calculates the integer square root
    for arbitrary large nonnegative integers
    '''
    if n < 0:
        raise ValueError('square root not defined for negative numbers')
    if n == 0:
        return 0
    a, b = divmod(bitlength(n), 2)
    x = 2**(a+b)
    while True:
        y = (x + n//x)//2
        if y >= x:
            return x
        x = y

def is_perfect_square(n):
    '''
    If n is a perfect square it returns sqrt(n),
    otherwise returns -1
    '''
    h = n & 0xF; #last hexadecimal "digit"
    if h > 9:
        return -1 # return immediately in 6 cases out of 16.
    # Take advantage of Boolean short-circuit evaluation
    if ( h != 2 and h != 3 and h != 5 and h != 6 and h != 7 and h != 8 ):
        # take square root if you must
        t = isqrt(n)
        if t*t == n:
            return t
        else:
            return -1
    return -1

def hack_RSA(e,n):
    '''
    Finds d knowing (e,n)
    applying the Wiener continued fraction attack
    '''
    frac = rational_to_contfrac(e, n)
    convergents = convergents_from_contfrac(frac)
    
    for (k,d) in convergents:
        
        #check if d is actually the key
        if k!=0 and (e*d-1)%k == 0:
            phi = (e*d-1)//k
            s = n - phi + 1
            # check if the equation x^2 - s*x + n = 0
            # has integer roots
            discr = s*s - 4*n
            if(discr>=0):
                t = is_perfect_square(discr)
                if t!=-1 and (s+t)%2==0:
                    print("Hacked!")
                    return d

def level1():
    e = 0x10001
    c = 22160015525054597533062795679117215923801827397299805735087138192137742945881204146337349060934854888054628153923021387981306839951210090523829296521835965212118849043671673133979884712755090374758002677916820953359774554825569218497687506468472278309097929775388010403607769802840990547048001743970754496905
    p = 6962443023774446497102092246794613339314677593117417573764609329949026862782472380488956732038459060928443992561763464365758383525259954798321350043810351
    q = 9631855759661411029901156175243744760977799976661519182223576693685069000499866459636568713055906075171480855575061732016121299027658733834671035383233163
    n = p*q
    d = invmod(e, (p-1)*(q-1)) 
    m = pow(c, d, n)  # m = c^d%n
    flag = n2s(m).decode('utf-8')
    return flag # flag{W0w_

def level2():
    e = 0x10001
    c = 17250922799297131008803303235771955129
    n = 134097988095851988085603926250918812377
    q, p = factorize(n)
    d = invmod(e, (p-1)*(q-1))
    m = pow(c, d, n)
    flag = n2s(m).decode()
    return flag # U_ar3_re4

def level3():
    e = 3
    c = 2776571135646565181849912433877522437622755332262910824866791711
    n = 85793694792655420934945863688968944466300304898903354212780512650924132933351787673979641944071634528676901506049360194331553838080226562532784448832916022442020751986591703547743056267118831445759258041047213294368605599719242059474324548598203039032847591828382166845797857139844445858881218318006747115157
    i = 0
    while True:
        m, ok = iroot(c+i*n, e)
        if ok:
            flag = n2s(int(m)).decode()
            break
        i += 1
    return flag # L1y_g0Od_

def level4():
    c = 68588738085497640698861260094482876262596289469248772328560280530093163764972313090939471997156632421517452790632223565521726590730640805290182026911025142051864898712501214753986865172996090706657535814234291235489829621372021092488300236623525366939477695283380634188510950335639019458758643273802572617191
    e = 51999725233581619348238930320668315462087635295211755849675812266270026439521805156908952855288255992098479180003264827305694330542325533165867427898010879823017054891520626992724274019277478717788189662456052796449734904215067032681345261878977193341769514961038309763898052908572726913209883965288047452751
    n = 68816697240190744603903822351423855593899797203703723038363240057913366227564780805815565183450516726498872118491739132110437976570592602837245705802946829337567674506561850972973663435358068441037127926802688722648016352967768929007662772115485020718202683004813042834036078650571763978066558718285783045969
    d = hack_RSA(e, n) # 12966126097163765179
    m = pow(c, d, n)
    flag = n2s(m).decode()
    return flag # 4t_m4th_4

def level5():
    e = 0x10001
    c = 1135954814335407362237156338232840769700916726653557860319741136149066730262056907097728029957898420630256832277578506404721904131425822963948589774909272408535427656986176833063600681390871582834223748797942203560505159946141171210061405977060061656807175913366911284450695116982731157917343650021723054666494528470413522258995220648163505549701953152705111304471498547618002847587649651689203632845303117282630095814054989963116013144483037051076441508388998829
    hint = 611144874477135520868450203622074557606421849009025270666985817360484127602945558050689975570970227439583312738313767886380304814871432558985582586031211416586296452510050692235459883608453661597776103386009579351911278185434163016083552988251266501525188362673472772346212970459561496301631587043106524741903627979311997541301471894670374945556313285203740782346029579923650160327646876967315182335114575921178144825057359851607166387868294019144940296084605930
    n = 1232865496850144050320992645475166723525103370117149219196294373695624167653495180701004894188767069545579706264513808335877905149818445940067870026924895990672091745229251935876434509430457142930654307044403355838663341948471348893414890261787326255632362887647279204029327042915224570484394917295606592360109952538313570951448278525753313335289675455996833500751672463525151201002407861423542656805624090223118747404488579783372944593022796321473618301206064979
    l = factorize(n)
    q, p = l[0], l[2]
    d = invmod(e, p*(p-1)*(q-1))
    m = pow(c, d, n)
    flag = n2s(m).decode()
    return flag # nD_RSA!!}

flag = level1()+level2()+level3()+level4()+level5()
print(flag) # flag{W0w_U_ar3_re4L1y_g0Od_4t_m4th_4nD_RSA!!}
```

------

### chaos

题目描述：

> 看上去很复杂？

附件`chaos.py`内容如下：

```python
import random
import time
from secret import flag

def LC(key, x, times, flags):
    (k1, k2) = key
    xn = []
    xn.append(x)
    if flags:
        xn.append(1 - 2 * xn[0]**2)
    else:
        xn.append(k2 * xn[0]**3 + (1 - k2)*xn[0])
    for i in range(times):
        assert xn[i]>=-1 and xn[i]<=1 and xn[i+1]>=-1 and xn[i+1]<=1
        if flags:
            xn.append((1 - 2 * xn[i]**2)*(k1 * xn[i+1]**3 + (1 - k1)*xn[i+1]))
        else:
            xn.append((k2 * xn[i]**3 + (1 - k2)*xn[i])*(1 - 2 * xn[i+1]**2))
    return xn[times + 1]

def init(): 
    sum, r, k = 0, 1, []
    k1 = random.uniform(3.2, 4) 
    k2 = random.uniform(3.2, 4)
    for i in range(16): 
        k.append(random.randint(1,256)) 
        sum += k[-1]
        r ^= k[-1]  
    a_1 = (sum/256) % 1 
    timea1 = 3 + int(1000 * a_1) % 30
    b_1 = (r/256)
    timeb1 = 3 + int(1000 * b_1) % 30
    xc_1 = a_1 * b_1
    yc_1 = (a_1 + b_1) % 1
    print('k1, k2 = %r, %r'%(k1, k2))
    print('k = %r'%k)
    return (k1, k2), (a_1, timea1, b_1, timeb1, xc_1, yc_1)

def encrypt(key, data, flag):
    (k1, k2) = key
    (a_1, timea1, b_1, timeb1, xc_1, yc_1) = data
    flag = list(flag)
    m, c = [], []
    miu, omiga = [], []
    ta = timea1
    tb = timeb1
    for tmp in flag:
        mi = ord(tmp)
        miu.append(LC(key, a_1, ta, 1))
        omiga.append(LC(key, b_1, tb, 0))
        c.append(((int(miu[-1] * 1000) + int(omiga[-1] * 1000)) ^ mi) % 256)
        delta = c[-1]/256
        for i in range(3):
            y = (yc_1 + delta) % 1
            y = k1 * y**3 + (1 - k1) * y
            x = xc_1
            x = k2 * x**3 + (1 - k2) * x
        ta = 3 + int(1000 * x) % 30
        tb = 3 + int(1000 * y) % 30
    print('c = %r'%(c))
    return c

if __name__=="__main__":
    # print(flag)
    key, data = init()
    c = encrypt(key, data, flag)

'''
k1, k2 = 3.967139695598587, 3.7926025078694305                                           
k = [107, 99, 55, 198, 210, 56, 137, 44, 127, 25, 150, 113, 75, 215, 187, 132]           
c = [23, 84, 105, 111, 230, 105, 97, 50, 58, 61, 25, 97, 57, 21, 175, 77, 102, 138, 120, 17, 66, 172, 52, 178, 101, 221, 109, 126, 71, 149, 63, 32, 56, 6, 134, 255, 110, 57, 15, 20, 116]
'''
```

编写`Python`代码求解可得`flag{ii24nji9-8ckkpil1-5hiev3n6-1u24g07m}`。

```python
import random
import time
#from secret import flag

def LC(key, x, times, flags):
    (k1, k2) = key
    xn = []
    xn.append(x)
    if flags:
        xn.append(1 - 2 * xn[0]**2)
    else:
        xn.append(k2 * xn[0]**3 + (1 - k2)*xn[0])
    for i in range(times):
        assert xn[i]>=-1 and xn[i]<=1 and xn[i+1]>=-1 and xn[i+1]<=1
        if flags:
            xn.append((1 - 2 * xn[i]**2)*(k1 * xn[i+1]**3 + (1 - k1)*xn[i+1]))
        else:
            xn.append((k2 * xn[i]**3 + (1 - k2)*xn[i])*(1 - 2 * xn[i+1]**2))
    return xn[times + 1]

def init(): 
    sum, r, k = 0, 1, []
    #k1 = random.uniform(3.2, 4) 
    #k2 = random.uniform(3.2, 4)
    k1, k2 = 3.967139695598587, 3.7926025078694305                                           
    k = [107, 99, 55, 198, 210, 56, 137, 44, 127, 25, 150, 113, 75, 215, 187, 132]           

    for i in range(16): 
        #k.append(random.randint(1,256)) 
        sum += k[i]
        r ^= k[i]  
    a_1 = (sum/256) % 1 
    timea1 = 3 + int(1000 * a_1) % 30
    b_1 = (r/256)
    timeb1 = 3 + int(1000 * b_1) % 30
    xc_1 = a_1 * b_1
    yc_1 = (a_1 + b_1) % 1
    print('k1, k2 = %r, %r'%(k1, k2))
    print('k = %r'%k)
    return (k1, k2), (a_1, timea1, b_1, timeb1, xc_1, yc_1)

def decrypt(key, data):
                                            
    #k = [107, 99, 55, 198, 210, 56, 137, 44, 127, 25, 150, 113, 75, 215, 187, 132]           
    c = [23, 84, 105, 111, 230, 105, 97, 50, 58, 61, 25, 97, 57, 21, 175, 77, 102, 138, 120, 17, 66, 172, 52, 178, 101, 221, 109, 126, 71, 149, 63, 32, 56, 6, 134, 255, 110, 57, 15, 20, 116]

    (k1, k2)=key
    (a_1, timea1, b_1, timeb1, xc_1, yc_1) = data
    #flag = list(flag)
    
    miu, omiga = [], []
    ta = timea1
    tb = timeb1
    m=''
    for tmp in c:
        #mi = ord(tmp)
        miu.append(LC(key, a_1, ta, 1))
        omiga.append(LC(key, b_1, tb, 0))
        #c.append(((int(miu[-1] * 1000) + int(omiga[-1] * 1000)) ^ mi) % 256)
        
        m+=(chr(tmp^((int(miu[-1] * 1000) + int(omiga[-1] * 1000)))%256))
        delta = tmp/256
        for i in range(3):
            y = (yc_1 + delta) % 1
            y = k1 * y**3 + (1 - k1) * y
            x = xc_1
            x = k2 * x**3 + (1 - k2) * x
        ta = 3 + int(1000 * x) % 30
        tb = 3 + int(1000 * y) % 30
    print('m= %r'%(m))
    return m

if __name__=="__main__":
    # print(flag)
    (key, data)=init()
    c = decrypt(key, data)

'''
k1, k2 = 3.967139695598587, 3.7926025078694305
k = [107, 99, 55, 198, 210, 56, 137, 44, 127, 25, 150, 113, 75, 215, 187, 132]
m= 'flag{ii24nji9-8ckkpil1-5hiev3n6-1u24g07m}'
'''
```

------

### Affine

附件给出`affine.py`和`output.txt`两个文件，其中`affine.py`的源码如下：

```python
from secret import flag
from Crypto.Util.number import *

a = getPrime(8)
b = getPrime(8)

ciphertext = []

for f in flag:
    ciphertext.append((a*f + b) % 0x100)

print(bytes(ciphertext))
```

`output.txt`的内容如下：

```python
b"\xb1\x83\x82T\x10\x80\xc9O\x84\xc9<\x0f\xf2\x82\x9a\xc9\x9b8'\x9b<\xdb\x9b\x9b\x82\xc8\xe0V"
```

这题考察的是放射加密，`getPrime(8)`获取一个最大为`8`位的素数。编写`Python`代码求解可得`flag{Kn0wn_p1aint3xt_4ttack}`。

```python
from Crypto.Util.number import *

tmp_flag = 'flag{'
tmp_s = b'\xb1\x83\x82T\x10\x80'
for i in range(3, 257):
    for j in range(3, 257):
        cipher_text = []
        for f in tmp_flag:
            cipher_text.append((i*ord(f)+j)%0x100)
        if bytes(cipher_text) in tmp_s:
            a, b = i, j
            print('a={}, b={}'.format(a, b))

s = b"\xb1\x83\x82T\x10\x80\xc9O\x84\xc9<\x0f\xf2\x82\x9a\xc9\x9b8'\x9b<\xdb\x9b\x9b\x82\xc8\xe0V"
flag = ''
cipher_text = list(s)
for f in cipher_text:
    n1 = inverse(a, 256)
    n2 = n1*b%256
    flag += chr((n1*f-n2)%256)
    
print(flag) # flag{Kn0wn_p1aint3xt_4ttack}
```

------

### unusual_base

附件给出`unusal_base.py`和`output.txt`两个文件，其中`unusal_base.py`的源码如下：

```python
from secret import flag
from Crypto.Util.number import *
from random import shuffle
from string import ascii_lowercase, ascii_uppercase, digits

alphabet = ascii_uppercase + ascii_lowercase + digits +'$&'
alphabet = list(alphabet)
bits = ''
pad_len = len(flag) % 3

for f in flag:  
    bits += bin(f)[2:].rjust(8,'0') # 不足8位用0填充
bits += '0000'*pad_len
encoded = ''
shuffle(alphabet)  # 将字母表元素随机排序
alphabet = "".join(alphabet)
for i in range(0, len(bits), 6):  # 6位为一次,一共38次
    encoded += alphabet[int(bits[i:i+6], 2)] # 从打乱的字母表中取字符
encoded += '%'*pad_len
print(f'encoded = "{encoded}"')
print(f'alphabet = "{alphabet}"')
```

`output.txt`的内容如下：

```python
encoded = "GjN3G$B3de58ym&7wQh9dgVNGQhfG2hndsGjlOyEdaxRFY%"
alphabet = "c5PKAQmgI&qSdyDZYCbOV2seXGloLwtFW3f9n7j481UMHBp6vNETRJa$rxuz0hik"
```

编写`Python`代码求解可得`flag{a1ph4bet_c0u1d_be_d1ffi3r3nt}`。

```python
encoded = "GjN3G$B3de58ym&7wQh9dgVNGQhfG2hndsGjlOyEdaxRFY"
alphabet = "c5PKAQmgI&qSdyDZYCbOV2seXGloLwtFW3f9n7j481UMHBp6vNETRJa$rxuz0hik"
bits = ''
for i in encoded:
    bits += bin(alphabet.index(i))[2:].rjust(6, '0')
print(bits)
flag = ''
for i in range(0, len(bits), 8):
    flag += chr(int(bits[i:i+8], 2))
print(flag) # flag{a1ph4bet_c0u1d_be_d1ffi3r3nt}
```

------

### [[BJDCTF2020]这是base??](https://buuoj.cn/challenges#[BJDCTF2020]%E8%BF%99%E6%98%AFbase??)

附件内容如下：

```
dict:{0: 'J', 1: 'K', 2: 'L', 3: 'M', 4: 'N', 5: 'O', 6: 'x', 7: 'y', 8: 'U', 9: 'V', 10: 'z', 11: 'A', 12: 'B', 13: 'C', 14: 'D', 15: 'E', 16: 'F', 17: 'G', 18: 'H', 19: '7', 20: '8', 21: '9', 22: 'P', 23: 'Q', 24: 'I', 25: 'a', 26: 'b', 27: 'c', 28: 'd', 29: 'e', 30: 'f', 31: 'g', 32: 'h', 33: 'i', 34: 'j', 35: 'k', 36: 'l', 37: 'm', 38: 'W', 39: 'X', 40: 'Y', 41: 'Z', 42: '0', 43: '1', 44: '2', 45: '3', 46: '4', 47: '5', 48: '6', 49: 'R', 50: 'S', 51: 'T', 52: 'n', 53: 'o', 54: 'p', 55: 'q', 56: 'r', 57: 's', 58: 't', 59: 'u', 60: 'v', 61: 'w', 62: '+', 63: '/', 64: '='}

cipertext:
FlZNfnF6Qol6e9w17WwQQoGYBQCgIkGTa9w3IQKw
```

给定了一串密文和这串密文加密时所用的编码对应表`dict`，根据`dict`中键和值的范围，可以推断出这是字符顺序被替换的`base64`编码表。我们需要找到`ciphertext`中每个字符在`dict`中对应的下标，然后再找到这些下标在`base64`编码表中对应的字符。编写`Python`代码求解可得`BJD{D0_Y0u_kNoW_Th1s_b4se_map}`，提交`flag{D0_Y0u_kNoW_Th1s_b4se_map}`即可。

```python
from base64 import b64decode

d = {0: 'J', 1: 'K', 2: 'L', 3: 'M', 4: 'N', 5: 'O', 6: 'x', 7: 'y', 8: 'U', 9: 'V', 10: 'z', 11: 'A', 12: 'B', 13: 'C', 14: 'D', 15: 'E', 16: 'F', 17: 'G', 18: 'H', 19: '7', 20: '8', 21: '9', 22: 'P', 23: 'Q', 24: 'I', 25: 'a', 26: 'b', 27: 'c', 28: 'd', 29: 'e', 30: 'f', 31: 'g', 32: 'h', 33: 'i', 34: 'j', 35: 'k', 36: 'l', 37: 'm', 38: 'W', 39: 'X', 40: 'Y', 41: 'Z', 42: '0', 43: '1', 44: '2', 45: '3', 46: '4', 47: '5', 48: '6', 49: 'R', 50: 'S', 51: 'T', 52: 'n', 53: 'o', 54: 'p', 55: 'q', 56: 'r', 57: 's', 58: 't', 59: 'u', 60: 'v', 61: 'w', 62: '+', 63: '/', 64: '='}
l = list(d.values())
s = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/='
cipertext = 'FlZNfnF6Qol6e9w17WwQQoGYBQCgIkGTa9w3IQKw'

flag = ''
for ch in cipertext:
    flag += s[l.index(ch)]
flag = b64decode(flag).decode()
print(flag) # BJD{D0_Y0u_kNoW_Th1s_b4se_map}
```

------

### [Rot](https://buuoj.cn/challenges#rot)

附件内容如下：

> 破解下面的密文：
>
> 83 89 78 84 45 86 96 45 115 121 110 116 136 132 132 132 108 128 117 118 134 110 123 111 110 127 108 112 124 122 108 118 128 108 131 114 127 134 108 116 124 124 113 108 76 76 76 76 138 23 90 81 66 71 64 69 114 65 112 64 66 63 69 61 70 114 62 66 61 62 69 67 70 63 61 110 110 112 64 68 62 70 61 112 111 112
>
> flag格式flag{}

编写`Python`代码进行`Rot13`解码：

```python
l = list(map(int, '83 89 78 84 45 86 96 45 115 121 110 116 136 132 132 132 108 128 117 118 134 110 123 111 110 127 108 112 124 122 108 118 128 108 131 114 127 134 108 116 124 124 113 108 76 76 76 76 138 23 90 81 66 71 64 69 114 65 112 64 66 63 69 61 70 114 62 66 61 62 69 67 70 63 61 110 110 112 64 68 62 70 61 112 111 112'.split(' ')))
print(''.join(chr(i-13) for i in l))
```

得到以下结果：

```
FLAG IS flag{www_shiyanbar_com_is_very_good_????}
MD5:38e4c352809e150186920aac37190cbc
```

编写`Python`代码爆破得到`flag{www_shiyanbar_com_is_very_good_@8Mu}`。

```python
from hashlib import md5

flag = 'flag{www_shiyanbar_com_is_very_good_'
cipher = '38e4c352809e150186920aac37190cbc'
for i in range(32,126):
    for j in range(32,126):
        for k in range(32,126):
            for m in range(32,126):
                s = flag+chr(i)+chr(j)+chr(k)+chr(m)+'}'
                t = md5(s.encode()).hexdigest()
                if t == cipher:
                    flag = s
                    print(flag)
                    exit()
```

------

### [[NCTF2019]childRSA](https://buuoj.cn/challenges#[NCTF2019]childRSA)

附件解压缩后的`.py`文件源码如下：

```python
from random import choice
from Crypto.Util.number import isPrime, sieve_base as primes
from flag import flag

def getPrime(bits):
    while True:
        n = 2
        while n.bit_length() < bits:
            n *= choice(primes)
        if isPrime(n + 1):
            return n + 1

e = 0x10001
m = int.from_bytes(flag.encode(), 'big')
p, q = [getPrime(2048) for _ in range(2)]
n = p * q
c = pow(m, e, n)

# n = 32849718197337581823002243717057659218502519004386996660885100592872201948834155543125924395614928962750579667346279456710633774501407292473006312537723894221717638059058796679686953564471994009285384798450493756900459225040360430847240975678450171551048783818642467506711424027848778367427338647282428667393241157151675410661015044633282064056800913282016363415202171926089293431012379261585078566301060173689328363696699811123592090204578098276704877408688525618732848817623879899628629300385790344366046641825507767709276622692835393219811283244303899850483748651722336996164724553364097066493953127153066970594638491950199605713033004684970381605908909693802373826516622872100822213645899846325022476318425889580091613323747640467299866189070780620292627043349618839126919699862580579994887507733838561768581933029077488033326056066378869170169389819542928899483936705521710423905128732013121538495096959944889076705471928490092476616709838980562233255542325528398956185421193665359897664110835645928646616337700617883946369110702443135980068553511927115723157704586595844927607636003501038871748639417378062348085980873502535098755568810971926925447913858894180171498580131088992227637341857123607600275137768132347158657063692388249513
# c = 26308018356739853895382240109968894175166731283702927002165268998773708335216338997058314157717147131083296551313334042509806229853341488461087009955203854253313827608275460592785607739091992591431080342664081962030557042784864074533380701014585315663218783130162376176094773010478159362434331787279303302718098735574605469803801873109982473258207444342330633191849040553550708886593340770753064322410889048135425025715982196600650740987076486540674090923181664281515197679745907830107684777248532278645343716263686014941081417914622724906314960249945105011301731247324601620886782967217339340393853616450077105125391982689986178342417223392217085276465471102737594719932347242482670320801063191869471318313514407997326350065187904154229557706351355052446027159972546737213451422978211055778164578782156428466626894026103053360431281644645515155471301826844754338802352846095293421718249819728205538534652212984831283642472071669494851823123552827380737798609829706225744376667082534026874483482483127491533474306552210039386256062116345785870668331513725792053302188276682550672663353937781055621860101624242216671635824311412793495965628876036344731733142759495348248970313655381407241457118743532311394697763283681852908564387282605279108
```

调用`requests`库在线请求 http://factordb.com 分解模数`n`可以得到`p`和`q`，接着就是`RSA`题的常规运算啦。

编写`Python`代码求解，提交`flag{Th3r3_ar3_1ns3cure_RSA_m0duli_7hat_at_f1rst_gl4nce_appe4r_t0_be_s3cur3}`即可。

```python
import requests
from libnum import *

def factorize(n):
    l = []
    url="http://factordb.com/api?query="+str(n)
    r = requests.get(url)
    data = r.json()
    for factor in data['factors']:
        l.append(int(factor[0]))
    return l

n = 32849718197337581823002243717057659218502519004386996660885100592872201948834155543125924395614928962750579667346279456710633774501407292473006312537723894221717638059058796679686953564471994009285384798450493756900459225040360430847240975678450171551048783818642467506711424027848778367427338647282428667393241157151675410661015044633282064056800913282016363415202171926089293431012379261585078566301060173689328363696699811123592090204578098276704877408688525618732848817623879899628629300385790344366046641825507767709276622692835393219811283244303899850483748651722336996164724553364097066493953127153066970594638491950199605713033004684970381605908909693802373826516622872100822213645899846325022476318425889580091613323747640467299866189070780620292627043349618839126919699862580579994887507733838561768581933029077488033326056066378869170169389819542928899483936705521710423905128732013121538495096959944889076705471928490092476616709838980562233255542325528398956185421193665359897664110835645928646616337700617883946369110702443135980068553511927115723157704586595844927607636003501038871748639417378062348085980873502535098755568810971926925447913858894180171498580131088992227637341857123607600275137768132347158657063692388249513
c = 26308018356739853895382240109968894175166731283702927002165268998773708335216338997058314157717147131083296551313334042509806229853341488461087009955203854253313827608275460592785607739091992591431080342664081962030557042784864074533380701014585315663218783130162376176094773010478159362434331787279303302718098735574605469803801873109982473258207444342330633191849040553550708886593340770753064322410889048135425025715982196600650740987076486540674090923181664281515197679745907830107684777248532278645343716263686014941081417914622724906314960249945105011301731247324601620886782967217339340393853616450077105125391982689986178342417223392217085276465471102737594719932347242482670320801063191869471318313514407997326350065187904154229557706351355052446027159972546737213451422978211055778164578782156428466626894026103053360431281644645515155471301826844754338802352846095293421718249819728205538534652212984831283642472071669494851823123552827380737798609829706225744376667082534026874483482483127491533474306552210039386256062116345785870668331513725792053302188276682550672663353937781055621860101624242216671635824311412793495965628876036344731733142759495348248970313655381407241457118743532311394697763283681852908564387282605279108
e = 0x10001
p, q = factorize(n)
d = invmod(e, (p-1)*(q-1))
m = pow(c, d, n)
flag = n2s(m).decode()
print(flag) # NCTF{Th3r3_ar3_1ns3cure_RSA_m0duli_7hat_at_f1rst_gl4nce_appe4r_t0_be_s3cur3}
```

------

### [[NCTF2019]babyRSA](https://buuoj.cn/challenges#[NCTF2019]babyRSA)

附件解压缩后得到`task.py`，源码如下：

```python
from Crypto.Util.number import *
from flag import flag

def nextPrime(n):
    n += 2 if n & 1 else 1
    while not isPrime(n):
        n += 2
    return n

p = getPrime(1024)
q = nextPrime(p)
n = p * q
e = 0x10001
d = inverse(e, (p-1) * (q-1))
c = pow(bytes_to_long(flag.encode()), e, n)

# d = 19275778946037899718035455438175509175723911466127462154506916564101519923603308900331427601983476886255849200332374081996442976307058597390881168155862238533018621944733299208108185814179466844504468163200369996564265921022888670062554504758512453217434777820468049494313818291727050400752551716550403647148197148884408264686846693842118387217753516963449753809860354047619256787869400297858568139700396567519469825398575103885487624463424429913017729585620877168171603444111464692841379661112075123399343270610272287865200880398193573260848268633461983435015031227070217852728240847398084414687146397303110709214913
# c = 5382723168073828110696168558294206681757991149022777821127563301413483223874527233300721180839298617076705685041174247415826157096583055069337393987892262764211225227035880754417457056723909135525244957935906902665679777101130111392780237502928656225705262431431953003520093932924375902111280077255205118217436744112064069429678632923259898627997145803892753989255615273140300021040654505901442787810653626524305706316663169341797205752938755590056568986738227803487467274114398257187962140796551136220532809687606867385639367743705527511680719955380746377631156468689844150878381460560990755652899449340045313521804
```

已知`c`，`d`，`e`，求`m`。通过加密算法可知，`p`和`q`是`1024`位的，因此两者相乘不低于`2048`位，通过运算可知`e*d-1`为`2064`位，因此`k`的范围就是 $\large{[2^{15},2^{16})}$，左闭右开。

> $\Large{e*d\equiv1mod(p-1)*(q-1)}$
>
> => $\Large{e*d-1\equiv k*(p-1)*(q-1)}$

写`Python`代码爆破`k`求解，得到`NCTF{70u2_nn47h_14_v3ry_gOO0000000d}`，提交`flag{70u2_nn47h_14_v3ry_gOO0000000d}`。

```python
import sympy.crypto
from libnum import *
from gmpy2 import iroot

d = 19275778946037899718035455438175509175723911466127462154506916564101519923603308900331427601983476886255849200332374081996442976307058597390881168155862238533018621944733299208108185814179466844504468163200369996564265921022888670062554504758512453217434777820468049494313818291727050400752551716550403647148197148884408264686846693842118387217753516963449753809860354047619256787869400297858568139700396567519469825398575103885487624463424429913017729585620877168171603444111464692841379661112075123399343270610272287865200880398193573260848268633461983435015031227070217852728240847398084414687146397303110709214913
c = 5382723168073828110696168558294206681757991149022777821127563301413483223874527233300721180839298617076705685041174247415826157096583055069337393987892262764211225227035880754417457056723909135525244957935906902665679777101130111392780237502928656225705262431431953003520093932924375902111280077255205118217436744112064069429678632923259898627997145803892753989255615273140300021040654505901442787810653626524305706316663169341797205752938755590056568986738227803487467274114398257187962140796551136220532809687606867385639367743705527511680719955380746377631156468689844150878381460560990755652899449340045313521804
e = 0x10001
ed1 = e*d-1
for k in range(pow(2,15),pow(2,16)):
    if ed1%k==0:
        x = iroot(ed1//k,2)[0]
        p = sympy.prevprime(x)
        q = sympy.nextprime(p)
        if (p-1)*(q-1)*k==ed1:
            # print(k, p, q)
            # k = 61610
            # p = 143193611591752210918770476402384783351740028841763223236102885221839966637073188462808195974548579833368313904083095786906479416347681923731100260359652426441593107755892485944809419189348311956308456459523437459969713060653432909873986596042482699670451716296743727525586437248462432327423361080811225075839
            # q = 143193611591752210918770476402384783351740028841763223236102885221839966637073188462808195974548579833368313904083095786906479416347681923731100260359652426441593107755892485944809419189348311956308456459523437459969713060653432909873986596042482699670451716296743727525586437248462432327423361080811225076497
            break
n = p*q
m = pow(c, d, n)
flag = n2s(m).decode()
print(flag)  # NCTF{70u2_nn47h_14_v3ry_gOO0000000d}
```

------

### [[HDCTF2019]bbbbbbrsa](https://buuoj.cn/challenges#[HDCTF2019]bbbbbbrsa)

附件解压缩后得到`encode.py`和`enc`，`encode.py`源码如下，写的真不敢恭维呐：

```python
from base64 import b64encode as b32encode
from gmpy2 import invert,gcd,iroot
from Crypto.Util.number import *
from binascii import a2b_hex,b2a_hex
import random

flag = "******************************"
nbit = 128
p = getPrime(nbit)
q = getPrime(nbit)
n = p*q
print p
print n

phi = (p-1)*(q-1)
e = random.randint(50000,70000)

while True:
    if gcd(e,phi) == 1:
        break;
    else:
        e -= 1;

c = pow(int(b2a_hex(flag),16),e,n)
print b32encode(str(c))[::-1]
# 2373740699529364991763589324200093466206785561836101840381622237225512234632
```

`enc`内容如下：

```
p = 177077389675257695042507998165006460849
n = 37421829509887796274897162249367329400988647145613325367337968063341372726061
c = ==gMzYDNzIjMxUTNyIzNzIjMyYTM4MDM0gTMwEjNzgTM2UTN4cjNwIjN2QzM5ADMwIDNyMTO4UzM2cTM5kDN2MTOyUTO5YDM0czM3MjM
```

显然，`c`是`base64`加密后倒序的字符串，`q`可以根据`p`和`n`得到，`e`给定了一个可爆破的范围，编写`Python`代码求解得到`flag{rs4_1s_s1mpl3!#}`。

```python
from libnum import *
from base64 import b64decode

p = 177077389675257695042507998165006460849
n = 37421829509887796274897162249367329400988647145613325367337968063341372726061
c = '==gMzYDNzIjMxUTNyIzNzIjMyYTM4MDM0gTMwEjNzgTM2UTN4cjNwIjN2QzM5ADMwIDNyMTO4UzM2cTM5kDN2MTOyUTO5YDM0czM3MjM'
q = n//p
c = int(b64decode(c[::-1]))
# c = 2373740699529364991763589324200093466206785561836101840381622237225512234632
phi = (p-1)*(q-1)
for e in range(50000, 70000):
    if gcd(e, phi) == 1:
        d = invmod(e, phi)
        m = pow(c, d, n)
        if b'flag' in n2s(m):
            print('e = ', e) # e =  51527
            flag = n2s(m).decode()
            print(flag) # flag{rs4_1s_s1mpl3!#}
            break
```

------

### [[BJDCTF2020]RSA](https://buuoj.cn/challenges#[BJDCTF2020]RSA)

附件解压缩后得到以下源码：

```python
from Crypto.Util.number import getPrime,bytes_to_long

flag=open("flag","rb").read()

p=getPrime(1024)
q=getPrime(1024)
assert(e<100000)
n=p*q
m=bytes_to_long(flag)
c=pow(m,e,n)
print c,n
print pow(294,e,n)

p=getPrime(1024)
n=p*q
m=bytes_to_long("BJD"*32)
c=pow(m,e,n)
print c,n

'''
output:
12641635617803746150332232646354596292707861480200207537199141183624438303757120570096741248020236666965755798009656547738616399025300123043766255518596149348930444599820675230046423373053051631932557230849083426859490183732303751744004874183062594856870318614289991675980063548316499486908923209627563871554875612702079100567018698992935818206109087568166097392314105717555482926141030505639571708876213167112187962584484065321545727594135175369233925922507794999607323536976824183162923385005669930403448853465141405846835919842908469787547341752365471892495204307644586161393228776042015534147913888338316244169120  13508774104460209743306714034546704137247627344981133461801953479736017021401725818808462898375994767375627749494839671944543822403059978073813122441407612530658168942987820256786583006947001711749230193542370570950705530167921702835627122401475251039000775017381633900222474727396823708695063136246115652622259769634591309421761269548260984426148824641285010730983215377509255011298737827621611158032976420011662547854515610597955628898073569684158225678333474543920326532893446849808112837476684390030976472053905069855522297850688026960701186543428139843783907624317274796926248829543413464754127208843070331063037
381631268825806469518166370387352035475775677163615730759454343913563615970881967332407709901235637718936184198930226303761876517101208677107311006065728014220477966000620964056616058676999878976943319063836649085085377577273214792371548775204594097887078898598463892440141577974544939268247818937936607013100808169758675042264568547764031628431414727922168580998494695800403043312406643527637667466318473669542326169218665366423043579003388486634167642663495896607282155808331902351188500197960905672207046579647052764579411814305689137519860880916467272056778641442758940135016400808740387144508156358067955215018
979153370552535153498477459720877329811204688208387543826122582132404214848454954722487086658061408795223805022202997613522014736983452121073860054851302343517756732701026667062765906277626879215457936330799698812755973057557620930172778859116538571207100424990838508255127616637334499680058645411786925302368790414768248611809358160197554369255458675450109457987698749584630551177577492043403656419968285163536823819817573531356497236154342689914525321673807925458651854768512396355389740863270148775362744448115581639629326362342160548500035000156097215446881251055505465713854173913142040976382500435185442521721  12806210903061368369054309575159360374022344774547459345216907128193957592938071815865954073287532545947370671838372144806539753829484356064919357285623305209600680570975224639214396805124350862772159272362778768036844634760917612708721787320159318432456050806227784435091161119982613987303255995543165395426658059462110056431392517548717447898084915167661172362984251201688639469652283452307712821398857016487590794996544468826705600332208535201443322267298747117528882985955375246424812616478327182399461709978893464093245135530135430007842223389360212803439850867615121148050034887767584693608776323252233254261047
'''
```

注意到`n1`和`n2`的`q`相同，因此可以通过求最大公因数得到`q`，从而得到`p1 = n//q`，然后根据`pow(294,e,n)`的值爆破出`e = 52361`，进而得到`flag{p_is_common_divisor}`。

```python
from libnum import *

c1 = 12641635617803746150332232646354596292707861480200207537199141183624438303757120570096741248020236666965755798009656547738616399025300123043766255518596149348930444599820675230046423373053051631932557230849083426859490183732303751744004874183062594856870318614289991675980063548316499486908923209627563871554875612702079100567018698992935818206109087568166097392314105717555482926141030505639571708876213167112187962584484065321545727594135175369233925922507794999607323536976824183162923385005669930403448853465141405846835919842908469787547341752365471892495204307644586161393228776042015534147913888338316244169120 
n1 = 13508774104460209743306714034546704137247627344981133461801953479736017021401725818808462898375994767375627749494839671944543822403059978073813122441407612530658168942987820256786583006947001711749230193542370570950705530167921702835627122401475251039000775017381633900222474727396823708695063136246115652622259769634591309421761269548260984426148824641285010730983215377509255011298737827621611158032976420011662547854515610597955628898073569684158225678333474543920326532893446849808112837476684390030976472053905069855522297850688026960701186543428139843783907624317274796926248829543413464754127208843070331063037
c_294 = 381631268825806469518166370387352035475775677163615730759454343913563615970881967332407709901235637718936184198930226303761876517101208677107311006065728014220477966000620964056616058676999878976943319063836649085085377577273214792371548775204594097887078898598463892440141577974544939268247818937936607013100808169758675042264568547764031628431414727922168580998494695800403043312406643527637667466318473669542326169218665366423043579003388486634167642663495896607282155808331902351188500197960905672207046579647052764579411814305689137519860880916467272056778641442758940135016400808740387144508156358067955215018
c2 = 979153370552535153498477459720877329811204688208387543826122582132404214848454954722487086658061408795223805022202997613522014736983452121073860054851302343517756732701026667062765906277626879215457936330799698812755973057557620930172778859116538571207100424990838508255127616637334499680058645411786925302368790414768248611809358160197554369255458675450109457987698749584630551177577492043403656419968285163536823819817573531356497236154342689914525321673807925458651854768512396355389740863270148775362744448115581639629326362342160548500035000156097215446881251055505465713854173913142040976382500435185442521721 
n2 = 12806210903061368369054309575159360374022344774547459345216907128193957592938071815865954073287532545947370671838372144806539753829484356064919357285623305209600680570975224639214396805124350862772159272362778768036844634760917612708721787320159318432456050806227784435091161119982613987303255995543165395426658059462110056431392517548717447898084915167661172362984251201688639469652283452307712821398857016487590794996544468826705600332208535201443322267298747117528882985955375246424812616478327182399461709978893464093245135530135430007842223389360212803439850867615121148050034887767584693608776323252233254261047
q = gcd(n1, n2)
p1 = n1//q
for e in range(100000):
    if pow(294,e,n1) == c_294:
        print('e =', e) # e =  52361
        break
d1 = invmod(e, (p1-1)*(q-1))
m1 = pow(c1, d1, n1)
flag = n2s(m1).decode()
print(flag)  # BJD{p_is_common_divisor}
```

------

### [[BJDCTF2020]rsa_output](https://buuoj.cn/challenges#[BJDCTF2020]rsa_output)

附件解压缩后得到以下内容：

```
{21058339337354287847534107544613605305015441090508924094198816691219103399526800112802416383088995253908857460266726925615826895303377801614829364034624475195859997943146305588315939130777450485196290766249612340054354622516207681542973756257677388091926549655162490873849955783768663029138647079874278240867932127196686258800146911620730706734103611833179733264096475286491988063990431085380499075005629807702406676707841324660971173253100956362528346684752959937473852630145893796056675793646430793578265418255919376323796044588559726703858429311784705245069845938316802681575653653770883615525735690306674635167111,2767}

{21058339337354287847534107544613605305015441090508924094198816691219103399526800112802416383088995253908857460266726925615826895303377801614829364034624475195859997943146305588315939130777450485196290766249612340054354622516207681542973756257677388091926549655162490873849955783768663029138647079874278240867932127196686258800146911620730706734103611833179733264096475286491988063990431085380499075005629807702406676707841324660971173253100956362528346684752959937473852630145893796056675793646430793578265418255919376323796044588559726703858429311784705245069845938316802681575653653770883615525735690306674635167111,3659}

message1=20152490165522401747723193966902181151098731763998057421967155300933719378216342043730801302534978403741086887969040721959533190058342762057359432663717825826365444996915469039056428416166173920958243044831404924113442512617599426876141184212121677500371236937127571802891321706587610393639446868836987170301813018218408886968263882123084155607494076330256934285171370758586535415136162861138898728910585138378884530819857478609791126971308624318454905992919405355751492789110009313138417265126117273710813843923143381276204802515910527468883224274829962479636527422350190210717694762908096944600267033351813929448599

message2=11298697323140988812057735324285908480504721454145796535014418738959035245600679947297874517818928181509081545027056523790022598233918011261011973196386395689371526774785582326121959186195586069851592467637819366624044133661016373360885158956955263645614345881350494012328275215821306955212788282617812686548883151066866149060363482958708364726982908798340182288702101023393839781427386537230459436512613047311585875068008210818996941460156589314135010438362447522428206884944952639826677247819066812706835773107059567082822312300721049827013660418610265189288840247186598145741724084351633508492707755206886202876227
```

题目给定了两个不同的`c`和`e`，以及一个共同的`n`值，推断出考察点是`RSA`共模攻击。

```
c1 = m^e1 % n   =>   c1^s1 = m^(e1*s1) mod n
c2 = m^e2 % n   =>   c2^s2 = m^(e2*s2) mod n
# 根据扩展的欧几里得算法，可以得到
e1*s1 + e2*s2 = gcd(e1, e2) = 1 # s1、s2皆为整数，但是一正一负
(c1^s1*c2^s2)%n = ((m^e1%n)^s1*(m^e2%n)^s2)%n
//化简为((m^e1)^s1*(m^e2)^s2)%n = (m^(e1^s1+e2^s2))%n
(c1^s1*c2^s2)%n = m%n
# 最后化简可得
c1^s1*c2^s2 = m
```

编写`Python`代码求解得到`BJD{r3a_C0mmoN_moD@_4ttack}`，提交`flag{r3a_C0mmoN_moD@_4ttack}`即可。

```python
from libnum import *

n=21058339337354287847534107544613605305015441090508924094198816691219103399526800112802416383088995253908857460266726925615826895303377801614829364034624475195859997943146305588315939130777450485196290766249612340054354622516207681542973756257677388091926549655162490873849955783768663029138647079874278240867932127196686258800146911620730706734103611833179733264096475286491988063990431085380499075005629807702406676707841324660971173253100956362528346684752959937473852630145893796056675793646430793578265418255919376323796044588559726703858429311784705245069845938316802681575653653770883615525735690306674635167111
e1=2767
e2=3659
c1=20152490165522401747723193966902181151098731763998057421967155300933719378216342043730801302534978403741086887969040721959533190058342762057359432663717825826365444996915469039056428416166173920958243044831404924113442512617599426876141184212121677500371236937127571802891321706587610393639446868836987170301813018218408886968263882123084155607494076330256934285171370758586535415136162861138898728910585138378884530819857478609791126971308624318454905992919405355751492789110009313138417265126117273710813843923143381276204802515910527468883224274829962479636527422350190210717694762908096944600267033351813929448599
c2=11298697323140988812057735324285908480504721454145796535014418738959035245600679947297874517818928181509081545027056523790022598233918011261011973196386395689371526774785582326121959186195586069851592467637819366624044133661016373360885158956955263645614345881350494012328275215821306955212788282617812686548883151066866149060363482958708364726982908798340182288702101023393839781427386537230459436512613047311585875068008210818996941460156589314135010438362447522428206884944952639826677247819066812706835773107059567082822312300721049827013660418610265189288840247186598145741724084351633508492707755206886202876227

s = xgcd(e1, e2) #扩展欧几里得算法
m1 = pow(c1, s[0], n)
m2 = pow(c2, s[1], n)
m = (m1*m2)%n
flag = n2s(m).decode()
print(flag) # BJD{r3a_C0mmoN_moD@_4ttack}
```

------

### [[ACTF新生赛2020]crypto-rsa0](https://buuoj.cn/challenges#[ACTF%E6%96%B0%E7%94%9F%E8%B5%9B2020]crypto-rsa0)

根据附件中的`hint`可知，压缩包被伪加密啦。

以下是一些关于压缩包加密的知识点。

> - 压缩源文件数据区：
>   50 4B 03 04 是头文件的标志 （0x04034b50）
>
>   00 00 全局方式标记（判断有无加密的重要标志）
>
> - 压缩文件目录区
>   50 4B 01 02 目录中文件头标志（0x02014b50）
>   
>   00 00 全局方式标记（有无加密的重要标志，更改这里就可以进行伪加密了，改为 09 00 打开就会提示有密码了。）
>   
> - 压缩源文件目录结束标志
>
>   50 4B 05 06 目录结束标记
>
>   辨别真假加密：
>
>   - 无加密：
>     - 压缩源文件数据区的全局加密应当为 00 00，且压缩源文件目录区的全局方式标记应当为00 00
>
>   - 假加密
>     - 压缩源文件数据区的全局加密应当为 00 00，且压缩文件目录区的全局方式标记应当为 09 00
>
>   - 真加密
>     - 压缩源文件数据区的全局加密应当为 09 00，且压缩源文件目录区的全局方式应当为 09 00

打开`WinHex`，遇到`50 4B 03 04`就把其后第3、4个字节改成`00 00`，遇到`50 4B 01 02`，把其后第5、6个字节改成`00 00`即可破解伪加密。解压缩后的`rsa0.py`文件源码如下：

```python
from Cryptodome.Util.number import *
import random
 
FLAG=#hidden, please solve it
flag=int.from_bytes(FLAG,byteorder = 'big')
 
p=getPrime(512)
q=getPrime(512)
 
print(p)
print(q)
N=p*q
e=65537
enc = pow(flag,e,N)
print (enc)
```

`output`中的内容如下：

```
9018588066434206377240277162476739271386240173088676526295315163990968347022922841299128274551482926490908399237153883494964743436193853978459947060210411
7547005673877738257835729760037765213340036696350766324229143613179932145122130685778504062410137043635958208805698698169847293520149572605026492751740223
50996206925961019415256003394743594106061473865032792073035954925875056079762626648452348856255575840166640519334862690063949316515750256545937498213476286637455803452890781264446030732369871044870359838568618176586206041055000297981733272816089806014400846392307742065559331874972274844992047849472203390350
```

常规`RSA`题，编写`Python`代码求解得到`actf{n0w_y0u_see_RSA}`，提交`flag{n0w_y0u_see_RSA}`即可。

```python
from libnum import *
p = 9018588066434206377240277162476739271386240173088676526295315163990968347022922841299128274551482926490908399237153883494964743436193853978459947060210411
q = 7547005673877738257835729760037765213340036696350766324229143613179932145122130685778504062410137043635958208805698698169847293520149572605026492751740223
enc = 50996206925961019415256003394743594106061473865032792073035954925875056079762626648452348856255575840166640519334862690063949316515750256545937498213476286637455803452890781264446030732369871044870359838568618176586206041055000297981733272816089806014400846392307742065559331874972274844992047849472203390350
e = 65537
n = p*q
d = invmod(e, (p-1)*(q-1))
m = pow(enc,d,n)
flag = n2s(m).decode()
print(flag) # actf{n0w_y0u_see_RSA}
```

------

### [[ACTF新生赛2020]crypto-rsa3](https://buuoj.cn/challenges#[ACTF%E6%96%B0%E7%94%9F%E8%B5%9B2020]crypto-rsa3)

附件解压缩后得到`rsa3.py`和`output.txt`，其中`rsa3.py`源码如下：

```python
from flag import FLAG
from Cryptodome.Util.number import *
import gmpy2
import random

e=65537
p = getPrime(512)
q = int(gmpy2.next_prime(p))
n = p*q
m = bytes_to_long(FLAG)
c = pow(m,e,n)
print(n)
print(c)
```

`output.txt`中的内容如下：

```
177606504836499246970959030226871608885969321778211051080524634084516973331441644993898029573612290095853069264036530459253652875586267946877831055147546910227100566496658148381834683037366134553848011903251252726474047661274223137727688689535823533046778793131902143444408735610821167838717488859902242863683
1457390378511382354771000540945361168984775052693073641682375071407490851289703070905749525830483035988737117653971428424612332020925926617395558868160380601912498299922825914229510166957910451841730028919883807634489834128830801407228447221775264711349928156290102782374379406719292116047581560530382210049
```

`q`是`p`的下一个素数，说明这两个质数非常接近，没必要用http://factordb.com来暴力分解模数`N`得到`p`和`q`啦。这题可以把`N`开平方，所得结果的`nextprime()`就是`q`，而`p = N//q`，接着就是`RSA`题的常规求解啦。

编写`Python`代码求解得到`actf{p_and_q_should_not_be_so_close_in_value}`，大括号外换成`flag`提交即可。

```python
from math import isqrt
from gmpy2 import next_prime
from Crypto.Util.number import *

n = 177606504836499246970959030226871608885969321778211051080524634084516973331441644993898029573612290095853069264036530459253652875586267946877831055147546910227100566496658148381834683037366134553848011903251252726474047661274223137727688689535823533046778793131902143444408735610821167838717488859902242863683
c = 1457390378511382354771000540945361168984775052693073641682375071407490851289703070905749525830483035988737117653971428424612332020925926617395558868160380601912498299922825914229510166957910451841730028919883807634489834128830801407228447221775264711349928156290102782374379406719292116047581560530382210049
e = 65537
x = isqrt(n)
q = next_prime(x)
p = n//q
# print(p, q)
# p = 13326909050357447643526585836833969378078147057723054701432842192988717649385731430095055622303549577233495793715580004801634268505725255565021519817179231 
# q = 13326909050357447643526585836833969378078147057723054701432842192988717649385731430095055622303549577233495793715580004801634268505725255565021519817179293
d = inverse(e, (p-1)*(q-1))
m = pow(c, d, n)
flag = long_to_bytes(m).decode()
print(flag) # actf{p_and_q_should_not_be_so_close_in_value}
```

------

### [[AFCTF2018]你能看出这是什么加密么](https://buuoj.cn/challenges#[AFCTF2018]%E4%BD%A0%E8%83%BD%E7%9C%8B%E5%87%BA%E8%BF%99%E6%98%AF%E4%BB%80%E4%B9%88%E5%8A%A0%E5%AF%86%E4%B9%88)

附件内容如下：

```python
p=0x928fb6aa9d813b6c3270131818a7c54edb18e3806942b88670106c1821e0326364194a8c49392849432b37632f0abe3f3c52e909b939c91c50e41a7b8cd00c67d6743b4f

q=0xec301417ccdffa679a8dcc4027dd0d75baf9d441625ed8930472165717f4732884c33f25d4ee6a6c9ae6c44aedad039b0b72cf42cab7f80d32b74061

e=0x10001

c=0x70c9133e1647e95c3cb99bd998a9028b5bf492929725a9e8e6d2e277fa0f37205580b196e5f121a2e83bc80a8204c99f5036a07c8cf6f96c420369b4161d2654a7eccbdaf583204b645e137b3bd15c5ce865298416fd5831cba0d947113ed5be5426b708b89451934d11f9aed9085b48b729449e461ff0863552149b965e22b6
```

将十六进制转换成十进制后就是常规的`RSA`题求解：

```python
from libnum import *

p = int(0x928fb6aa9d813b6c3270131818a7c54edb18e3806942b88670106c1821e0326364194a8c49392849432b37632f0abe3f3c52e909b939c91c50e41a7b8cd00c67d6743b4f)
q = int(0xec301417ccdffa679a8dcc4027dd0d75baf9d441625ed8930472165717f4732884c33f25d4ee6a6c9ae6c44aedad039b0b72cf42cab7f80d32b74061)
e = int(0x10001)
c = int(0x70c9133e1647e95c3cb99bd998a9028b5bf492929725a9e8e6d2e277fa0f37205580b196e5f121a2e83bc80a8204c99f5036a07c8cf6f96c420369b4161d2654a7eccbdaf583204b645e137b3bd15c5ce865298416fd5831cba0d947113ed5be5426b708b89451934d11f9aed9085b48b729449e461ff0863552149b965e22b6)
n = p*q
d = invmod(e, (p-1)*(q-1))
m = pow(c, d, n)
print(n2s(m))
# 这啥玩意?! b'\x02\xd3\xe4v\xea\x80r\x83\xda\x99\x88\xf5#\x08\xbbAT\x8b\xaf\xd2\xf4\xdc\x9f\xd3\xbf\xb7A\xc3\xcc\xc5`\xa1\x8b\x86\x18y\xd0&\x88\x10\xef\xbe\x83\xcer\xceC\x17\xec[\xb7%\x08\xef\x16\x1f\xab\x0c\x96\xa3\xdc N^\x8e,\xa3\x11{\x99U\xcd\x15o\xd7B\xf4L\x8f}&\xc5$\xca\xd5;\xf9\x02Y\xc1\xbbS\xfd4\x83M\x96\xa9\xbd;\x83/\xf7\x00afctf{R54_|5_$0_$imp13}'
flag = 'afctf{R54_|5_$0_$imp13}'.replace('afctf', 'flag')
print(flag) # flag{R54_|5_$0_$imp13}
```

提交`flag{R54_|5_$0_$imp13}`即可。

------

### [yxx](https://buuoj.cn/challenges#yxx)

附件解压缩后得到`密文.txt`和`明文.txt`。编写`Python`代码对这两个文件的二进制数据进行异或操作：

```python
from libnum import b2s

m = '0110110001101111011101100110010101101100011011110111011001100101011011000110111101110110011001010110110001101111011101100110010101101100011011110111011001100101011011000110111101110110011001010110110001101111011101100110010101101100011011110111011001100101'
c = '0000101000000011000101110000001001010110000000010001010100010001000010100001010000001110000010100001111000110000000011100000101000011110001100000000111000001010000111100011000000010100000011000001100100001101000111110001000000001110000001100000001100011000'
flag = ''
for i in range(len(m)):
    if(m[i]==c[i]):
        flag += '0'
    else:
        flag += '1'

flag = b2s(flag).decode()
print(flag) # flag:nctf{xor_xor_xor_biubiubiu}
```

提交`flag{xor_xor_xor_biubiubiu}`即可。

------

### [[AFCTF2018]Vigenère](https://buuoj.cn/challenges#[AFCTF2018]Vigen%C3%A8re)

附件解压缩后得到`encode.c`和`flag_encode.txt`，其中`encode.c`源码如下：

```c
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int main()
{
    freopen("flag.txt","r",stdin);
    freopen("flag_encode.txt","w",stdout);
    char key[] = /*SADLY SAYING! Key is eaten by Monster!*/;
    int len = strlen(key);
    char ch;
    int index = 0;
    while((ch = getchar()) != EOF){
        if(ch>='a'&&ch<='z'){
            putchar((ch-'a'+key[index%len]-'a')%26+'a');
            ++index;
        }else if(ch>='A'&&ch<='Z'){
            putchar((ch-'A'+key[index%len]-'a')%26+'A');
            ++index;
        }else{
            putchar(ch);
        }
    }
    return 0;
}
```

`flag_encode.txt`内容如下：

```
Yzyj ia zqm Cbatky kf uavin rbgfno ig hnkozku fyyefyjzy sut gha pruyte gu famooybn bhr vqdcpipgu jaaju obecu njde pupfyytrj cpez cklb wnbzqmr ntf li wsfavm azupy nde cufmrf uh lba enxcp, tuk uwjwrnzn inq ksmuh sggcqoa zq obecu zqm Lncu gz Jagaam aaj qx Hwthxn'a Gbj gfnetyk cpez, g fwwang xnapriv li phr uyqnvupk ib mnttqnq xgioerry cpag zjws ohbaul drinsla tuk liufku obecu ovxey zjwg po gnn aecgtsneoa.

Cn poyj vzyoe gxdbhf zq ty oeyl-ndiqkpl, ndag gut mrt cjy yrrgcmd rwwsf, phnz cpel gtw yjdbcnl bl zjwcn Cekjboe cklb yeezjqn htcdcannhum Rvmjlm, phnz juoam vzyoe nxn Tisk, Navarge jvd gng honshoc wf Ugrhcjefy. — Cpag zq kyyuek cpefk taadtf, Mxdeetowhps nxn qnfzklopeq gvwnt Sgf, xarvbrvg gngal fufz ywwrxu xlkm gnn koaygfn kf gnn ooiktfyz, — Tugc ehrtgnyn aae Owrz uh Yireetvmng hguiief jnateaelcre bl cpefk gfxo, ig ob bhr Xkybp os zqm Prurdy po nrcmr bx vg uxoyobp ig, gpv nk iaycqthzg fys Gbbnznzkpl, fwyvtp qtf lqmhzagoxv oa ywub lrvtlqpyku shz oemjvimopy cps cufmrf op koyh suau, af zq lbam fnjtl fkge gksg rrseye vg ybfric bhrot Kubege jvd Ugrhcjefy. Yzuqkpuy, enqknl, wvrn vcytnzn bhnz Igparasnvtf rqfa asggktifngv mdohrm vog hg ubwntkm noe rkybp aaj czaaykwhp cnabms; ntf swyoejrvgye cdf axckaqeaig zuph fnnen gncl gwnxowl aek ogla dvyywsrj vg mqfska, ehvrg wpelf gam shlhwlwbyk cpaa zq jcchg zqmmfknnyo bl gkwlvyjahc tuk owrzy vg qdipn cpel gtw uychycwmrj. Dmn shrt j toam vjuen bl jjufku shz ufaaxagoqfm, lueydqnt opnuninhug tuk usga Oopnkt rbkfwas n jnaitt vg ladhin bhrs wfxar nhbwlhzg Vyopbzram, vz kk ndevx aqguz, kl co tukrz dhza, li pheuf wfs ywub Coikavmrtv, shz tb vawvvjg fys Ghgals sut lbaie ldbuek uwwqrvzh. — Aupn jsm xert cpe cgvayjt faoneegpuy kf gnnae Pungheef; gwl shij am joj zqm nrigkmetl cqqcu iqfmprnowa tuko li wlgka bhrot xinmrx Bgsgkok ib Gbbnznzkpl. Nde uobboee qx nde cxnaeaz Mahc os Mamag Htanwia ob i hvyvglu os xnxenzgv cjjhxrms ntf mmqrcgcqoay, cdf daiowo ia jkjyyt bhsmcg zjw yotnhuqsusgfn kf nt jjsbrwly Pyegwvy bbgj ndefk Bbagku. Li lrbbn bhvy, nwn Bapzb je fadecptrj cw a pgpvcz wbxul.

Hr nck lafhynl hvy Ckmang zx Tajy, vzy iofz fpoykugga aaj wmcryuslu fbx cpe caddcy gbum.

Pe ugu xinbvjmmn uou Yireetxzs gu rsmo Lncb wf vsowxeagk jvd cxgkment ovxoezcfwa, uarnas fauhyjdrj rv tukkj ileegcqoa zkdf dif Gbaeaz uziqlq hn wbggkfyz; aaj fpea yq kooprtmmd, uk jsm qtgkaty akidyytrj cw agzgfx po gnnu.

Hr nck lafhynl tb vckm ktuka Tajy hgl phr glkozsqvupibt xn lnxiw xesgxrktf uh hykpyk, dvlryu lbksr vnwpyk ygohd ekuqndakkb phr xrohg uh Jylrrynvtnzkgh en gnn Tetoudupuek, j zitnv ahasgovibyk vg ndez gwl fbxoaxwbyk cw tlxcfno oarh.

Pe ugu uuhlrj cwgrzjwl hetobtagoxw vkdvkb it crcuyo uaabcay, apuiifbxcibyk, cfx zifzjvt sxqe nde qkywsvzqjs kf gnnqr Caddcy Rrixzdf, lqj nde fuum phxrgma os ljbitakfa phrs rvtb iqejhintlm wvzj zco mrgbcrry.

Jw bws qobaoybgv Lapekbmnggvapa Hbabms ekrwupeqrh, noe urhioiam fqtu scffu fvxvvefy jam enigbqoay qf nde eopptf uh lba pruyte.

Uk jsm nesabmd sut s fknt zrue, nlvwl oupn mqsfunmneoay, cw cnauw iphrxb bo ok gdyytrj, fpeekdq nde Ykpqsygvapa Pbcnzs, vtesjwbyk xn Aatkzchagoxv, hnbg jypuetnl tb zjw Jaocrn it ygtyy boe zqmie kzwlyifk; cpe Fzcly nezgrviam kf nde zkjv tvsg wrlofkm bo nrn lba dntpmrf uh ahrafoxv feuo ocphbac, inq iqfpqlfoxvs jovzcj.

Hr nja eajgspkuekm bo cxgnyjt gnn xocansneoa uo bhryg Knwtry; owr gncl jqrcubm ooyvjoytvtp bhr Rcom boe Tjbuegnatwtvuw wf Sutwccnrxb; zesauahc tb vjas bzjwlo tb kwkohxcyy phroa uitxclcknf nrbhrx, cfx navyrvg gng uijdvzrwnf uh fys Acvawpeoclcknf uo Taaju.

Zy daf ukateaelyz tuk Jlmvtkknnagoxv os Pwknecr hh zesauahc hvy Jasrtv li Hajy owr ryvsvhifnrvg Wafaweaee Ywwrxu.

Zy daf sjle Wafyyo drvnvdrtv gh dif Crtl nrqfy boe zqm trtwjy kf gnnqr blhawas, ntm bhr gogojt ntm xalsgfn kf gnnqr fgnsleef.

luig vy cxwpf{Jnxwobuqg_O_Cogiqi!}

Hr nck ynepznl a zanlcpuqk xn Nrc Qxzecry, jvd fkpl betuka awnxok ib Oslrkeey vg bwrnyb wue vggjhe ntm mag uwl ndevx bcbfzcfwa.

Hr nja krvv sgknt ab, qn goowm kf ckjke, Fzcfxent Gauiry yandohz cpe Pupkyjt bl xcr ykiamhagaams.

Uk jsm wfsklbeq zq jyjdrx cpe Zonanwrl owleckpvyjt bl jvd farwleoe zx bhr Iknch Pbcnz.

Hr nck wkmoowmd jovz iphrxb bo fadbyyt hy cw a watamzipzrwn sutwccn gu xcr pupknethzrwn, ntf mhwcxtxelrjiwx xy baa tajy; iapent nra Afygfn po gnnqr Nivk ib pekcmnqkf Dycifrjbibt:

Hgl munxcmrvti dungr hxliry qx unmrj czobvu sgknt ab:

Noe vtgnacgowo tuko, ts w mbit Brvgn xlkm cawqsusgfn boe gwg Mhxfwlo wuolp tuka kbkuyj lwmzov gh phr Owpaoovshps bl cpefk Ulupef:

Lxz chzvahc osl xcr Gxcvy sign jtl cgtlm kf gnn eoerf:

Xin izvxaiam Vsras bt da wvzjgop ohx Lwnfkpl:

Zkr qkyziiopy oo ia sjvy pguwm, kf gnn jeakhan kf Gxril oe Lmlu:

Fbx czaayrglpiam da breqfx Oeny cw br ztayz fbx yzegkpvyz oslnvcry:

Hgl wbbrrahvti lba fekn Ayfzge ib Eamuqsu Rcom en n tnqguhqmlent Vawvvtew, yotnhuqsuopy ndeekrv aa Gttcprnxh ooiktfgang, gwl earcjaent oca Bbapvuniry bw af zq jyjdrx rb ag upuy wn rdjupyk cfx big owateaowhp fbx rvteufmwent zqm snsg svooyacm rhrg ahpo gnnae Pungheef

Lxz tnqkfa wwne xcr Pncjnarf, gkwlvyjahc ohx vwsg bcdowbyk Uiwf gpv uhtrxrvg sapvuieazjtll zjw Zkrzy xn ohx Igparasnvtf:

Lqj mqsckwliam qml kwa Rnoifrclonef, gwl drinslent zqmmfknnyo iabnatrj yand pbcnz tb rgycolnzn noe au ah wly ijaef cjsnoorbnz.

Hr nck uxdvijbeq Mqnynnzkwb hrxg, ts zeprjziam wk iqt bl qqs Cxqlyytvuw inq ccycjg Jga ignopkn qs.

Uk qis crwfxarrj xcr fkck, lwvnmnl ohx eguotf, hdzng uwj nkway, jvd qkullkyrj cpe yoxwm kf baa xebvnw.

Ba if gc bhvy vaga tegwapbxvahc lnxpm Aeskwm kf suamitt Owlyeagaqef zq uiipykjb tuk yglgs bl mmagn, fwmklnzrwn, ntf lsnaath, ilekcvs xetaw eign ealyuzycinpku gz Yrhkuby & Cktxczy fijzcrra hunayrnteq op lba mbyc jaehcjiqs nmna, aaj vgnwlye dvwbxvzs phr Nnid bl c ucriyoimd agvaij.

Hr nja cbtullwiakm wue lgdfkw Pocqzrtu lugea Ijxtvbg gh phr nroh Fkck nk brga Irzy cyuenfz cpevx Egojtee, cw briqey phr kgmchzkgharf uo bhrot xleeajb inq Htwndrrt, xz tb lcdf phrsbmliku ts phroa Paaju.

Zy daf kgkigkf viiefzrk iaywjlacgoxvs nsqfaot hy, jvd ugu whzenbxcrrj vg vniam xv tuk kfbwbvzjvtf uh gon feuwbirxu, lba mrxlqlryu Ahzint Bivnmgk qdofk tvojt tmfa os cjzfnxg, am wn htmqsgopyoesukm lefztmwpibt xn ayr cyyo, srdna aaj eghzigoxvs.

Vt gnyny fzjoe bl vzyoe Bvyzefykgho Wr njde Ckvaneoakm noe Xgvlasf ow bhr sqkn duzhum trxok: Iqr ekymagkf Hypigoxvs ugxw vaea gwawrxgv ijll hh zeckclyz iapdzy. N Vtahye, jnxae pncjuytrx ra tuau eunkrj kg eiktq uyt jnrkh zga vybiak j Byegpl, co ualrb tb hg lba rhrnz os g hjya pruyte.

Aut zure Jk kmea ccfnent ow itgkplcknf zx wue Htanesu hamtuxgf. Qa hnbn eaetgv ndez lawm goow nk tvsn wf nzvwgltf hh bhrot dycifrjbuek vg yttrtm in htyslnaazjjlr pwjcodvicqoa uxwl qs. Jk qivr xgecjdrj cpez uh lba cvxlcmfzcfwas bl xcr rskylwtvuw inq yglnhezkwb hrxg. Oy daik jxprgnwx po gnnqr agvapa jhycqcr gpv gwgagwqmvza, shz wr njde pupboneq zqmm oe vzy piry xn ohx eggioa qrvdekf li zifgeww gngky qshxyitvupk, qdipn fwuyj kfyriggkty vtvwlnucz xcr pupfyytvuwa aaj eglnefvxvdrtew. Ndel zxw hnbg tyan qkjn tb zjw pkipk xn jhyvawa aaj xn cbtushcuvtrby. Jk ommp, tukamfbxg, swmuvkbke vt vzy jepkbaige, yzcyh qkwwuaigk iqr Fkyirnzkgh, wnq nxtd gnge, uo wr nxtd gng jyot bl vinxopv, Yjezona ia Ccj, cj Prglm Feogfxo.

Wr, zqmrrlqjy, phr Xnxrrygfnwtvbna os zjw ojigkm Atnzgk ib Azkaqcn, op Yyjeegu Koamtwmo, Afynubykf, sjlenrrvg gu vzy Oucxnue Wafyy kf gnn eoerf xin tuk amcgovmxa os udz iazgfneoay, mw, ia zjw Hwmr, gwl bl Gwlbkrvzh wf gng yikd Ckxxlr uh lbasr Ixtoaogk, mklrswty caddcoh ntm leprcjy, Phnz cpefk wfcpeq Ixtoaogk une, ntm wf Eoizn kutnc bo ok Hjya aaj Rvdrvgfxang Ycitry, vzup tukh irr Gdkihvrj ozoz gnd Uhlrmrinpk vg nde Oxrbifn Ejisn, ntm bhnz cdf loyocqcnr eghjepzrwn okvoyan gnnu aaj vzy Otnzn wf Txgsn Xrvzjqn, vy cfx kutnc bo ok vgnwlye mqsfunnyz; aaj cpag gu Xlae ntm Qnqkrwhzeaz Bbagku, lbay ugem fhrn Hisee zx teie Ysl, yoaiucdr Vgswa, cbtczapz Cdfeaaina, efzctfesu Ixumrxew, ujd gu mw ayr qlbar Nica aaj Vzcjgf cqqcu Opvyleajnvt Fzclyo mne xn rvmjl xk. — Aaj owr gng kolpbxc wf gnkk Xacygaitvup, ocph n lrzm eknaujcr uw bhr vtgnacgoxv os Jkncje Cxxdiqkpuy, se zaccayra hfadtk cw enij gndee udz Lvbgk, iqr Suabuaku, shz ohx bicekf Zijoe.
```

使用https://www.guballa.de/vigenere-solver求解，可以发现`flag is afctf{Whooooooo_U_Gotcha!}`。

```
When in the Course of human events it becomes necessary for one people to dissolve the political bands which have connected them with another and to assume among the powers of the earth, the separate and equal station to which the Laws of Nature and of Nature's God entitle them, a decent respect to the opinions of mankind requires that they should declare the causes which impel them to the separation.

We hold these truths to be self-evident, that all men are created equal, that they are endowed by their Creator with certain unalienable Rights, that among these are Life, Liberty and the pursuit of Happiness. — That to secure these rights, Governments are instituted among Men, deriving their just powers from the consent of the governed, — That whenever any Form of Government becomes destructive of these ends, it is the Right of the People to alter or to abolish it, and to institute new Government, laying its foundation on such principles and organizing its powers in such form, as to them shall seem most likely to effect their Safety and Happiness. Prudence, indeed, will dictate that Governments long established should not be changed for light and transient causes; and accordingly all experience hath shewn that mankind are more disposed to suffer, while evils are sufferable than to right themselves by abolishing the forms to which they are accustomed. But when a long train of abuses and usurpations, pursuing invariably the same Object evinces a design to reduce them under absolute Despotism, it is their right, it is their duty, to throw off such Government, and to provide new Guards for their future security. — Such has been the patient sufferance of these Colonies; and such is now the necessity which constrains them to alter their former Systems of Government. The history of the present King of Great Britain is a history of repeated injuries and usurpations, all having in direct object the establishment of an absolute Tyranny over these States. To prove this, let Facts be submitted to a candid world.

He has refused his Assent to Laws, the most wholesome and necessary for the public good.

He has forbidden his Governors to pass Laws of immediate and pressing importance, unless suspended in their operation till his Assent should be obtained; and when so suspended, he has utterly neglected to attend to them.

He has refused to pass other Laws for the accommodation of large districts of people, unless those people would relinquish the right of Representation in the Legislature, a right inestimable to them and formidable to tyrants only.

He has called together legislative bodies at places unusual, uncomfortable, and distant from the depository of their Public Records, for the sole purpose of fatiguing them into compliance with his measures.

He has dissolved Representative Houses repeatedly, for opposing with manly firmness his invasions on the rights of the people.

He has refused for a long time, after such dissolutions, to cause others to be elected, whereby the Legislative Powers, incapable of Annihilation, have returned to the People at large for their exercise; the State remaining in the mean time exposed to all the dangers of invasion from without, and convulsions within.

He has endeavoured to prevent the population of these States; for that purpose obstructing the Laws for Naturalization of Foreigners; refusing to pass others to encourage their migrations hither, and raising the conditions of new Appropriations of Lands.

He has obstructed the Administration of Justice by refusing his Assent to Laws for establishing Judiciary Powers.

He has made Judges dependent on his Will alone for the tenure of their offices, and the amount and payment of their salaries.

flag is afctf{Whooooooo_U_Gotcha!}

He has erected a multitude of New Offices, and sent hither swarms of Officers to harass our people and eat out their substance.

He has kept among us, in times of peace, Standing Armies without the Consent of our legislatures.

He has affected to render the Military independent of and superior to the Civil Power.

He has combined with others to subject us to a jurisdiction foreign to our constitution, and unacknowledged by our laws; giving his Assent to their Acts of pretended Legislation:

For quartering large bodies of armed troops among us:

For protecting them, by a mock Trial from punishment for any Murders which they should commit on the Inhabitants of these States:

For cutting off our Trade with all parts of the world:

For imposing Taxes on us without our Consent:

For depriving us in many cases, of the benefit of Trial by Jury:

For transporting us beyond Seas to be tried for pretended offences:

For abolishing the free System of English Laws in a neighbouring Province, establishing therein an Arbitrary government, and enlarging its Boundaries so as to render it at once an example and fit instrument for introducing the same absolute rule into these Colonies

For taking away our Charters, abolishing our most valuable Laws and altering fundamentally the Forms of our Governments:

For suspending our own Legislatures, and declaring themselves invested with power to legislate for us in all cases whatsoever.

He has abdicated Government here, by declaring us out of his Protection and waging War against us.

He has plundered our seas, ravaged our coasts, burnt our towns, and destroyed the lives of our people.

He is at this time transporting large Armies of foreign Mercenaries to compleat the works of death, desolation, and tyranny, already begun with circumstances of Cruelty & Perfidy scarcely paralleled in the most barbarous ages, and totally unworthy the Head of a civilized nation.

He has constrained our fellow Citizens taken Captive on the high Seas to bear Arms against their Country, to become the executioners of their friends and Brethren, or to fall themselves by their Hands.

He has excited domestic insurrections amongst us, and has endeavoured to bring on the inhabitants of our frontiers, the merciless Indian Savages whose known rule of warfare, is an undistinguished destruction of all ages, sexes and conditions.

In every stage of these Oppressions We have Petitioned for Redress in the most humble terms: Our repeated Petitions have been answered only by repeated injury. A Prince, whose character is thus marked by every act which may define a Tyrant, is unfit to be the ruler of a free people.

Nor have We been wanting in attentions to our British brethren. We have warned them from time to time of attempts by their legislature to extend an unwarrantable jurisdiction over us. We have reminded them of the circumstances of our emigration and settlement here. We have appealed to their native justice and magnanimity, and we have conjured them by the ties of our common kindred to disavow these usurpations, which would inevitably interrupt our connections and correspondence. They too have been deaf to the voice of justice and of consanguinity. We must, therefore, acquiesce in the necessity, which denounces our Separation, and hold them, as we hold the rest of mankind, Enemies in War, in Peace Friends.

We, therefore, the Representatives of the united States of America, in General Congress, Assembled, appealing to the Supreme Judge of the world for the rectitude of our intentions, do, in the Name, and by Authority of the good People of these Colonies, solemnly publish and declare, That these united Colonies are, and of Right ought to be Free and Independent States, that they are Absolved from all Allegiance to the British Crown, and that all political connection between them and the State of Great Britain, is and ought to be totally dissolved; and that as Free and Independent States, they have full Power to levy War, conclude Peace, contract Alliances, establish Commerce, and to do all other Acts and Things which Independent States may of right do. — And for the support of this Declaration, with a firm reliance on the protection of Divine Providence, we mutually pledge to each other our Lives, our Fortunes, and our sacred Honor.
```

------

### [[AFCTF2018]可怜的RSA](https://buuoj.cn/challenges#[AFCTF2018]%E5%8F%AF%E6%80%9C%E7%9A%84RSA)

附件解压缩后得到`flag.enc`和`public.key`，编写`Python`代码进行求解，首先用`Crypto.PublicKey`的`RSA`模块来获取公钥对`<n, e>`，然后调用`requests`库在线请求 http://factordb.com 分解模数`n`，得到`p`和`q`，算出 `φ(n) = (p-1)(q-1)`，进而得到私钥的解密质数`d`，至此私钥已经拿到。用`Crypto.PublicKey`的`PKCS1_OAEP`模块生成私钥对`base64`解码后的`flag.enc`进行`RSA`解密，可以得到明文`afctf{R54_|5_$0_B0rin9}`，提交`flag{R54_|5_$0_B0rin9}`即可。

```python
import requests
from base64 import b64decode
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Util.number import inverse

def factorize(n):
    l = []
    url="http://factordb.com/api?query="+str(n)
    r = requests.get(url)
    data = r.json()
    for factor in data['factors']:
        l.append(int(factor[0]))
    return l

with open('public.key', 'rb') as f:
    public_key = RSA.importKey(f.read())

n = public_key.n
e = public_key.e
q, p = factorize(n)
d = inverse(e, (p-1)*(q-1))
key_info = RSA.construct((n, e, d, p, q))
key = RSA.importKey(key_info.exportKey())
private_key = PKCS1_OAEP.new(key)

with open('flag.enc', 'rb') as f:
    cipher_text = b64decode(f.read())
    flag = private_key.decrypt(cipher_text).decode()

print(flag) # afctf{R54_|5_$0_B0rin9}
```

------

### ❤[[BJDCTF2020]easyrsa](https://buuoj.cn/challenges#[BJDCTF2020]easyrsa)

附件解压缩后得到`rsa_task.py`，源码如下：

```python
from Crypto.Util.number import getPrime,bytes_to_long
from sympy import Derivative
from fractions import Fraction
from secret import flag

p=getPrime(1024)
q=getPrime(1024)
e=65537
n=p*q
z=Fraction(1,Derivative(arctan(p),p))-Fraction(1,Derivative(arth(q),q))
m=bytes_to_long(flag)
c=pow(m,e,n)
print(c,z,n)
'''
output:
7922547866857761459807491502654216283012776177789511549350672958101810281348402284098310147796549430689253803510994877420135537268549410652654479620858691324110367182025648788407041599943091386227543182157746202947099572389676084392706406084307657000104665696654409155006313203957292885743791715198781974205578654792123191584957665293208390453748369182333152809882312453359706147808198922916762773721726681588977103877454119043744889164529383188077499194932909643918696646876907327364751380953182517883134591810800848971719184808713694342985458103006676013451912221080252735948993692674899399826084848622145815461035
32115748677623209667471622872185275070257924766015020072805267359839059393284316595882933372289732127274076434587519333300142473010344694803885168557548801202495933226215437763329280242113556524498457559562872900811602056944423967403777623306961880757613246328729616643032628964072931272085866928045973799374711846825157781056965164178505232524245809179235607571567174228822561697888645968559343608375331988097157145264357626738141646556353500994924115875748198318036296898604097000938272195903056733565880150540275369239637793975923329598716003350308259321436752579291000355560431542229699759955141152914708362494482
15310745161336895413406690009324766200789179248896951942047235448901612351128459309145825547569298479821101249094161867207686537607047447968708758990950136380924747359052570549594098569970632854351825950729752563502284849263730127586382522703959893392329333760927637353052250274195821469023401443841395096410231843592101426591882573405934188675124326997277775238287928403743324297705151732524641213516306585297722190780088180705070359469719869343939106529204798285957516860774384001892777525916167743272419958572055332232056095979448155082465977781482598371994798871917514767508394730447974770329967681767625495394441
'''
```

我们分析关键代码行后，得到关系式 ${\large z=p^{2}+q^{2}}$。

> ### z=Fraction(1,Derivative(arctan(p),p))-Fraction(1,Derivative(arth(q),q))
>
> - ##### Fraction(a,b) 用于形成分式a/b
>
> - ##### Derivative(F, x) 用于在F式中对x求导
>
> ${\LARGE z=\frac{1}{[arctan(p)]'}-\frac{1}{[arth(q)]'}} $
>
> ${\LARGE z=\frac{1}{\huge{\frac{1}{1+p^{2}}}}-\frac{1}{\huge{\frac{1}{1-q^{2}}}}} $
>
> ${\Large z=1+p^{2}-(1-q^{2})}$
>
> ${\Large z=p^{2}+q^{2}}$

根据 ${\large z=p^{2}+q^{2}}$ 和 ${\large n=p*q}$ 进行数学推导：

> ${\Large (p+q)^{2}=p^{2}+2pq+q^{2}=z+2n}$
>
> ${\Large (p-q)^{2}=p^{2}-2pq+q^{2}=z-2n}$

`z`和`n`都是已知数，这里可以用`z3`约束求解器解方程组，也可以开平方化简后做差求解出`p`和`q`的值。

> ${\Large p+q=\sqrt{z+2n}}$
>
> ${\Large p-q=\sqrt{z-2n}}$

编写`Python`代码求解得到`BJD{Advanced_mathematics_is_too_hard!!!}`，提交`flag{Advanced_mathematics_is_too_hard!!!}`。

```python
from libnum import *
from math import isqrt

c = 7922547866857761459807491502654216283012776177789511549350672958101810281348402284098310147796549430689253803510994877420135537268549410652654479620858691324110367182025648788407041599943091386227543182157746202947099572389676084392706406084307657000104665696654409155006313203957292885743791715198781974205578654792123191584957665293208390453748369182333152809882312453359706147808198922916762773721726681588977103877454119043744889164529383188077499194932909643918696646876907327364751380953182517883134591810800848971719184808713694342985458103006676013451912221080252735948993692674899399826084848622145815461035
z = 32115748677623209667471622872185275070257924766015020072805267359839059393284316595882933372289732127274076434587519333300142473010344694803885168557548801202495933226215437763329280242113556524498457559562872900811602056944423967403777623306961880757613246328729616643032628964072931272085866928045973799374711846825157781056965164178505232524245809179235607571567174228822561697888645968559343608375331988097157145264357626738141646556353500994924115875748198318036296898604097000938272195903056733565880150540275369239637793975923329598716003350308259321436752579291000355560431542229699759955141152914708362494482
n = 15310745161336895413406690009324766200789179248896951942047235448901612351128459309145825547569298479821101249094161867207686537607047447968708758990950136380924747359052570549594098569970632854351825950729752563502284849263730127586382522703959893392329333760927637353052250274195821469023401443841395096410231843592101426591882573405934188675124326997277775238287928403743324297705151732524641213516306585297722190780088180705070359469719869343939106529204798285957516860774384001892777525916167743272419958572055332232056095979448155082465977781482598371994798871917514767508394730447974770329967681767625495394441
e = 65537
p_add_q = isqrt(z+2*n)
p_subtr_q = isqrt(z-2*n)
p = (p_add_q+p_subtr_q)//2
q = p_add_q-p
# print(p, q)
# p = 144564833334456076455156647979862690498796694770100520405218930055633597500009574663803955456004439398699669751249623406199542605271188909145969364476344963078599240058180033000440459281558347909876143313940657252737586803051935392596519226965519859474501391969755712097119163926672753588797180811711004203301 
# q = 105909195259921349656664570904199242969110902804477734660927330311460997899731622163728968380757294196277263615386525795293086103142131020215128282050307177125962302515483190468569376643751587606016315185736245896434947691528567696271911398179288329609207435393579332931583829355558784305002360873458907029141
d = invmod(e, (p-1)*(q-1))
m = pow(c, d, n)
flag = n2s(m).decode()
print(flag) # BJD{Advanced_mathematics_is_too_hard!!!}
```

------

### ❤[[RoarCTF2019]babyRSA](https://buuoj.cn/challenges#[RoarCTF2019]babyRSA)

附件解压缩后内容如下：

```python
import sympy
import random

def myGetPrime():
    A= getPrime(513)
    print(A)
    B=A-random.randint(1e3,1e5)
    print(B)
    return sympy.nextPrime((B!)%A)
p=myGetPrime()
#A1=21856963452461630437348278434191434000066076750419027493852463513469865262064340836613831066602300959772632397773487317560339056658299954464169264467234407
#B1=21856963452461630437348278434191434000066076750419027493852463513469865262064340836613831066602300959772632397773487317560339056658299954464169264467140596
q=myGetPrime()
#A2=16466113115839228119767887899308820025749260933863446888224167169857612178664139545726340867406790754560227516013796269941438076818194617030304851858418927
#B2=16466113115839228119767887899308820025749260933863446888224167169857612178664139545726340867406790754560227516013796269941438076818194617030304851858351026
r=myGetPrime()
n=p*q*r
#n=85492663786275292159831603391083876175149354309327673008716627650718160585639723100793347534649628330416631255660901307533909900431413447524262332232659153047067908693481947121069070451562822417357656432171870951184673132554213690123308042697361969986360375060954702920656364144154145812838558365334172935931441424096270206140691814662318562696925767991937369782627908408239087358033165410020690152067715711112732252038588432896758405898709010342467882264362733
c=pow(flag,e,n)
#e=0x1001
#c=75700883021669577739329316795450706204502635802310731477156998834710820770245219468703245302009998932067080383977560299708060476222089630209972629755965140317526034680452483360917378812244365884527186056341888615564335560765053550155758362271622330017433403027261127561225585912484777829588501213961110690451987625502701331485141639684356427316905122995759825241133872734362716041819819948645662803292418802204430874521342108413623635150475963121220095236776428
#so,what is the flag?
```

通过自定义函数`myGetPrime()`得到三个大质数`p`，`q`和`r`，将它们的乘积赋值给`n`，然后再对`flag`进行加密。`myGetPrime()`函数的关键在于`sympy.nextPrime((B!)%A)`，`B`的阶乘计算量太大啦。根据威尔逊定理有`(p-1)!+1 ≡ 0(mod p)`。因为`A`和`B`相近且`A > B`，所以`A!`是包含`B!`的。

> (B - 1) ! + 1 ≡ 0 ( mod B)
>
> (A - 1) ! +1 ≡ 0 ( mod A)   →   B! × (B+1) × (B+2) × ... × (A-1) ≡ -1 ( mod A)
>
> 因此只要求出 (B+1) × (B+2) × ... × (A-1) 在模数A下的逆即可求出B!
>
> 记 C = (B+1) × (B+2) × ... × (A-1) , 有 B! × C ≡ -1 ( mod A)
>
> B! ≡ -1×C (mod A) 知道 B! 后 B!%A的值也能计算出来

```python
import sympy
from Crypto.Util.number import * 

A1 = 21856963452461630437348278434191434000066076750419027493852463513469865262064340836613831066602300959772632397773487317560339056658299954464169264467234407
B1 = 21856963452461630437348278434191434000066076750419027493852463513469865262064340836613831066602300959772632397773487317560339056658299954464169264467140596
A2 = 16466113115839228119767887899308820025749260933863446888224167169857612178664139545726340867406790754560227516013796269941438076818194617030304851858418927
B2 = 16466113115839228119767887899308820025749260933863446888224167169857612178664139545726340867406790754560227516013796269941438076818194617030304851858351026
n = 85492663786275292159831603391083876175149354309327673008716627650718160585639723100793347534649628330416631255660901307533909900431413447524262332232659153047067908693481947121069070451562822417357656432171870951184673132554213690123308042697361969986360375060954702920656364144154145812838558365334172935931441424096270206140691814662318562696925767991937369782627908408239087358033165410020690152067715711112732252038588432896758405898709010342467882264362733
e = 0x1001
c = 75700883021669577739329316795450706204502635802310731477156998834710820770245219468703245302009998932067080383977560299708060476222089630209972629755965140317526034680452483360917378812244365884527186056341888615564335560765053550155758362271622330017433403027261127561225585912484777829588501213961110690451987625502701331485141639684356427316905122995759825241133872734362716041819819948645662803292418802204430874521342108413623635150475963121220095236776428

def myGetPrime(A, B):
    C = 1
    for i in range(B+1, A):
        C = (C*inverse(i, A))%A
    C = C*(A-1)%A
    return sympy.nextprime(C)

p = myGetPrime(A1, B1)
q = myGetPrime(A2, B2)
r = n//p//q
d = inverse(e, (p-1)*(q-1)*(r-1))
m = pow(c, d, n)
flag = long_to_bytes(m).decode()
print(flag) # RoarCTF{wm-CongrAtu1ation4-1t4-ju4t-A-bAby-R4A}
flag = flag.replace('RoarCTF', 'flag')
print(flag) # flag{wm-CongrAtu1ation4-1t4-ju4t-A-bAby-R4A}
```

------

### ❤[[RoarCTF2019]RSA](https://buuoj.cn/challenges#[RoarCTF2019]RSA)

附件解压缩后内容如下：

```
A=(((y%x)**5)%(x%y))**2019+y**316+(y+1)/x
p=next_prime(z*x*y)
q=next_prime(z)
A =  2683349182678714524247469512793476009861014781004924905484127480308161377768192868061561886577048646432382128960881487463427414176114486885830693959404989743229103516924432512724195654425703453612710310587164417035878308390676612592848750287387318129424195208623440294647817367740878211949147526287091298307480502897462279102572556822231669438279317474828479089719046386411971105448723910594710418093977044179949800373224354729179833393219827789389078869290217569511230868967647963089430594258815146362187250855166897553056073744582946148472068334167445499314471518357535261186318756327890016183228412253724
n =  117930806043507374325982291823027285148807239117987369609583515353889814856088099671454394340816761242974462268435911765045576377767711593100416932019831889059333166946263184861287975722954992219766493089630810876984781113645362450398009234556085330943125568377741065242183073882558834603430862598066786475299918395341014877416901185392905676043795425126968745185649565106322336954427505104906770493155723995382318346714944184577894150229037758434597242564815299174950147754426950251419204917376517360505024549691723683358170823416757973059354784142601436519500811159036795034676360028928301979780528294114933347127
c =  41971850275428383625653350824107291609587853887037624239544762751558838294718672159979929266922528917912189124713273673948051464226519605803745171340724343705832198554680196798623263806617998072496026019940476324971696928551159371970207365741517064295956376809297272541800647747885170905737868568000101029143923792003486793278197051326716680212726111099439262589341050943913401067673851885114314709706016622157285023272496793595281054074260451116213815934843317894898883215362289599366101018081513215120728297131352439066930452281829446586562062242527329672575620261776042653626411730955819001674118193293313612128
```

调用`requests`库在线请求 [http://factordb.com](http://factordb.com/) 分解模数`n`，得到`p`和`q`。由于无法得知`e`的值，只能挨个`try`进行爆破啦，编写`Python`代码运行可得`e = 65537`, `flag: RoarCTF{wm-l1l1ll1l1l1l111ll}`。提交`flag{wm-l1l1ll1l1l1l111ll}`即可。

```python
import requests
from gmpy2 import next_prime
from Crypto.Util.number import inverse, long_to_bytes

def factorize(n):
    l = []
    url="http://factordb.com/api?query="+str(n)
    r = requests.get(url)
    data = r.json()
    for factor in data['factors']:
        l.append(int(factor[0]))
    return l

n = 117930806043507374325982291823027285148807239117987369609583515353889814856088099671454394340816761242974462268435911765045576377767711593100416932019831889059333166946263184861287975722954992219766493089630810876984781113645362450398009234556085330943125568377741065242183073882558834603430862598066786475299918395341014877416901185392905676043795425126968745185649565106322336954427505104906770493155723995382318346714944184577894150229037758434597242564815299174950147754426950251419204917376517360505024549691723683358170823416757973059354784142601436519500811159036795034676360028928301979780528294114933347127
c = 41971850275428383625653350824107291609587853887037624239544762751558838294718672159979929266922528917912189124713273673948051464226519605803745171340724343705832198554680196798623263806617998072496026019940476324971696928551159371970207365741517064295956376809297272541800647747885170905737868568000101029143923792003486793278197051326716680212726111099439262589341050943913401067673851885114314709706016622157285023272496793595281054074260451116213815934843317894898883215362289599366101018081513215120728297131352439066930452281829446586562062242527329672575620261776042653626411730955819001674118193293313612128
p, q = factorize(n)
# print(p, q)
# p = 842868045681390934539739959201847552284980179958879667933078453950968566151662147267006293571765463137270594151138695778986165111380428806545593588078365331313084230014618714412959584843421586674162688321942889369912392031882620994944241987153078156389470370195514285850736541078623854327959382156753458569
# q = 139916095583110895133596833227506693679306709873174024876891023355860781981175916446323044732913066880786918629089023499311703408489151181886568535621008644997971982182426706592551291084007983387911006261442519635405457077292515085160744169867410973960652081452455371451222265819051559818441257438021073941183
phi_n = (p-1)*(q-1)
e = 0
while True:
    e = next_prime(e)
    try:
        d = inverse(e, phi_n)
        m = pow(c, d, n)
    except:
        pass
    else:
        s = str(long_to_bytes(m))
        if 'CTF' in s or 'flag' in s:
            flag = s.decode()
            break

print("e = {}, flag: {}".format(e,flag))
# e = 65537, flag: RoarCTF{wm-l1l1ll1l1l1l111ll}
```

------

### [ACTF新生赛2020]crypto-classic0

附件解压缩后得到`howtoencrypt.zip`，`cipher`和`hint.txt`，其中`hint.txt`内容如下：

> 哼，压缩包的密码？这是小Z童鞋的生日吧==

根据`hint.txt`得知密码是小Z同学的生日，小Z是谁并不重要，重点是密码是`6`或`8`位纯数字，爆破压缩包得到密码是`19990306`。

`cipher`内容如下：

```
Ygvd<0x7f>mq[lYate[elghqvakl}
```

`classic0.c`源码如下：

```c
#include<stdio.h>

char flag[25] = ***

int main()
{
    int i;
    for(i=0;i<25;i++)
    {
        flag[i] -= 3;
        flag[i] ^= 0x7;
        printf("%c",flag[i]);
    }
    return 0; 
}
```

编写`Python`代码求解得到`actf{my_naive_encrytion}`，提交`flag{my_naive_encrytion}`：

```python
cipher = 'Ygvd\x7fmq[lYate[elghqvakl}'
flag=''
for c in cipher:
    t = ord(c)^0x7
    t += 3
    flag += chr(t)

print(flag) # actf{my_naive_encrytion}
```

------

### [[网鼎杯 2020 青龙组]you_raise_me_up](https://buuoj.cn/challenges#[%E7%BD%91%E9%BC%8E%E6%9D%AF%202020%20%E9%9D%92%E9%BE%99%E7%BB%84]you_raise_me_up)

附件解压缩后得到`you_raise_me_up.py`，源码如下：

```python
#!/usr/bin/env python
# -*- coding: utf-8 -*-
from Crypto.Util.number import *
import random

n = 2 ** 512
m = random.randint(2, n-1) | 1
c = pow(m, bytes_to_long(flag), n)
print 'm = ' + str(m)
print 'c = ' + str(c)

# m = 391190709124527428959489662565274039318305952172936859403855079581402770986890308469084735451207885386318986881041563704825943945069343345307381099559075
# c = 6665851394203214245856789450723658632520816791621796775909766895233000234023642878786025644953797995373211308485605397024123180085924117610802485972584499
```

已知`c`，`m`，`n`，求离散对数。

> $\Large{c = m^{bytes\_to\_long(flag)}modn}$
>
> $\Large{bytes\_to\_long(flag) =\log_{(m\ mod\ n)}{(c\ mod \ n)}}$

用`sage`库的`discrete_log()`函数求解就完事啦。编写`Python`代码求解得到`flag{5f95ca93-1594-762d-ed0b-a9139692cb4a}`。

```python
from sage.all import *
from Crypto.Util.number import long_to_bytes

n = 2 ** 512
m = 391190709124527428959489662565274039318305952172936859403855079581402770986890308469084735451207885386318986881041563704825943945069343345307381099559075
c = 6665851394203214245856789450723658632520816791621796775909766895233000234023642878786025644953797995373211308485605397024123180085924117610802485972584499
flag = long_to_bytes(discrete_log(c,mod(m,n))).decode()
print(flag) # flag{5f95ca93-1594-762d-ed0b-a9139692cb4a}
```

------

### [[WUSTCTF2020]大数计算](https://buuoj.cn/challenges#[WUSTCTF2020]%E5%A4%A7%E6%95%B0%E8%AE%A1%E7%AE%97)

附件解压缩后得到`题目描述.txt`和`图片附件.zip`，`题目描述.txt`如下：

```
flag等于 wctf2020{Part1-Part2-Part3-Part4} 每一Part都为数的十六进制形式（不需要0x)，并用 '-' 连接
Part1 = 2020*2019*2018* ... *3*2*1 的前8位
Part2 = 520^1314 + 2333^666 的前8位
Part3 = 宇宙终极问题的答案 x,y,z绝对值和的前8位
Part4 = 见图片附件，计算结果乘上1314
```

`图片附件.zip`解压缩后得到`Part4.jpg`，看到公式$\large{\int_{0}^{22}2x\ dx+36}$。先来求解`Part1`得到`38609695`。

```python
part1 = 1
for i in range(1,2021):
    part1 *= i

part1 = str(part1)[:8] # 38609695
```

接着求解`Part2`，需要注意的是`.txt`中的是 $\large{520^{1314}+2333^{666}}$，得到`67358675`。

```python
part2 = str(520**1314 + 2333**666)[:8] # 67358675
```

宇宙终极问题是：是否存在整数`k`、`x`、`y`、`z`，使得对于所有的`k`都满足`Diophantine Equation`，$\large{k=x^{3}+y^{3}+z^{3}}$。宇宙终极问题的答案是`42`，$42 = (-80538738812075974)^{3}+80435758145817515^{3}+12602123297335631^{3}$，得到`Part3`是`17357662`。

先来计算$\large{\int_{0}^{22}2x\ dx+36}$，得到 $\large{x^{2}}|_{0}^{22}+36=22^{2}+36=520$，乘上`1314`后得到`Part4`的值为`683280`。

```python
part1 = 1
for i in range(1,2021):
    part1 *= i

part1 = hex(int(str(part1)[:8]))[2:]
part2 = hex(int(str(520**1314 + 2333**666)[:8]))[2:]
x = -80538738812075974
y = 80435758145817515
z = 12602123297335631
part3 = hex(int(str(abs(x)+y+z)[:8]))[2:]
part4 = hex(520*1314)[2:]
flag = f'flag{{{part1}-{part2}-{part3}-{part4}}}'
print(flag) # flag{24d231f-403cfd3-108db5e-a6d10}
```

------

### ❤[[MRCTF2020]babyRSA](https://buuoj.cn/challenges#[MRCTF2020]babyRSA)

附件解压缩后得到以下源码：

```python
import sympy
import random
from gmpy2 import gcd, invert
from Crypto.Util.number import getPrime, isPrime, getRandomNBitInteger, bytes_to_long, long_to_bytes
from z3 import *
flag = b"MRCTF{xxxx}"
base = 65537


def GCD(A):
    B = 1
    for i in range(1, len(A)):
        B = gcd(A[i-1], A[i])
    return B


def gen_p():
    P = [0 for i in range(17)]
    P[0] = getPrime(128)
    for i in range(1, 17):
        P[i] = sympy.nextprime(P[i-1])
    print("P_p :", P[9])
    n = 1
    for i in range(17):
        n *= P[i]
    p = getPrime(1024)
    factor = pow(p, base, n)
    print("P_factor :", factor)
    return sympy.nextprime(p)


def gen_q():
    sub_Q = getPrime(1024)
    Q_1 = getPrime(1024)
    Q_2 = getPrime(1024)
    Q = sub_Q ** Q_2 % Q_1
    print("Q_1: ", Q_1)
    print("Q_2: ", Q_2)
    print("sub_Q: ", sub_Q)
    return sympy.nextprime(Q)


if __name__ == "__main__":
    _E = base
    _P = gen_p()
    _Q = gen_q()
    assert (gcd(_E, (_P - 1) * (_Q - 1)) == 1)
    _M = bytes_to_long(flag)
    _C = pow(_M, _E, _P * _Q)
    print("Ciphertext = ", _C)
'''
P_p : 206027926847308612719677572554991143421
P_factor : 213671742765908980787116579976289600595864704574134469173111790965233629909513884704158446946409910475727584342641848597858942209151114627306286393390259700239698869487469080881267182803062488043469138252786381822646126962323295676431679988602406971858136496624861228526070581338082202663895710929460596143281673761666804565161435963957655012011051936180536581488499059517946308650135300428672486819645279969693519039407892941672784362868653243632727928279698588177694171797254644864554162848696210763681197279758130811723700154618280764123396312330032986093579531909363210692564988076206283296967165522152288770019720928264542910922693728918198338839
Q_1:  103766439849465588084625049495793857634556517064563488433148224524638105971161051763127718438062862548184814747601299494052813662851459740127499557785398714481909461631996020048315790167967699932967974484481209879664173009585231469785141628982021847883945871201430155071257803163523612863113967495969578605521
Q_2:  151010734276916939790591461278981486442548035032350797306496105136358723586953123484087860176438629843688462671681777513652947555325607414858514566053513243083627810686084890261120641161987614435114887565491866120507844566210561620503961205851409386041194326728437073995372322433035153519757017396063066469743
sub_Q:  168992529793593315757895995101430241994953638330919314800130536809801824971112039572562389449584350643924391984800978193707795909956472992631004290479273525116959461856227262232600089176950810729475058260332177626961286009876630340945093629959302803189668904123890991069113826241497783666995751391361028949651
Ciphertext =  1709187240516367141460862187749451047644094885791761673574674330840842792189795049968394122216854491757922647656430908587059997070488674220330847871811836724541907666983042376216411561826640060734307013458794925025684062804589439843027290282034999617915124231838524593607080377300985152179828199569474241678651559771763395596697140206072537688129790126472053987391538280007082203006348029125729650207661362371936196789562658458778312533505938858959644541233578654340925901963957980047639114170033936570060250438906130591377904182111622236567507022711176457301476543461600524993045300728432815672077399879668276471832
'''
```

先来分析`gen_p()`，`P`是一个大小为`17`的列表，`P[0]`是一个随机生成的`128`位素数，`P[1]`是`P[0]`的下一个素数，依此类推，`P[2]`，`P[3]`，`...`，`P[16]`。`P_p`是`P[9]`的值，利用`sympy`库可以把列表`P`中的其他素数全部推算出来，列表`P`中所有元素的乘积就是`n`。

由$factor=p^{base}\%n$，`base`的逆元`d = inverse(base, phi(n))`，可得$p=factor^{\large{d}}\%n$。

```python
base = 65537
def gen_p():
    P = [0 for i in range(17)]
    P[0] = getPrime(128)
    for i in range(1, 17):
        P[i] = sympy.nextprime(P[i-1])
    print("P_p :", P[9])
    n = 1
    for i in range(17):
        n *= P[i]
    p = getPrime(1024)
    factor = pow(p, base, n)
    print("P_factor :", factor)
    return sympy.nextprime(p)
'''
P_p : 206027926847308612719677572554991143421
P_factor : 213671742765908980787116579976289600595864704574134469173111790965233629909513884704158446946409910475727584342641848597858942209151114627306286393390259700239698869487469080881267182803062488043469138252786381822646126962323295676431679988602406971858136496624861228526070581338082202663895710929460596143281673761666804565161435963957655012011051936180536581488499059517946308650135300428672486819645279969693519039407892941672784362868653243632727928279698588177694171797254644864554162848696210763681197279758130811723700154618280764123396312330032986093579531909363210692564988076206283296967165522152288770019720928264542910922693728918198338839
'''
```

编写`Python`代码来求解`p`：

```python
import sympy.crypto
from Crypto.Util.number import *

base = 65537
P_p = 206027926847308612719677572554991143421
P_factor = 213671742765908980787116579976289600595864704574134469173111790965233629909513884704158446946409910475727584342641848597858942209151114627306286393390259700239698869487469080881267182803062488043469138252786381822646126962323295676431679988602406971858136496624861228526070581338082202663895710929460596143281673761666804565161435963957655012011051936180536581488499059517946308650135300428672486819645279969693519039407892941672784362868653243632727928279698588177694171797254644864554162848696210763681197279758130811723700154618280764123396312330032986093579531909363210692564988076206283296967165522152288770019720928264542910922693728918198338839
P = [0 for i in range(17)]
P[9] = P_p
for i in range(8, -1, -1):
    P[i] = sympy.prevprime(P[i+1])
    
for i in range(10, 17):
    P[i] = sympy.nextprime(P[i-1])
    
n, phin = 1, 1
for i in range(17):
    n *= P[i]
    phin *= P[i]-1  # phi(n)
d = inverse(base, phin)
p = pow(P_factor, d, n)
p = sympy.nextprime(p)
print(p)
# p = 160735380264118564161835536782782924160005620631679929855445290207351945863258282088265202232862202180668844947205806261323713945818872852303248590355632665886900928520533421774721590935485773234619558181513033385642711706205607543347313747616062185115981201425568780146693758544521883683953378438266703113683
```

接着来分析`gen_q()`，已知`Q_1`，`Q_2`和`sub_Q`，$\large{Q=sub_Q^{Q_2}\%Q_1}$，`q`是`Q`的下一个素数。

```python
def gen_q():
    sub_Q = getPrime(1024)
    Q_1 = getPrime(1024)
    Q_2 = getPrime(1024)
    Q = sub_Q ** Q_2 % Q_1
    print("Q_1: ", Q_1)
    print("Q_2: ", Q_2)
    print("sub_Q: ", sub_Q)
    return sympy.nextprime(Q)
'''
Q_1:  103766439849465588084625049495793857634556517064563488433148224524638105971161051763127718438062862548184814747601299494052813662851459740127499557785398714481909461631996020048315790167967699932967974484481209879664173009585231469785141628982021847883945871201430155071257803163523612863113967495969578605521
Q_2:  151010734276916939790591461278981486442548035032350797306496105136358723586953123484087860176438629843688462671681777513652947555325607414858514566053513243083627810686084890261120641161987614435114887565491866120507844566210561620503961205851409386041194326728437073995372322433035153519757017396063066469743
sub_Q:  168992529793593315757895995101430241994953638330919314800130536809801824971112039572562389449584350643924391984800978193707795909956472992631004290479273525116959461856227262232600089176950810729475058260332177626961286009876630340945093629959302803189668904123890991069113826241497783666995751391361028949651
'''
```

编写`Python`代码求解`q`：

```python
import sympy.crypto

Q_1 = 103766439849465588084625049495793857634556517064563488433148224524638105971161051763127718438062862548184814747601299494052813662851459740127499557785398714481909461631996020048315790167967699932967974484481209879664173009585231469785141628982021847883945871201430155071257803163523612863113967495969578605521
Q_2 = 151010734276916939790591461278981486442548035032350797306496105136358723586953123484087860176438629843688462671681777513652947555325607414858514566053513243083627810686084890261120641161987614435114887565491866120507844566210561620503961205851409386041194326728437073995372322433035153519757017396063066469743
sub_Q = 168992529793593315757895995101430241994953638330919314800130536809801824971112039572562389449584350643924391984800978193707795909956472992631004290479273525116959461856227262232600089176950810729475058260332177626961286009876630340945093629959302803189668904123890991069113826241497783666995751391361028949651
Q = pow(sub_Q,Q_2,Q_1)
q = sympy.nextprime(Q)
print(q)
# q = 95170653714081687088760585440906768700419459767774333757336842864507607081809193370870747769993218256925111100260761958233280546585624501259121060195932474781731613458132842656517609786144352755126076860272047457230913808406105832246663969943550533958139118721153456230616182820319799156494938586844573835221
```

接着就是`RSA`常规求解啦，得到`MRCTF{sti11_@_b@by_qu3st10n}`。

```python
from libnum import *

e = 65537
p = 160735380264118564161835536782782924160005620631679929855445290207351945863258282088265202232862202180668844947205806261323713945818872852303248590355632665886900928520533421774721590935485773234619558181513033385642711706205607543347313747616062185115981201425568780146693758544521883683953378438266703113683
q = 95170653714081687088760585440906768700419459767774333757336842864507607081809193370870747769993218256925111100260761958233280546585624501259121060195932474781731613458132842656517609786144352755126076860272047457230913808406105832246663969943550533958139118721153456230616182820319799156494938586844573835221
c = 1709187240516367141460862187749451047644094885791761673574674330840842792189795049968394122216854491757922647656430908587059997070488674220330847871811836724541907666983042376216411561826640060734307013458794925025684062804589439843027290282034999617915124231838524593607080377300985152179828199569474241678651559771763395596697140206072537688129790126472053987391538280007082203006348029125729650207661362371936196789562658458778312533505938858959644541233578654340925901963957980047639114170033936570060250438906130591377904182111622236567507022711176457301476543461600524993045300728432815672077399879668276471832
assert (gcd(e, (p-1)*(q-1)) == 1) # True
n = p*q
d = invmod(e, (p-1)*(q-1))
m = pow(c,d,n)
flag = n2s(m).decode()
print(flag) # MRCTF{sti11_@_b@by_qu3st10n}
```

最后来整合一下这题的代码，还是`libnum`用得得劲：

```python
import sympy.crypto
from libnum import *

e = 65537
P_p = 206027926847308612719677572554991143421
P_factor = 213671742765908980787116579976289600595864704574134469173111790965233629909513884704158446946409910475727584342641848597858942209151114627306286393390259700239698869487469080881267182803062488043469138252786381822646126962323295676431679988602406971858136496624861228526070581338082202663895710929460596143281673761666804565161435963957655012011051936180536581488499059517946308650135300428672486819645279969693519039407892941672784362868653243632727928279698588177694171797254644864554162848696210763681197279758130811723700154618280764123396312330032986093579531909363210692564988076206283296967165522152288770019720928264542910922693728918198338839
P = [0 for i in range(17)]
P[9] = P_p
for i in range(8, -1, -1):
    P[i] = sympy.prevprime(P[i+1])
    
for i in range(10, 17):
    P[i] = sympy.nextprime(P[i-1])
    
n, phin = 1, 1
for i in range(17):
    n *= P[i]
    phin *= P[i]-1  # phi(n)
d = invmod(e, phin)
p = pow(P_factor, d, n)
p = sympy.nextprime(p)
# print(p)
# p = 160735380264118564161835536782782924160005620631679929855445290207351945863258282088265202232862202180668844947205806261323713945818872852303248590355632665886900928520533421774721590935485773234619558181513033385642711706205607543347313747616062185115981201425568780146693758544521883683953378438266703113683
Q_1 = 103766439849465588084625049495793857634556517064563488433148224524638105971161051763127718438062862548184814747601299494052813662851459740127499557785398714481909461631996020048315790167967699932967974484481209879664173009585231469785141628982021847883945871201430155071257803163523612863113967495969578605521
Q_2 = 151010734276916939790591461278981486442548035032350797306496105136358723586953123484087860176438629843688462671681777513652947555325607414858514566053513243083627810686084890261120641161987614435114887565491866120507844566210561620503961205851409386041194326728437073995372322433035153519757017396063066469743
sub_Q = 168992529793593315757895995101430241994953638330919314800130536809801824971112039572562389449584350643924391984800978193707795909956472992631004290479273525116959461856227262232600089176950810729475058260332177626961286009876630340945093629959302803189668904123890991069113826241497783666995751391361028949651
Q = pow(sub_Q,Q_2,Q_1)
q = sympy.nextprime(Q)
# print(q)
c = 1709187240516367141460862187749451047644094885791761673574674330840842792189795049968394122216854491757922647656430908587059997070488674220330847871811836724541907666983042376216411561826640060734307013458794925025684062804589439843027290282034999617915124231838524593607080377300985152179828199569474241678651559771763395596697140206072537688129790126472053987391538280007082203006348029125729650207661362371936196789562658458778312533505938858959644541233578654340925901963957980047639114170033936570060250438906130591377904182111622236567507022711176457301476543461600524993045300728432815672077399879668276471832
assert (gcd(e, (p-1)*(q-1)) == 1) # True
n = p*q
d = invmod(e, (p-1)*(q-1))
m = pow(c,d,n)
flag = n2s(m).decode()
print(flag) # MRCTF{sti11_@_b@by_qu3st10n}
```

------

### [[NPUCTF2020]EzRSA](https://buuoj.cn/challenges#[NPUCTF2020]EzRSA)

附件内容如下：

```python
from gmpy2 import lcm , powmod , invert , gcd , mpz
from Crypto.Util.number import getPrime
from sympy import nextprime
from random import randint
p = getPrime(1024)
q = getPrime(1024)
n = p * q
gift = lcm(p - 1 , q - 1)
e = 54722
flag = b'NPUCTF{******************}'
m = int.from_bytes(flag , 'big')
c = powmod(m , e , n)
print('n: ' , n)
print('gift: ' , gift)
print('c: ' , c)

#n:  17083941230213489700426636484487738282426471494607098847295335339638177583685457921198569105417734668692072727759139358207667248703952436680183153327606147421932365889983347282046439156176685765143620637107347870401946946501620531665573668068349080410807996582297505889946205052879002028936125315312256470583622913646319779125559691270916064588684997382451412747432722966919513413709987353038375477178385125453567111965259721484997156799355617642131569095810304077131053588483057244340742751804935494087687363416921314041547093118565767609667033859583125275322077617576783247853718516166743858265291135353895239981121
#gift:  2135492653776686212553329560560967285303308936825887355911916917454772197960682240149821138177216833586509090969892419775958406087994054585022894165950768427741545736247918410255804894522085720642952579638418483800243368312702566458196708508543635051350999572787188236243275631609875253617015664414032058822919469443284453403064076232765024248435543326597418851751586308514540124571309152787559712950209357825576896132278045112177910266019741013995106579484868768251084453338417115483515132869594712162052362083414163954681306259137057581036657441897428432575924018950961141822554251369262248368899977337886190114104
#c:  3738960639194737957667684143565005503596276451617922474669745529299929395507971435311181578387223323429323286927370576955078618335757508161263585164126047545413028829873269342924092339298957635079736446851837414357757312525158356579607212496060244403765822636515347192211817658170822313646743520831977673861869637519843133863288550058359429455052676323196728280408508614527953057214779165450356577820378810467527006377296194102671360302059901897977339728292345132827184227155061326328585640019916328847372295754472832318258636054663091475801235050657401857262960415898483713074139212596685365780269667500271108538319
```

不需要`gift`也行，直接调用`requests`库在线请求 http://factordb.com 分解模数`n`，得到`p`和`q`，接着就是`RSA`题的常规求解啦。需要注意的是`e`是偶数，不和`phi=(p-1)*(q-1)`互素，进行推导分析：

> $\Large{c=m^{e}\ mod\ n}$
>
> $\Large{c=m^{2*\LARGE{\frac{e}{2}}}\ mod\ n}$
>
> $\Large{c=(m^{2})^{\LARGE{\frac{e}{2}}}\ mod\ n}$

所以我们可以利用`e//2`算出$m^{2}$，进而开平方得到`m`。编写`Python`代码求解得到`NPUCTF{diff1cult_rsa_1s_e@sy}`。

```python
import requests
from math import isqrt
from Crypto.Util.number import *

def factorize(n):
    l = []
    url="http://factordb.com/api?query="+str(n)
    r = requests.get(url)
    data = r.json()
    for factor in data['factors']:
        l.append(int(factor[0]))
    return l


n = 17083941230213489700426636484487738282426471494607098847295335339638177583685457921198569105417734668692072727759139358207667248703952436680183153327606147421932365889983347282046439156176685765143620637107347870401946946501620531665573668068349080410807996582297505889946205052879002028936125315312256470583622913646319779125559691270916064588684997382451412747432722966919513413709987353038375477178385125453567111965259721484997156799355617642131569095810304077131053588483057244340742751804935494087687363416921314041547093118565767609667033859583125275322077617576783247853718516166743858265291135353895239981121
c = 3738960639194737957667684143565005503596276451617922474669745529299929395507971435311181578387223323429323286927370576955078618335757508161263585164126047545413028829873269342924092339298957635079736446851837414357757312525158356579607212496060244403765822636515347192211817658170822313646743520831977673861869637519843133863288550058359429455052676323196728280408508614527953057214779165450356577820378810467527006377296194102671360302059901897977339728292345132827184227155061326328585640019916328847372295754472832318258636054663091475801235050657401857262960415898483713074139212596685365780269667500271108538319
e = 54722
p, q = factorize(n)
# print(p, q)
# p = 106021448991021391444550749375115277080844281746248845802565680557785009341952320484175568763707424932172033597514861602114171459176440279045761846695231788376075050452154924141266290931413542110639081792550648106240966552406813059396358355737185354885474455248579946190266152416149137616855791805617206153497
# q = 161136651053130509602530659420755324119806487925813087617466818245407407797561810253722204813002837916779909309520498985459703212021249251124954613236122142746302911323565396331355397916764254680629384957057354297855676493062493901977415968666512459829211010720514167083018352796496733697235524845188512914793
d = inverse(e//2, (p-1)*(q-1))
m = isqrt(pow(c, d, n))
flag = long_to_bytes(m).decode()
print(flag) # NPUCTF{diff1cult_rsa_1s_e@sy}
```

------

### [[UTCTF2020]basic-crypto](https://buuoj.cn/challenges#[UTCTF2020]basic-crypto)

附件解压缩后得到一个全是`0`和`1`的`.txt`文件。编写`Python`代码将二进制串转换成字符串：

```python
with open('attachment.txt', 'rb') as f:
    s = f.read().strip().decode()

txt = ''
for i in s.split(' '):
    txt += chr(eval('0b'+i))
print(txt)
# "Uh-oh, looks like we have another block of text, with some sort of special encoding. Can you figure out what this encoding is? (hint: if you look carefully, you'll notice that there only characters present are A-Z, a-z, 0-9, and sometimes / and +. See if you can find an encoding that looks like this one.)\nTmV3IGNoYWxsZW5nZSEgQ2FuIHlvdSBmaWd1cmUgb3V0IHdoYXQncyBnb2luZyBvbiBoZXJlPyBJdCBsb29rcyBsaWtlIHRoZSBsZXR0ZXJzIGFyZSBzaGlmdGVkIGJ5IHNvbWUgY29uc3RhbnQuIChoaW50OiB5b3UgbWlnaHQgd2FudCB0byBzdGFydCBsb29raW5nIHVwIFJvbWFuIHBlb3BsZSkuCmt2YnNxcmQsIGl5ZSdibyBrdnd5Y2QgZHJvYm8hIFh5ZyBweWIgZHJvIHBzeGt2IChreG4gd2tpbG8gZHJvIHJrYm5vY2QuLi4pIHprYmQ6IGsgY2VsY2RzZGVkc3l4IG1zenJvYi4gU3ggZHJvIHB5dnZ5Z3N4cSBkb2hkLCBTJ2ZvIGRrdW94IHdpIHdvY2NrcW8ga3huIGJvenZrbW9uIG9mb2JpIGt2enJrbG9kc20gbXJrYmttZG9iIGdzZHIgayBteWJib2N6eXhub3htbyBkeSBrIG5zcHBvYm94ZCBtcmtia21kb2IgLSB1eHlneCBrYyBrIGNlbGNkc2RlZHN5eCBtc3pyb2IuIE1reCBpeWUgcHN4biBkcm8gcHN4a3YgcHZrcT8gcnN4ZDogR28gdXh5ZyBkcmtkIGRybyBwdmtxIHNjIHF5c3hxIGR5IGxvIHlwIGRybyBweWJ3a2QgZWRwdmtxey4uLn0gLSBncnNtciB3b2t4YyBkcmtkIHNwIGl5ZSBjb28gZHJrZCB6a2Rkb2J4LCBpeWUgdXh5ZyBncmtkIGRybyBteWJib2N6eXhub3htb2MgcHliIGUsIGQsIHAsIHYgaywga3huIHEga2JvLiBJeWUgbWt4IHpieWxrbHZpIGd5YnUgeWVkIGRybyBib3drc3hzeHEgbXJrYmttZG9iYyBsaSBib3p2a21zeHEgZHJvdyBreG4gc3hwb2Jic3hxIG15d3d5eCBneWJuYyBzeCBkcm8gT3hxdnNjciB2a3hxZWtxby4gS3h5ZHJvYiBxYm9rZCB3b2RyeW4gc2MgZHkgZWNvIHBib2Flb3htaSBreGt2aWNzYzogZ28gdXh5ZyBkcmtkICdvJyBjcnlnYyBleiB3eWNkIHlwZG94IHN4IGRybyBrdnpya2xvZCwgY3kgZHJrZCdjIHpieWxrbHZpIGRybyB3eWNkIG15d3d5eCBtcmtia21kb2Igc3ggZHJvIGRvaGQsIHB5dnZ5Z29uIGxpICdkJywga3huIGN5IHl4LiBZeG1vIGl5ZSB1eHlnIGsgcG9nIG1ya2JrbWRvYmMsIGl5ZSBta3ggc3hwb2IgZHJvIGJvY2QgeXAgZHJvIGd5Ym5jIGxrY29uIHl4IG15d3d5eCBneWJuYyBkcmtkIGNyeWcgZXogc3ggZHJvIE94cXZzY3Igdmt4cWVrcW8uCnJnaG54c2RmeXNkdGdodSEgcWdmIGlzYWsgY3RodHVpa2UgZGlrIHprbnRoaGt4IHJ4cWxkZ254c2xpcSByaXN5eWtobmsuIGlreGsgdHUgcyBjeXNuIGNneCBzeXkgcWdmeCBpc3hlIGtjY2d4ZHU6IGZkY3lzbntoMHZfZGk0ZHVfdmk0ZF90X3I0eXlfcnhxbGQwfS4gcWdmIHZ0eXkgY3RoZSBkaXNkIHMgeWdkIGdjIHJ4cWxkZ254c2xpcSB0dSBwZnVkIHpmdHlldGhuIGdjYyBkaXR1IHVneGQgZ2MgenN1dHIgYmhndnlrZW5rLCBzaGUgdGQgeGtzeXlxIHR1IGhnZCB1ZyB6c2Ugc2Nka3ggc3l5LiBpZ2xrIHFnZiBraHBncWtlIGRpayByaXN5eWtobmsh"
```

根据`A-Z, a-z, 0-9, and sometimes / and +`可以推测出是`base64`编码，编写`Python`代码进行`base64`解码：

```python
cipher = txt.split('\n')[1]
from base64 import b64decode
txt = b64decode(cipher).decode()
print(txt)
# "New challenge! Can you figure out what's going on here? It looks like the letters are shifted by some constant. (hint: you might want to start looking up Roman people).\nkvbsqrd, iye'bo kvwycd drobo! Xyg pyb dro psxkv (kxn wkilo dro rkbnocd...) zkbd: k celcdsdedsyx mszrob. Sx dro pyvvygsxq dohd, S'fo dkuox wi wocckqo kxn bozvkmon ofobi kvzrklodsm mrkbkmdob gsdr k mybboczyxnoxmo dy k nsppoboxd mrkbkmdob - uxygx kc k celcdsdedsyx mszrob. Mkx iye psxn dro psxkv pvkq? rsxd: Go uxyg drkd dro pvkq sc qysxq dy lo yp dro pybwkd edpvkq{...} - grsmr wokxc drkd sp iye coo drkd zkddobx, iye uxyg grkd dro mybboczyxnoxmoc pyb e, d, p, v k, kxn q kbo. Iye mkx zbylklvi gybu yed dro bowksxsxq mrkbkmdobc li bozvkmsxq drow kxn sxpobbsxq mywwyx gybnc sx dro Oxqvscr vkxqekqo. Kxydrob qbokd wodryn sc dy eco pboaeoxmi kxkvicsc: go uxyg drkd 'o' crygc ez wycd ypdox sx dro kvzrklod, cy drkd'c zbylklvi dro wycd mywwyx mrkbkmdob sx dro dohd, pyvvygon li 'd', kxn cy yx. Yxmo iye uxyg k pog mrkbkmdobc, iye mkx sxpob dro bocd yp dro gybnc lkcon yx mywwyx gybnc drkd cryg ez sx dro Oxqvscr vkxqekqo.\nrghnxsdfysdtghu! qgf isak cthtuike dik zknthhkx rxqldgnxsliq risyykhnk. ikxk tu s cysn cgx syy qgfx isxe kccgxdu: fdcysn{h0v_di4du_vi4d_t_r4yy_rxqld0}. qgf vtyy cthe disd s ygd gc rxqldgnxsliq tu pfud zftyethn gcc ditu ugxd gc zsutr bhgvykenk, she td xksyyq tu hgd ug zse scdkx syy. iglk qgf khpgqke dik risyykhnk!"
```

根据`hint`推测是凯撒密码，继续编写`Python`代码进行解码，得知是最后一行是词频分析，用 https://quipqiup.com/ 进行词频分析可以看到`utflag{n0w_th4ts_wh4t_i_c4ll_crypt0}`。

```python
cipher = txt.split('\n')[2]
txt = txt.split('\n')[1]
print(txt)
# "kvbsqrd, iye'bo kvwycd drobo! Xyg pyb dro psxkv (kxn wkilo dro rkbnocd...) zkbd: k celcdsdedsyx mszrob. Sx dro pyvvygsxq dohd, S'fo dkuox wi wocckqo kxn bozvkmon ofobi kvzrklodsm mrkbkmdob gsdr k mybboczyxnoxmo dy k nsppoboxd mrkbkmdob - uxygx kc k celcdsdedsyx mszrob. Mkx iye psxn dro psxkv pvkq? rsxd: Go uxyg drkd dro pvkq sc qysxq dy lo yp dro pybwkd edpvkq{...} - grsmr wokxc drkd sp iye coo drkd zkddobx, iye uxyg grkd dro mybboczyxnoxmoc pyb e, d, p, v k, kxn q kbo. Iye mkx zbylklvi gybu yed dro bowksxsxq mrkbkmdobc li bozvkmsxq drow kxn sxpobbsxq mywwyx gybnc sx dro Oxqvscr vkxqekqo. Kxydrob qbokd wodryn sc dy eco pboaeoxmi kxkvicsc: go uxyg drkd 'o' crygc ez wycd ypdox sx dro kvzrklod, cy drkd'c zbylklvi dro wycd mywwyx mrkbkmdob sx dro dohd, pyvvygon li 'd', kxn cy yx. Yxmo iye uxyg k pog mrkbkmdobc, iye mkx sxpob dro bocd yp dro gybnc lkcon yx mywwyx gybnc drkd cryg ez sx dro Oxqvscr vkxqekqo."
flag = ''
for i in range(1, 27):
    s = ''
    for x in txt:
        if x.isalpha():
            s += chr(ord('a')+(ord(x)-ord('a')+i)%26)
        else:
            s += x
    s = s.lower()
    if 'flag' in s:
        flag = s
        print('{} 移位是{}'.format(s, (ord(txt[0])-ord(s[0]))%26))
# "alright, you're almost there! how for the final (and maybe the hardest...) part: a substitution cipher. cn the following text, c've taken my message and replaced every alphabetic character with a correspondence to a different character - known as a substitution cipher. wan you find the final flag? hint: qe know that the flag is going to be of the format utflag{...} - which means that if you see that pattern, you know what the correspondences for u, t, f, l a, and g are. sou can probably work out the remaining characters by replacing them and inferring common words in the ynglish language. unother great method is to use frequency analysis: we know that 'e' shows up most often in the alphabet, so that's probably the most common character in the text, followed by 't', and so on. ince you know a few characters, you can infer the rest of the words based on common words that show up in the ynglish language. 移位是10"
# https://quipqiup.com/
# congratulations! you have finished the beginner cryptography challenge. here is a flag for all your hard efforts: utflag{n0w_th4ts_wh4t_i_c4ll_crypt0}. you will find that a lot of cryptography is just building off this sort of basic knowledge, and it really is not so bad after all. hope you enjoyed the challenge!
```

------

### [WUSTCTF2020]情书

附件解压缩后得到以下内容：

```
Premise: Enumerate the alphabet by 0、1、2、.....  、25
Using the RSA system 
Encryption:0156 0821 1616 0041 0140 2130 1616 0793
Public Key:2537 and 13
Private Key:2537 and 937

flag: wctf2020{Decryption}
```

编写`Python`代码求解得到`flag{iloveyou}`。

```python
from libnum import *
import string

alphabet = string.ascii_lowercase
c = '0156 0821 1616 0041 0140 2130 1616 0793'
n = 2537
e = 13
d = 937
p, q = factorize(n)
# print(p, q)
# p = 43 
# q = 59
m = ''.join(alphabet[pow(int(i), d, n)] for i in c.split())
flag = f'flag{{{m}}}'
print(flag)  # flag{iloveyou}
```

------

## Real

### DASCTF2022_RSA

```python
from Crypto.Util.number import *
from gmpy2 import *

flag = b'DASCTF{xxxxxxxxxxxx}'

p = getPrime(512)
q = getPrime(512)

n = p*q
phi = (p-1)*(q-1)
while e := getRandomInteger(16):
    if gcd(e, phi) == 2:
        break

m = bytes_to_long(flag)
c = powmod(m, e, n)

print('n =', n)
print('e =', e)
print('c =', c)
print('h =', p**2 + q)

'''
n = 116511357060712144099976831158416173670467763509289584801493671983604041910332385046875404384756630045618050783932185923516987202481448148103872447145541170729746402328353998383492261143217680863970590230010586491615247835524208887971058047964672314644549792925412373691164840635424723609445014754830472392209
e = 36526
c = 68566562752091338059697971943044848432167577056994212169182746579664413762856878641964389495160899828612738440047547382833551104203712893527042407485845990546365951293911064224353754617767168257803980890401905329505235528035798742136124001870783107781705890831136037290806374721309719666807958790646103085768
h = 118281503660900552145988262483339393233985528449636132779876616077036147786271012801732196061115583504320630043125553844303439507836838360542594809019689063414521859114811409777400410154808000209258308294888519030043778123024058803886403741431766179429783054411509193156279355605455472548615352680641931274832
'''
```

用`z3`解方程组求出`p`和`q`，`e`和`phi`的最大公约数为`2`，编写`Python`代码求解得到`DASCTF{194d3623abfa2b8ff96119ceaf2ed934}`。

```python
from z3 import *
from math import isqrt
from Crypto.Util.number import *

n = 116511357060712144099976831158416173670467763509289584801493671983604041910332385046875404384756630045618050783932185923516987202481448148103872447145541170729746402328353998383492261143217680863970590230010586491615247835524208887971058047964672314644549792925412373691164840635424723609445014754830472392209
e = 36526
c = 68566562752091338059697971943044848432167577056994212169182746579664413762856878641964389495160899828612738440047547382833551104203712893527042407485845990546365951293911064224353754617767168257803980890401905329505235528035798742136124001870783107781705890831136037290806374721309719666807958790646103085768
h = 118281503660900552145988262483339393233985528449636132779876616077036147786271012801732196061115583504320630043125553844303439507836838360542594809019689063414521859114811409777400410154808000209258308294888519030043778123024058803886403741431766179429783054411509193156279355605455472548615352680641931274832
p = Int('p')
q = Int('q')
s = Solver()
s.add(p*q==n)
s.add(p**2+q==h)
if s.check() == sat:
    p = s.model()[p].as_long()
    q = s.model()[q].as_long()
# print(p, q)
# p = 10875730028871650515065014441296606276263483087773849451147307607447447416011541301551891346245451645857485498452834754451215820107294511193623920048942559
# q = 10712968853714743872526082284449246817083435005715609873200136574062381693683264866111272068450623053780663098018090504894839697187442017093462707849806351
d = inverse(e, (p-1)*(q-1))
m = isqrt(pow(c, d, n))
flag = long_to_bytes(m).decode()
print(flag) # DASCTF{194d3623abfa2b8ff96119ceaf2ed934}
```

