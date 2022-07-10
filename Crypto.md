# Crypto

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

直接对`n`进行大因素分解，得到`p`和`Q`，再求`m`。

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

### PwnTheBox

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

