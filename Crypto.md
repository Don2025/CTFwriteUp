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

### [rsa3](https://ce.pwnthebox.com/challenges?id=188)

附件解压缩后得到`pub.pem`和`flag.enc`。编写`Python`进行求解，首先用`rsa`库来获取公钥对`<n, e>`，然后调用`requests`库在线请求 http://factordb.com 分解模数`n`，得到`p`和`q`，算出 `φ(n) = (p-1)(q-1)`，进而得到私钥的解密质数`d`，至此私钥已经拿到。用私钥对`flag.enc`进行`rsa`解密，可以得到明文`flag{decrypt_256}`，提交即可。

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

