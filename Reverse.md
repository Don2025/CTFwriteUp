# Reverse

## ADWorld

### [Hello, CTF](https://adworld.xctf.org.cn/task/answer?type=reverse&number=4&grade=0&id=5075)

用`file`查看`.exe`文件发现是`PE32`，用`IDA Pro 32bit`打开附件给出的`.exe`文件后按`F5`进行反编译，代码审计后可以发现这段代码大致逻辑为将用户输入的字符串与`v13`字符串`437261636b4d654a757374466f7246756e`进行比对，判断是否输入正确，这一串字符串是`16`进制的`ASCII`码，直接编写`Python`代码即可得到`flag`：`CrackMeJustForFun`。

```python
flag = bytes.fromhex('437261636b4d654a757374466f7246756e').decode('utf-8')
print(flag) # CrackMeJustForFun
# 上面是方法1 下面是方法2
import binascii
flag = binascii.a2b_hex('437261636b4d654a757374466f7246756e')
print(flag) # CrackMeJustForFun
```

------

### [insanity](https://adworld.xctf.org.cn/task/answer?type=reverse&number=4&grade=0&id=5079)

用`IDA Pro 32bit`打开附件给出的文件，按`F5`进行反编译，`shift + F12`打开`Strings window`可以看到有一行`9447{This_is_a_flag}`，提交即可。

------

### [python-trade](https://adworld.xctf.org.cn/task/answer?type=reverse&number=4&grade=0&id=5083)

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
# Embedded file name: 1.py
# Compiled at: 2017-06-03 10:20:43
import base64

def encode(message):
    s = ''
    for i in message:
        x = ord(i) ^ 32
        x = x + 16
        s += chr(x)
    return base64.b64encode(s)

correct = 'XlNkVmtUI1MgXWBZXCFeKY+AaXNt'
flag = ''
print 'Input flag:'
flag = raw_input()
if encode(flag) == correct:
    print 'correct'
else:
    print 'wrong'
```

要得到原始`flag`的话，函数内部的运算，`+`变`-`，异或运算的逆过程就是再做一次异或，`base64.b64encode()`改成`base64.b64decode()`。运行`Python`代码即可得到`nctf{d3c0mpil1n9_PyC}`。

```python
import base64

def decode(s):
    s = base64.b64decode(s)
    ans = ''
    for i in s:
        x = i - 16
        x ^= 32
        ans += chr(x)
    return ans

flag = decode('XlNkVmtUI1MgXWBZXCFeKY+AaXNt')
print(flag)
```

------

### [re1](https://adworld.xctf.org.cn/task/answer?type=reverse&number=4&grade=0&id=5073)

用`file`查看`.exe`文件发现是`PE32`，用`IDA Pro 32bit`以二进制文件形式打开附件给出的`.exe`文件后按`shift + F12`查看`Strings window`可以发现`flag`：`DUTCTF{We1c0met0DUTCTF}`。

------

### [open-source](https://adworld.xctf.org.cn/task/answer?type=reverse&number=4&grade=0&id=5076)

这道题的附件是一个`.c`文件，直接查看源码：

```c
#include <stdio.h>
#include <string.h>

int main(int argc, char *argv[]) {
    if (argc != 4) {
    	printf("what?\n");
    	exit(1);
    }
    // first = 51966;
    unsigned int first = atoi(argv[1]);
    if (first != 0xcafe) {  
    	printf("you are wrong, sorry.\n");
    	exit(2);
    }
    // second = 25;
    unsigned int second = atoi(argv[2]);
    if (second % 5 == 3 || second % 17 != 8) {
    	printf("ha, you won't get it!\n");
    	exit(3);
    }
    // argv[3] = "h4cky0u";
    if (strcmp("h4cky0u", argv[3])) {
    	printf("so close, dude!\n");
    	exit(4);
    }

    printf("Brr wrrr grr\n");

    unsigned int hash = first * 31337 + (second % 17) * 11 + strlen(argv[3]) - 1615810207;

    printf("Get your key: ");
    printf("%x\n", hash);
    return 0;
}
```

可以看到`flag`应该就是变量`hash`的`16`进制数值，由判断条件`argc != 4`可知命令行需要输入`4`个参数，其中参数`first=0xcafe;`即`first=51966;`，由判断条件`second%5==3 || second%17!=8`可以令`second=25;`，由判断条件`strcmp("h4cky0u", argv[3])`可知`argv[3]="h4cky0u";`，`%x`表示输出该数的`16`进制值。

直接在命令行输入`./a 51966 25 h4cky0u`即可看到以下结果：

```bash
Brr wrrr grr
Get your key: c0ffee
```

提交`flag{c0ffee}`即可。

------

### [simple-unpack](https://adworld.xctf.org.cn/task/answer?type=reverse&number=4&grade=0&id=5077)

题目描述中有说这是一个被加壳的二进制文件，在`Kali-Linux`中使用命令行`upx -d 文件名`进行脱壳。

![](https://paper.tanyaodan.com/ADWorld/reverse/simple-unpack/1.png)

`file ./simple-unpack`发现该文件是`64`位的，用`IDA Pro 64bit`以`ELF 64 for x86-64`形式打开文件后，按`F5`进行反编译可以看到以下源码：

![](https://paper.tanyaodan.com/ADWorld/reverse/simple-unpack/2.png)

双击`flag`即可得到`flag{Upx_1s_n0t_a_d3liv3r_c0mp4ny}`。

![](https://paper.tanyaodan.com/ADWorld/reverse/simple-unpack/3.png)

如果题目没有提示，不知道需要脱壳的话，也可以直接用`file`查看`.exe`文件发现是`ELF 64-bit LSB executable, x86-64`，用`IDA Pro 64bit`以二进制文件形式打开附件给出的`.exe`文件后按`shift + F12`查看`Strings window`可以发现`flag`：`flag{Upx_1s_n0t_a_d3liv3r_c0mp4ny}`。

------

### [logmein](https://adworld.xctf.org.cn/task/answer?type=reverse&number=4&grade=0&id=5078)

用`file`查看`.exe`文件发现是`ELF 64-bit LSB executable, x86-64`，用`IDA Pro 64bit`打开附件，按`F5`进行反编译可以看到以下源码：

![](https://paper.tanyaodan.com/ADWorld/reverse/logmein/1.png)

分析代码逻辑，`v8`是加密后数据，`v7`相当于密钥，将`v8`逐个字符与`v7`中的字符逐个进行异或后，得到的字符串就是正确的密码。

编写`Python`代码即可得到`flag`：`RC3-2016-XORISGUD`。

```python
v6 = 7
v7 = bytes.fromhex('65626D61726168')[::-1].decode('utf-8')
v8 = ':\"AL_RT^L*.?+6/46'
flag = ''
for i in range(0, len(v8)):
    flag += chr(ord(v7[i%v6])^ord(v8[i]))
print(flag)
```

可以`./logmein`验证一下`RC3-2016-XORISGUD`这个密码是否正确：

```bash
Welcome to the RC3 secure password guesser.
To continue, you must enter the correct password.
Enter your guess: RC3-2016-XORISGUD
You entered the correct password!
Great job!
```

------

## BUUCTF

### [reverse2](https://buuoj.cn/challenges#reverse2)

用 `file`查看`reverse2.exe`发现是`64bit`的`X86`架构编译的`ELF`文件，用`IDA Pro 64bit`打开文件后，按`F5`反编译可以看到主函数的`C`语言代码如下：

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int result; // eax
  int stat_loc; // [rsp+4h] [rbp-3Ch] BYREF
  int i; // [rsp+8h] [rbp-38h]
  __pid_t pid; // [rsp+Ch] [rbp-34h]
  char s2[24]; // [rsp+10h] [rbp-30h] BYREF
  unsigned __int64 v8; // [rsp+28h] [rbp-18h]

  v8 = __readfsqword(0x28u);
  pid = fork();
  if ( pid )
  {
    waitpid(pid, &stat_loc, 0);
  }
  else
  {
    for ( i = 0; i <= strlen(&flag); ++i )
    {
      if ( *(&flag + i) == 105 || *(&flag + i) == 114 )
        *(&flag + i) = 49;
    }
  }
  printf("input the flag:");
  __isoc99_scanf("%20s", s2);
  if ( !strcmp(&flag, s2) )
    result = puts("this is the right flag!");
  else
    result = puts("wrong flag!");
  return result;
}
```

双击`flag`变量可以看到以下信息：

![](https://paper.tanyaodan.com/BUUCTF/reverse2/1.png)

分析源码发现程序执行了字符替换，把字母`i`和`r`替换成了数字`1`。

![](https://paper.tanyaodan.com/BUUCTF/reverse2/2.png)

因此最终的`flag`为`flag{hack1ng_fo1_fun}`。

