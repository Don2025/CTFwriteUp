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

### [game](https://adworld.xctf.org.cn/task/answer?type=reverse&number=4&grade=0&id=5074)

`file`查看文件可以看到：`./game.exe: PE32 executable (console) Intel 80386, for MS Windows`。使用`IDA Pro 32bit`打开附件，按`F5`进行反编译可以看到以下源码：

```c
// attributes: thunk
int __cdecl main(int argc, const char **argv, const char **envp)
{
  return main_0(argc, argv, envp);
}
```

双击`main_0()`函数，可以看到以下源码：

```c
int __cdecl main_0(int argc, const char **argv, const char **envp)
{
  int i; // [esp+DCh] [ebp-20h]
  int v5; // [esp+F4h] [ebp-8h] BYREF

  sub_45A7BE(&unk_50B110);
  sub_45A7BE(&unk_50B158);
  sub_45A7BE(&unk_50B1A0);
  sub_45A7BE(&unk_50B1E8);
  sub_45A7BE(&unk_50B230);
  sub_45A7BE(&unk_50B278);
  sub_45A7BE(&unk_50B2C0);
  sub_45A7BE(&unk_50B308);
  sub_45A7BE("二                                                     |\n");
  sub_45A7BE("|              by 0x61                                 |\n");
  sub_45A7BE("|                                                      |\n");
  sub_45A7BE("|------------------------------------------------------|\n");
  sub_45A7BE(
    "Play a game\n"
    "The n is the serial number of the lamp,and m is the state of the lamp\n"
    "If m of the Nth lamp is 1,it's on ,if not it's off\n"
    "At first all the lights were closed\n");
  sub_45A7BE("Now you can input n to change its state\n");
  sub_45A7BE(
    "But you should pay attention to one thing,if you change the state of the Nth lamp,the state of (N-1)th and (N+1)th w"
    "ill be changed too\n");
  sub_45A7BE("When all lamps are on,flag will appear\n");
  sub_45A7BE("Now,input n \n");
  while ( 1 )
  {
    while ( 1 )
    {
      sub_45A7BE("input n,n(1-8)\n");
      sub_459418();
      sub_45A7BE("n=");
      sub_4596D4("%d", &v5);
      sub_45A7BE("\n");
      if ( v5 >= 0 && v5 <= 8 )
        break;
      sub_45A7BE("sorry,n error,try again\n");
    }
    if ( v5 )
    {
      sub_4576D6(v5 - 1);
    }
    else
    {
      for ( i = 0; i < 8; ++i )
      {
        if ( (unsigned int)i >= 9 )
          j____report_rangecheckfailure();
        byte_532E28[i] = 0;
      }
    }
    j__system("CLS");
    sub_458054();
    if ( byte_532E28[0] == 1
      && byte_532E28[1] == 1
      && byte_532E28[2] == 1
      && byte_532E28[3] == 1
      && byte_532E28[4] == 1
      && byte_532E28[5] == 1
      && byte_532E28[6] == 1
      && byte_532E28[7] == 1 )
    {
      sub_457AB4();
    }
  }
}
```

双击`sub_457AB4()`函数，可以看到以下源码：

```c
// attributes: thunk
int sub_457AB4(void)
{
  return sub_45E940();
}
```

再双击`sub_45E940()`函数，可以看到以下源码：

```c
int sub_45E940()
{
  int i; // [esp+D0h] [ebp-94h]
  char v2[22]; // [esp+DCh] [ebp-88h]
  char v3[32]; // [esp+F2h] [ebp-72h] BYREF
  char v4[4]; // [esp+112h] [ebp-52h] BYREF
  char v5[64]; // [esp+120h] [ebp-44h]

  sub_45A7BE("done!!! the flag is ");
  v5[0] = 18;
  v5[1] = 64;
  v5[2] = 98;
  v5[3] = 5;
  v5[4] = 2;
  v5[5] = 4;
  v5[6] = 6;
  v5[7] = 3;
  v5[8] = 6;
  v5[9] = 48;
  v5[10] = 49;
  v5[11] = 65;
  v5[12] = 32;
  v5[13] = 12;
  v5[14] = 48;
  v5[15] = 65;
  v5[16] = 31;
  v5[17] = 78;
  v5[18] = 62;
  v5[19] = 32;
  v5[20] = 49;
  v5[21] = 32;
  v5[22] = 1;
  v5[23] = 57;
  v5[24] = 96;
  v5[25] = 3;
  v5[26] = 21;
  v5[27] = 9;
  v5[28] = 4;
  v5[29] = 62;
  v5[30] = 3;
  v5[31] = 5;
  v5[32] = 4;
  v5[33] = 1;
  v5[34] = 2;
  v5[35] = 3;
  v5[36] = 44;
  v5[37] = 65;
  v5[38] = 78;
  v5[39] = 32;
  v5[40] = 16;
  v5[41] = 97;
  v5[42] = 54;
  v5[43] = 16;
  v5[44] = 44;
  v5[45] = 52;
  v5[46] = 32;
  v5[47] = 64;
  v5[48] = 89;
  v5[49] = 45;
  v5[50] = 32;
  v5[51] = 65;
  v5[52] = 15;
  v5[53] = 34;
  v5[54] = 18;
  v5[55] = 16;
  v5[56] = 0;
  v2[0] = 123;
  v2[1] = 32;
  v2[2] = 18;
  v2[3] = 98;
  v2[4] = 119;
  v2[5] = 108;
  v2[6] = 65;
  v2[7] = 41;
  v2[8] = 124;
  v2[9] = 80;
  v2[10] = 125;
  v2[11] = 38;
  v2[12] = 124;
  v2[13] = 111;
  v2[14] = 74;
  v2[15] = 49;
  v2[16] = 83;
  v2[17] = 108;
  v2[18] = 94;
  v2[19] = 108;
  v2[20] = 84;
  v2[21] = 6;
  qmemcpy(v3, "`S,yhn _uec{", 12);
  v3[12] = 127;
  v3[13] = 119;
  v3[14] = 96;
  v3[15] = 48;
  v3[16] = 107;
  v3[17] = 71;
  v3[18] = 92;
  v3[19] = 29;
  v3[20] = 81;
  v3[21] = 107;
  v3[22] = 90;
  v3[23] = 85;
  v3[24] = 64;
  v3[25] = 12;
  v3[26] = 43;
  v3[27] = 76;
  v3[28] = 86;
  v3[29] = 13;
  v3[30] = 114;
  v3[31] = 1;
  strcpy(v4, "u~");
  for ( i = 0; i < 56; ++i )
  {
    v2[i] ^= v5[i];
    v2[i] ^= 0x13u;
  }
  return sub_45A7BE("%s\n");
}
```

根据代码逻辑，可以编写出以下`Python`代码，运行得到`flag`：`zsctf{T9is_tOpic_1s_v5ry_int7resting_b6t_others_are_n0t}`。

```python
a = [123,32,18,98,119,108,65,41,124,80,125,38,124,111,74,49,83,108,94,108,84,6,96,83,44,121,104,110,32,95,117,101,99,123,127,119,96,48,107,71,92,29,81,107,90,85,64,12,43,76,86,13,114,1,117,126]
b = [18,64,98,5,2,4,6,3,6,48,49,65,32,12,48,65,31,78,62,32,49,32,1,57,96,3,21,9,4,62,3,5,4,1,2,3,44,65,78,32,16,97,54,16,44,52,32,64,89,45,32,65,15,34,18,16]
for i in range(0, 56):
    a[i] ^= b[i]
    a[i] ^= 0x13
flag = ''.join(chr(i) for i in a)
print(flag)
```

------

### [no-strings-attached](https://adworld.xctf.org.cn/task/answer?type=reverse&number=4&grade=0&id=5080)

`file`查看文件可以看到以下信息：

![](https://paper.tanyaodan.com/ADWorld/reverse/no-strings-attached/1.png)

使用`IDA Pro 32bit`打开附件，按`F5`进行反编译可以看到以下源码：

![](https://paper.tanyaodan.com/ADWorld/reverse/no-strings-attached/2.png)

第一个函数用于区域设置；第二个获取时间，搞了个随机数种子，还输出了欢迎语；第三个函数里只输出了句话让用户输入，都没啥用。双击`authenticate()`函数可以看到调用`decrypt()`函数的这行代码很关键，用户输入要和`s2`进行字符串比较，显然`s2`就是`flag`。

![](https://paper.tanyaodan.com/ADWorld/reverse/no-strings-attached/3.png)

双击`decrypt()`函数可以看到源码如下：

![](https://paper.tanyaodan.com/ADWorld/reverse/no-strings-attached/4.png)

查看汇编代码，发现`decrypt()` 函数执行结束后，会将一个结果放入内存中。

![](https://paper.tanyaodan.com/ADWorld/reverse/no-strings-attached/5.png)

这就需要用`gdb`进行动态调试，在`decrypt()`函数处设置断点，执行完该函数后再执行一步来读取`$eax`寄存器中的内容，即可得到`flag`。

```bash
gdb ./no-strings-attached -q
b decrypt
r
n
x/sw $eax
```

`break/b` 可以设置断点，`gdb`可以直接根据已知函数名来对该函数设置断点，也可通过`*指定地址`下断点。 `run/r`可以运行程序，`next/n`表示单步步过，`s` 表示单步步入（如果此行代码中有函数调用，则进入该函数），` x` 指令表示查看寄存器内容，参数`/s`表示用字符串形式显示，`/w`表示四字节宽，因此`/sw` 表示以四字节宽来显示字符串。

![](https://paper.tanyaodan.com/ADWorld/reverse/no-strings-attached/6.png)

本题的`flag`就是`9447{you_are_an_international_mystery}`。

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

