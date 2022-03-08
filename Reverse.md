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

### [Shuffle](https://adworld.xctf.org.cn/task/answer?type=reverse&number=4&grade=1&id=4942)

用 `file`查看`maze`，可以看到信息`./Shuffle: ELF 32-bit LSB executable, Intel 80386`，用`IDA Pro 32bit`打开文件后，按`F5`反编译可以看到主函数的`C`语言代码如下：

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  time_t v3; // ebx
  __pid_t v4; // eax
  int i; // [esp+14h] [ebp-44h]
  unsigned int v7; // [esp+18h] [ebp-40h]
  unsigned int v8; // [esp+1Ch] [ebp-3Ch]
  char v9; // [esp+20h] [ebp-38h]
  char s[40]; // [esp+24h] [ebp-34h] BYREF
  unsigned int v11; // [esp+4Ch] [ebp-Ch]

  v11 = __readgsdword(0x14u);
  strcpy(s, "SECCON{Welcome to the SECCON 2014 CTF!}");
  v3 = time(0);
  v4 = getpid();
  srand(v3 + v4);
  for ( i = 0; i <= 99; ++i )
  {
    v7 = rand() % 0x28u;
    v8 = rand() % 0x28u;
    v9 = s[v7];
    s[v7] = s[v8];
    s[v8] = v9;
  }
  puts(s);
  return 0;
}
```

`flag`都写出来了，直接提交`SECCON{Welcome to the SECCON 2014 CTF!}`即可。

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
print(flag) # nctf{d3c0mpil1n9_PyC}
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
print(flag) # zsctf{T9is_tOpic_1s_v5ry_int7resting_b6t_others_are_n0t}
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

### [csaw2013reversing2](https://adworld.xctf.org.cn/task/answer?type=reverse&number=4&grade=0&id=5081)

用 `file`查看`csaw2013reversing2.exe`，可以看到信息`./csaw2013reversing2.exe: PE32 executable (console) Intel 80386, for MS Windows`。用`IDA Pro 32bit`打开文件后，按`F5`反编译可以看到主函数的`C`语言代码如下：

```c
int __cdecl __noreturn main(int argc, const char **argv, const char **envp)
{
  int v3; // ecx
  CHAR *lpMem; // [esp+8h] [ebp-Ch]
  HANDLE hHeap; // [esp+10h] [ebp-4h]

  hHeap = HeapCreate(0x40000u, 0, 0);
  lpMem = (CHAR *)HeapAlloc(hHeap, 8u, SourceSize + 1);
  memcpy_s(lpMem, SourceSize, &unk_409B10, SourceSize);
  if ( !sub_40102A() && !IsDebuggerPresent() )
  {
    MessageBoxA(0, lpMem + 1, "Flag", 2u);
    HeapFree(hHeap, 0, lpMem);
    HeapDestroy(hHeap);
    ExitProcess(0);
  }
  __debugbreak();
  sub_401000(v3 + 4, lpMem);
  ExitProcess(0xFFFFFFFF);
}
```

注意到 `MessageBoxA(0, lpMem + 1, "Flag", 2u);` 这行代码，这行代码在一个`if`代码块中，而这个`if`语句的判断条件默认不成立，直接跳转到后面代码中输出乱码。回到汇编语言代码，`loc_401096` 中有一个 `int3` 断点可以`Trap to Debugger`，`loc_4010B9`可以输出弹窗。

![](https://paper.tanyaodan.com/ADWorld/reverse/csaw2013reversing2/1.png)

所以解题思路就是让程序跳转到 `loc_401096` 进行解码， 将`int3` 改成 `nop(0x90)`，再跳转到 `loc_4010B9` 输出弹窗。而不是直接执行`loc_4010B9`输出含有乱码的弹窗。

使用`ollydbg`打开`csaw2013reversing2.exe`，将`0040109A`这条`int 3`语句前的`je short csaw2013.00BF10B9`修改为`je short csaw2013.00BF1096`。![](https://paper.tanyaodan.com/ADWorld/reverse/csaw2013reversing2/2.png)

将`int3` 这个断点中断改成 `nop(0x90)`。

![](https://paper.tanyaodan.com/ADWorld/reverse/csaw2013reversing2/3.png)

再将后面的那条`je short csaw2013.00BF10EF`修改为`je short csaw2013.00BF10B9`。

![](https://paper.tanyaodan.com/ADWorld/reverse/csaw2013reversing2/4.png)

`run`执行程序即可输出包含`flag`的无码弹窗，从而得到`flag`：`flag{reversing_is_not_that_hard!}`。

![](https://paper.tanyaodan.com/ADWorld/reverse/csaw2013reversing2/5.png)

------

### [getit](https://adworld.xctf.org.cn/task/answer?type=reverse&number=4&grade=0&id=5082)

用 `file`查看`getit`，可以看到信息`./getit: ELF 64-bit LSB executable, x86-64`，用`IDA Pro 64bit`打开文件后，按`F5`反编译可以看到主函数的`C`语言代码如下：

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char v3; // al
  int i; // [rsp+0h] [rbp-40h]
  int j; // [rsp+4h] [rbp-3Ch]
  FILE *stream; // [rsp+8h] [rbp-38h]
  char filename[24]; // [rsp+10h] [rbp-30h] BYREF
  unsigned __int64 v9; // [rsp+28h] [rbp-18h]

  v9 = __readfsqword(0x28u);
  for ( i = 0; i < strlen(s); ++i )
  {
    if ( (i & 1) != 0 )
      v3 = 1;
    else
      v3 = -1;
    *(&t + i + 10) = s[i] + v3;
  }
  strcpy(filename, "/tmp/flag.txt");
  stream = fopen(filename, "w");
  fprintf(stream, "%s\n", u);
  for ( j = 0; j < strlen(&t); ++j )
  {
    fseek(stream, p[j], 0);
    fputc(*(&t + p[j]), stream);
    fseek(stream, 0LL, 0);
    fprintf(stream, "%s\n", u);
  }
  fclose(stream);
  remove(filename);
  return 0;
}
```

分析主函数的代码逻辑，首先是判断字符串`v5`的长度是否小于字符串`s`的长度，然后经过运算，将得到的`flag`写入文件。`flag.txt`文件所在的位置是`/tmp`目录，这个目录是`Linux`系统中的临时文件夹，当程序运行完成后，生成`flag`的`txt`文件就会被清理，因此无法再在该目录中找到文件。

在`IDA`中查看汇编代码，追踪`strlen`可以找到`for()`的判断条件位置，还要进行一步查找`fseek()`函数。根据汇编代码，可以确定`jnb loc_4008B5`就是`fseek()`函数，而`mov eax,[rbp+var_3C]`中每次移动的值应该就是`flag`中的一部分，继续审计汇编代码可以看到`mov rdx, [rbp+stream] `，所以`flag`最终应该会存放在寄存器`$rdx`中。

![](https://paper.tanyaodan.com/ADWorld/reverse/getit/1.png)

`vim ~/.gdbinit`然后取消`#source /home/tyd/ctf/gdb/pwndbg/gdbinit.py`前的`#`注释以启用`pwndbg`。接着使用`pwndbg`来动态调试程序，`b *0x400832`在地址`0x400832`处设置断点，`r/run`运行程序，可以直接看到每个寄存器中存储的数值信息，而`$rdx`寄存器中存放着`flag`：`SharifCTF{b70c59275fcfa8aebf2d5911223c6589}`。

![](https://paper.tanyaodan.com/ADWorld/reverse/getit/2.png)

此外，这道题还可根据代码审计的结果编写`Python`代码，运行即可得到`flag`：`SharifCTF{b70c59275fcfa8aebf2d5911223c6589}`。

```python
s = 'c61b68366edeb7bdce3c6820314b7498'
flag = ''
for i in range(0, len(s)):
    if i&1:
        v3 = 1
    else:
        v3 = -1
    flag += chr(ord(s[i])+v3)
flag = 'SharifCTF' + flag + '}'  #因为这题来源SharifCTF 2016
print(flag) # SharifCTF{b70c59275fcfa8aebf2d5911223c6589}
```

------

### [maze](https://adworld.xctf.org.cn/task/answer?type=reverse&number=4&grade=0&id=5084)

用 `file`查看`maze`，可以看到信息`./maze: ELF 64-bit LSB executable, x86-64`，用`IDA Pro 64bit`打开文件后，按`F5`反编译可以看到主函数的`C`语言代码如下：	

```c
__int64 __fastcall main(int a1, char **a2, char **a3)
{
  __int64 v3; // rbx
  int v4; // eax
  char v5; // bp
  char v6; // al
  const char *v7; // rdi
  unsigned int v9; // [rsp+0h] [rbp-28h] BYREF
  int v10[9]; // [rsp+4h] [rbp-24h] BYREF

  v10[0] = 0;
  v9 = 0;
  puts("Input flag:");
  scanf("%s", &s1);
  if ( strlen(&s1) != 24 || strncmp(&s1, "nctf{", 5uLL) || *(&byte_6010BF + 24) != 125 )
  {
LABEL_22:
    puts("Wrong flag!");
    exit(-1);
  }
  v3 = 5LL;
  if ( strlen(&s1) - 1 > 5 )
  {
    while ( 1 )
    {
      v4 = *(&s1 + v3);
      v5 = 0;
      if ( v4 > 78 )
      {
        if ( (unsigned __int8)v4 == 79 )  // 79,'O'
        {
          v6 = sub_400650(v10);
          goto LABEL_14;
        }
        if ( (unsigned __int8)v4 == 111 )  // 111,'o'
        {
          v6 = sub_400660(v10);
          goto LABEL_14;
        }
      }
      else
      {
        if ( (unsigned __int8)v4 == 46 )  // 46,'.'
        {
          v6 = sub_400670(&v9);
          goto LABEL_14;
        }
        if ( (unsigned __int8)v4 == 48 )  //48,'0'
        {
          v6 = sub_400680(&v9);
LABEL_14:
          v5 = v6;
          goto LABEL_15;
        }
      }
LABEL_15:
      if ( !(unsigned __int8)sub_400690(asc_601060, (unsigned int)v10[0], v9) )
        goto LABEL_22;
      if ( ++v3 >= strlen(&s1) - 1 )
      {
        if ( v5 )
          break;
LABEL_20:
        v7 = "Wrong flag!";
        goto LABEL_21;
      }
    }
  }
  if ( asc_601060[8 * v9 + v10[0]] != 35 ) // 当前位置 = 8(迷宫横长) * 当前纵坐标 + 当前横坐标
    goto LABEL_20;
  v7 = "Congratulations!";
LABEL_21:
  puts(v7);
  return 0LL;
}
```

审计代码可以发现`flag`的长度为`24`，且开头前`5`个字符是`nctf{`，最后一位字符是`}`。此外还能看到四个判断语句分别进入四个函数：

```c
bool __fastcall sub_400650(_DWORD *a1) // *a1 = v10 横坐标
{
  int v1; // eax

  v1 = (*a1)--;   // 横坐标-1,即左移
  return v1 > 0;
}

bool __fastcall sub_400660(int *a1) // *a1 = v10 横坐标
{
  int v1; // eax

  v1 = *a1 + 1;  //横坐标+1,即右移
  *a1 = v1;
  return v1 < 8;
}

bool __fastcall sub_400670(_DWORD *a1) // *a1 = v9 纵坐标
{
  int v1; // eax

  v1 = (*a1)--;  // 纵坐标-1,即上移
  return v1 > 0;
}

bool __fastcall sub_400680(int *a1) // *a1 = v9 纵坐标
{
  int v1; // eax

  v1 = *a1 + 1;  // 纵坐标+1,即下移
  *a1 = v1;
  return v1 < 8;
}
```

根据进入这四个函数的`if`语句判断条件，可以确定`O`: 左，`o`: 右，`.`: 上，`0`: 下。从上往下以此追踪，可以发现这些函数最终会跳到`lable15`处继续执行。对`lable15`进行分析，发现`asc_601060`中存储着特殊字符串。`asc_601060[8 * v9 + v10[0]] != 35`，即判断当前位置的字符是否为`#`，其中当前位置 = 8(迷宫横长) * 当前纵坐标 + 当前横坐标。编写`Python`代码来查看这个 `8×8` 的迷宫。

```python
maze = '  *******   *  **** * ****  * ***  *#  *** *** ***     *********'
g = ''
s = ''
for i in range(0, len(maze)):
    g += maze[i]
    if (i+1)%8==0:
        g += s + '\n'
        s = ''
print(g)
```

这个迷宫的字符图如下所示，迷宫的走法是：右下右右下下左下下下右右右右上上左左。根据`O`: 左，`o`: 右，`.`: 上，`0`: 下 来进行移动，可以得到`flag`：`nctf{o0oo00O000oooo..OO}`。

```
  ******
*   *  *
*** * **
**  * **
*  *#  *
** *** *
**     *
********
```

------

### [srm-50](https://adworld.xctf.org.cn/task/answer?type=reverse&number=4&grade=1&id=4963)

用 `file`查看`srm-50.exe`，可以看到信息`./srm-50.exe: PE32 executable (GUI) Intel 80386, for MS Windows`，用`IDA Pro 32bit`打开文件后，按`F5`反编译可以看到主函数的`C`语言代码如下：

```c
int __stdcall WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nShowCmd)
{
  return DialogBoxParamW(hInstance, (LPCWSTR)0x65, 0, DialogFunc, 0);
}
```

双击`DialogFunc`函数可以看到以下代码（对着ASCII数值按下R键即可转换成ASCII字符）：

```c
INT_PTR __stdcall DialogFunc(HWND hDlg, UINT a2, WPARAM a3, LPARAM a4)
{
  HMODULE v5; // eax
  HICON v6; // eax
  HMODULE v7; // eax
  HWND v8; // eax
  HCURSOR v9; // [esp-4h] [ebp-34Ch]
  CHAR String[256]; // [esp+8h] [ebp-340h] BYREF
  CHAR v11[256]; // [esp+108h] [ebp-240h] BYREF
  CHAR Text[256]; // [esp+208h] [ebp-140h] BYREF
  char Source[60]; // [esp+308h] [ebp-40h] BYREF

  if ( a2 == 16 )
  {
    EndDialog(hDlg, 0);
    return 0;
  }
  if ( a2 == 272 )
  {
    v5 = GetModuleHandleW(0);
    v6 = LoadIconW(v5, (LPCWSTR)0x67);
    SetClassLongA(hDlg, -14, (LONG)v6);
    v7 = GetModuleHandleW(0);
    v9 = LoadCursorW(v7, (LPCWSTR)0x66);
    v8 = GetDlgItem(hDlg, 1);
    SetClassLongA(v8, -12, (LONG)v9);
    return 1;
  }
  if ( a2 != 273 || (unsigned __int16)a3 != 1 )
    return 0;
  memset(String, (unsigned __int16)a3 - 1, sizeof(String));
  memset(v11, 0, sizeof(v11));
  memset(Text, 0, sizeof(Text));
  GetDlgItemTextA(hDlg, 1001, String, 256);
  GetDlgItemTextA(hDlg, 1002, v11, 256);
  if ( strstr(String, "@") && strstr(String, ".") && strstr(String, ".")[1] && strstr(String, "@")[1] != 46 )
  {
    strcpy(&Source[36], "Registration failure.");
    strcpy(Source, "Registration Success!\nYour flag is:");
    if ( strlen(v11) == 16
      && v11[0] == 'C'
      && v11[15] == 'X'
      && v11[1] == 'Z'
      && v11[14] == 'A'
      && v11[2] == '9'
      && v11[13] == 'b'
      && v11[3] == 'd'
      && v11[12] == '7'
      && v11[4] == 'm'
      && v11[11] == 'G'
      && v11[5] == 'q'
      && v11[10] == '9'
      && v11[6] == '4'
      && v11[9] == 'g'
      && v11[7] == 'c'
      && v11[8] == '8' )
    {
      strcpy_s(Text, 0x100u, Source);
      strcat_s(Text, 0x100u, v11);
    }
    else
    {
      strcpy_s(Text, 0x100u, &Source[36]);
    }
  }
  else
  {
    strcpy_s(Text, 0x100u, "Your E-mail address in not valid.");
  }
  MessageBoxA(hDlg, Text, "Registeration", 0x40u);
  return 1;
}
```

代码审计后发现`v11`中存储的值`CZ9dmq4c8g9G7bAX`就是本题的`flag`。

------

### [Mysterious](https://adworld.xctf.org.cn/task/answer?type=reverse&number=4&grade=1&id=5480)

用 `file`查看`Mysterious.exe`，可以看到信息`./Mysterious.exe: PE32 executable (GUI) Intel 80386, for MS Windows`，用`IDA Pro 32bit`打开文件后，按`F5`反编译可以看到主函数的`C`语言代码如下：

```c
// attributes: thunk
int __stdcall WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nShowCmd)
{
  return _WinMain@16_0(hInstance, hPrevInstance, lpCmdLine, nShowCmd);
}
```

双击`_WinMain@16_0`函数，可以看到以下代码：

```c
int __stdcall WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nShowCmd)
{
  DialogBoxParamA(hInstance, (LPCSTR)0x65, 0, DialogFunc, 0);
  return 0;
}
```

双击`DialogFunc`函数，可以看到以下代码：

```c
// attributes: thunk
INT_PTR __stdcall DialogFunc(HWND a1, UINT a2, WPARAM a3, LPARAM a4)
{
  return sub_401090(a1, a2, a3, a4);
}
```

再双击`sub_401090`函数，可以看到以下代码：

```c
int __stdcall sub_401090(HWND hWnd, int a2, int a3, int a4)
{
  int v4; // eax
  char Source[260]; // [esp+50h] [ebp-310h] BYREF
  CHAR Text[5]; // [esp+154h] [ebp-20Ch] BYREF
  char v8[252]; // [esp+159h] [ebp-207h] BYREF
  __int16 v9; // [esp+255h] [ebp-10Bh]
  char v10; // [esp+257h] [ebp-109h]
  int Value; // [esp+258h] [ebp-108h]
  CHAR String[260]; // [esp+25Ch] [ebp-104h] BYREF

  memset(String, 0, sizeof(String));
  Value = 0;
  if ( a2 == 16 )
  {
    DestroyWindow(hWnd);
    PostQuitMessage(0);
  }
  else if ( a2 == 273 )
  {
    if ( a3 == 1000 )
    {
      GetDlgItemTextA(hWnd, 1002, String, 260);
      strlen(String);
      if ( strlen(String) > 6 )
        ExitProcess(0);
      v4 = atoi(String);
      Value = v4 + 1;
      if ( v4 == 122 && String[3] == 120 && String[5] == 122 && String[4] == 121 )
      {
        strcpy(Text, "flag");
        memset(v8, 0, sizeof(v8));
        v9 = 0;
        v10 = 0;
        _itoa(Value, Source, 10);
        strcat(Text, "{");
        strcat(Text, Source);
        strcat(Text, "_");
        strcat(Text, "Buff3r_0v3rf|0w");
        strcat(Text, "}");
        MessageBoxA(0, Text, "well done", 0);
      }
      SetTimer(hWnd, 1u, 0x3E8u, TimerFunc);
    }
    if ( a3 == 1001 )
      KillTimer(hWnd, 1u);
  }
  return 0;
}
```

由那几个`strcat()`函数可知`flag`为`flag{ + Source + _Buff3r_0v3rf|0w}`，而`Source`是由`int`型变量`Value`经过`_itoa()`函数转换而来的，其中`Value = v4 + 1`，而由判断语句可知 `v4==122` 成立时才能执行 `if` 代码块中的内容，由此得知`Source = 123`，所以这题的`flag`是`flag{123_Buff3r_0v3rf|0w}`。

------

### [re4-unvm-me](https://adworld.xctf.org.cn/task/answer?type=reverse&number=4&grade=1&id=5033)

这道题的附件是一个`.pyc`文件，`.pyc`是一种二进制文件，是由`.py`文件经过编译后生成的文件，是一种`byte code`，`.py`文件变成`.pyc`文件后，运行加载的速度会有所提高，并且可以实现部分的源码隐藏，保证了`Python`做商业化软件时的安全性。

我们可以使用[**python-uncompyle6**](https://github.com/rocky/python-uncompyle6)来对`.pyc`文件进行反编译从而得到`.py`文件。

```bash
uncompyle6 -o . re4-unvm-me.pyc
```

打开反编译得到的`.py`文件可以看到以下`Python2.x`版本的源码：

```python
# uncompyle6 version 3.7.4
# Python bytecode 2.7 (62211)
# Decompiled from: Python 3.8.8 (default, Apr 13 2021, 15:08:03) [MSC v.1916 64 bit (AMD64)]
# Embedded file name: unvm_me.py
# Compiled at: 2016-12-21 05:44:01
import md5
md5s = [
 174282896860968005525213562254350376167, 137092044126081477479435678296496849608, 126300127609096051658061491018211963916, 314989972419727999226545215739316729360, 256525866025901597224592941642385934114, 115141138810151571209618282728408211053, 8705973470942652577929336993839061582, 256697681645515528548061291580728800189, 39818552652170274340851144295913091599, 65313561977812018046200997898904313350, 230909080238053318105407334248228870753, 196125799557195268866757688147870815374, 74874145132345503095307276614727915885]
print 'Can you turn me back to python ? ...'
flag = raw_input('well as you wish.. what is the flag: ')
if len(flag) > 69:
    print 'nice try'
    exit()
if len(flag) % 5 != 0:
    print 'nice try'
    exit()
for i in range(0, len(flag), 5):
    s = flag[i:i + 5]
    if int('0x' + md5.new(s).hexdigest(), 16) != md5s[(i / 5)]:
        print 'nice try'
        exit()

print 'Congratz now you have the flag'
```

这个程序是将传入的字符串分`5`个一组，使用`md5`函数加密后，将`16`进制转`10`进制，然后依次与`md5s`数组进行比较。

所以这题的求解思路是：`md5s`数组中的数据从`10`进制转换回`16`进制，再使用`md5`解密网站 https://www.cmd5.com/ 进行解密。

```
831daa3c843ba8b087c895f0ed305ce7
6722f7a07246c6af20662b855846c2c8
5f04850fec81a27ab5fc98befa4eb40c
ecf8dcac7503e63a6a3667c5fb94f610
c0fd15ae2c3931bc1e140523ae934722
569f606fd6da5d612f10cfb95c0bde6d
068cb5a1cf54c078bf0e7e89584c1a4e
c11e2cd82d1f9fbd7e4d6ee9581ff3bd
1df4c637d625313720f45706a48ff20f
3122ef3a001aaecdb8dd9d843c029e06
adb778a0f729293e7e0b19b96a4c5a61
938c747c6a051b3e163eb802a325148e
38543c5e820dd9403b57beff6020596d
```

将以上数据依次解密后可以连在一起就能得到`flag`：`ALEXCTF{dv5d4s2vj8nk43s8d8l6m1n5l67ds9v41n52nv37j481h3d28n4b6v3k}`。

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

