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

### [easyRE1](https://adworld.xctf.org.cn/task/answer?type=reverse&number=4&grade=1&id=5592)

将附件解压缩后得到两个文件：`easy-32`和`easy-64`。这都没必要`file`了，用`IDA Pro 32bit`打开文件`easy-32`后，按`F5`反编译可以看到主函数的`C`语言代码如下：

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char s[256]; // [esp+1Ch] [ebp-10Ch] BYREF
  unsigned int v5; // [esp+11Ch] [ebp-Ch]

  v5 = __readgsdword(0x14u);
  puts("What is the password?");
  gets(s);
  if ( !strcmp(s, "the password") )
    puts("FLAG:db2f62a36a018bce28e46d976e3f9864");
  else
    puts("Wrong!!");
  return 0;
}
```

显然`flag`就是`db2f62a36a018bce28e46d976e3f9864`可惜提交不对，提交`flag{db2f62a36a018bce28e46d976e3f9864}`过啦。

既然给了两个文件就再来看看`easy-64`吧，用`IDA Pro 64bit`打开文件`easy-64`后，按`F5`反编译可以看到主函数的`C`语言代码如下：

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char s1[264]; // [rsp+10h] [rbp-110h] BYREF
  unsigned __int64 v5; // [rsp+118h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  puts("What is the password?");
  gets(s1);
  if ( !strcmp(s1, "the password") )
    puts("FLAG:db2f62a36a018bce28e46d976e3f9864");
  else
    puts("Wrong!!");
  return 0;
}
```

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

![](https://paper.tanyaodan.com/ADWorld/reverse/5077/1.png)

`file ./simple-unpack`发现该文件是`64`位的，用`IDA Pro 64bit`以`ELF 64 for x86-64`形式打开文件后，按`F5`进行反编译可以看到以下源码：

![](https://paper.tanyaodan.com/ADWorld/reverse/5077/2.png)

双击`flag`即可得到`flag{Upx_1s_n0t_a_d3liv3r_c0mp4ny}`。

![](https://paper.tanyaodan.com/ADWorld/reverse/5077/3.png)

如果题目没有提示，不知道需要脱壳的话，也可以直接用`file`查看`.exe`文件发现是`ELF 64-bit LSB executable, x86-64`，用`IDA Pro 64bit`以二进制文件形式打开附件给出的`.exe`文件后按`shift + F12`查看`Strings window`可以发现`flag`：`flag{Upx_1s_n0t_a_d3liv3r_c0mp4ny}`。

------

### [logmein](https://adworld.xctf.org.cn/task/answer?type=reverse&number=4&grade=0&id=5078)

用`file`查看`.exe`文件发现是`ELF 64-bit LSB executable, x86-64`，用`IDA Pro 64bit`打开附件，按`F5`进行反编译可以看到以下源码：

![](https://paper.tanyaodan.com/ADWorld/reverse/5078/1.png)

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

`file`查看附件`game.exe`可以看到：`./game.exe: PE32 executable (console) Intel 80386, for MS Windows`。使用`IDA Pro 32bit`打开附件，按`F5`进行反编译可以看到以下源码：

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

`file`查看附件`./no-strings-attached`可以看到以下信息：

![](https://paper.tanyaodan.com/ADWorld/reverse/5080/1.png)

使用`IDA Pro 32bit`打开附件，按`F5`进行反编译可以看到以下源码：

![](https://paper.tanyaodan.com/ADWorld/reverse/5080/2.png)

第一个函数用于区域设置；第二个获取时间，搞了个随机数种子，还输出了欢迎语；第三个函数里只输出了句话让用户输入，都没啥用。双击`authenticate()`函数可以看到调用`decrypt()`函数的这行代码很关键，用户输入要和`s2`进行字符串比较，显然`s2`就是`flag`。

![](https://paper.tanyaodan.com/ADWorld/reverse/5080/3.png)

双击`decrypt()`函数可以看到源码如下：

![](https://paper.tanyaodan.com/ADWorld/reverse/5080/4.png)

查看汇编代码，发现`decrypt()` 函数执行结束后，会将一个结果放入内存中。

![](https://paper.tanyaodan.com/ADWorld/reverse/5080/5.png)

这就需要用`gdb`进行动态调试，在`decrypt()`函数处设置断点，执行完该函数后再执行一步来读取`$eax`寄存器中的内容，即可得到`flag`。

```bash
gdb ./no-strings-attached -q
b decrypt
r
n
x/sw $eax
```

`break/b` 可以设置断点，`gdb`可以直接根据已知函数名来对该函数设置断点，也可通过`*指定地址`下断点。 `run/r`可以运行程序，`next/n`表示单步步过，`s` 表示单步步入（如果此行代码中有函数调用，则进入该函数），` x` 指令表示查看寄存器内容，参数`/s`表示用字符串形式显示，`/w`表示四字节宽，因此`/sw` 表示以四字节宽来显示字符串。

![](https://paper.tanyaodan.com/ADWorld/reverse/5080/6.png)

本题的`flag`就是`9447{you_are_an_international_mystery}`。

------

### [csaw2013reversing2](https://adworld.xctf.org.cn/task/answer?type=reverse&number=4&grade=0&id=5081)

用 `file`查看附件`csaw2013reversing2.exe`，可以看到信息`./csaw2013reversing2.exe: PE32 executable (console) Intel 80386, for MS Windows`。用`IDA Pro 32bit`打开文件后，按`F5`反编译可以看到主函数的`C`语言代码如下：

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

![](https://paper.tanyaodan.com/ADWorld/reverse/5081/1.png)

所以解题思路就是让程序跳转到 `loc_401096` 进行解码， 将`int3` 改成 `nop(0x90)`，再跳转到 `loc_4010B9` 输出弹窗。而不是直接执行`loc_4010B9`输出含有乱码的弹窗。

使用`ollydbg`打开`csaw2013reversing2.exe`，将`0040109A`这条`int 3`语句前的`je short csaw2013.00BF10B9`修改为`je short csaw2013.00BF1096`。![](https://paper.tanyaodan.com/ADWorld/reverse/5081/2.png)

将`int3` 这个断点中断改成 `nop(0x90)`。

![](https://paper.tanyaodan.com/ADWorld/reverse/5081/3.png)

再将后面的那条`je short csaw2013.00BF10EF`修改为`je short csaw2013.00BF10B9`。

![](https://paper.tanyaodan.com/ADWorld/reverse/5081/4.png)

`run`执行程序即可输出包含`flag`的无码弹窗，从而得到`flag`：`flag{reversing_is_not_that_hard!}`。

![](https://paper.tanyaodan.com/ADWorld/reverse/5081/5.png)

------

### [getit](https://adworld.xctf.org.cn/task/answer?type=reverse&number=4&grade=0&id=5082)

用 `file`查看附件`getit`，可以看到信息`./getit: ELF 64-bit LSB executable, x86-64`，用`IDA Pro 64bit`打开文件后，按`F5`反编译可以看到主函数的`C`语言代码如下：

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

![](https://paper.tanyaodan.com/ADWorld/reverse/5082/1.png)

`vim ~/.gdbinit`然后取消`#source /home/tyd/ctf/gdb/pwndbg/gdbinit.py`前的`#`注释以启用`pwndbg`。接着使用`pwndbg`来动态调试程序，`b *0x400832`在地址`0x400832`处设置断点，`r/run`运行程序，可以直接看到每个寄存器中存储的数值信息，而`$rdx`寄存器中存放着`flag`：`SharifCTF{b70c59275fcfa8aebf2d5911223c6589}`。

![](https://paper.tanyaodan.com/ADWorld/reverse/5082/2.png)

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

用 `file`查看附件`maze`，可以看到信息`./maze: ELF 64-bit LSB executable, x86-64`，用`IDA Pro 64bit`打开文件后，按`F5`反编译可以看到主函数的`C`语言代码如下：	

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

用 `file`查看附件`srm-50.exe`，可以看到信息`./srm-50.exe: PE32 executable (GUI) Intel 80386, for MS Windows`，用`IDA Pro 32bit`打开文件后，按`F5`反编译可以看到主函数的`C`语言代码如下：

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

用 `file`查看附件`Mysterious.exe`，可以看到信息`./Mysterious.exe: PE32 executable (GUI) Intel 80386, for MS Windows`，用`IDA Pro 32bit`打开文件后，按`F5`反编译可以看到主函数的`C`语言代码如下：

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

### [流浪者](https://adworld.xctf.org.cn/task/answer?type=reverse&number=4&grade=1&id=5570)

用 `file`查看附件`Mysterious.exe`，可以看到信息`./cm.exe: PE32 executable (GUI) Intel 80386, for MS Windows`，用`IDA Pro 32bit`打开文件后，按`F5`反编译可以看到主函数的`C`语言代码如下：

```c
int __stdcall WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nShowCmd)
{
  return AfxWinMain(hInstance, hPrevInstance, lpCmdLine, nShowCmd);
}
```

双击`AfxWinMain()`函数可以看到以下代码：

```c
// attributes: thunk
int __stdcall AfxWinMain(HINSTANCE a1, HINSTANCE a2, char *a3, int a4)
{
  return __imp_?AfxWinMain@@YGHPAUHINSTANCE__@@0PADH@Z(a1, a2, a3, a4);
}
```

无从下手，使用`shift+F12`查看`Strings window`可以看到特殊字符串`请输入pass!`，根据它能定位到`sub_401890()`函数，这个函数是对用户输入进行处理。注意到最后的`sub_4017F0()`函数。

```c
int __thiscall sub_401890(CWnd *this)
{
  CWnd *v1; // eax
  int v2; // eax
  struct CString *v4; // [esp-4h] [ebp-C4h]
  int v5[26]; // [esp+4Ch] [ebp-74h] BYREF
  int i; // [esp+B4h] [ebp-Ch]
  char *Str; // [esp+B8h] [ebp-8h]
  CWnd *v8; // [esp+BCh] [ebp-4h]

  v8 = this;
  v4 = (CWnd *)((char *)this + 100);
  v1 = CWnd::GetDlgItem(this, 1002);
  CWnd::GetWindowTextA(v1, v4);  // 读取用户输入并保存到v1
  v2 = sub_401A30((char *)v8 + 100);
  Str = CString::GetBuffer((CWnd *)((char *)v8 + 100), v2);
  if ( !strlen(Str) )
    return CWnd::MessageBoxA(v8, "请输入pass!", 0, 0);
  for ( i = 0; Str[i]; ++i )
  {
    if ( Str[i] > 57 || Str[i] < 48 )
    {
      if ( Str[i] > 122 || Str[i] < 97 )
      {
        if ( Str[i] > 90 || Str[i] < 65 )
          sub_4017B0();
        else
          v5[i] = Str[i] - 29;
      }
      else
      {
        v5[i] = Str[i] - 87;
      }
    }
    else
    {
      v5[i] = Str[i] - 48;
    }
  }
  return sub_4017F0(v5);
}
```

双击`sub_4017F0()`函数查看源码：

```c
int __cdecl sub_4017F0(int a1)
{
  int result; // eax
  char Str1[28]; // [esp+D8h] [ebp-24h] BYREF
  int v3; // [esp+F4h] [ebp-8h]
  int v4; // [esp+F8h] [ebp-4h]

  v4 = 0;
  v3 = 0;
  while ( *(int *)(a1 + 4 * v4) < 62 && *(int *)(a1 + 4 * v4) >= 0 )
  {
    Str1[v4] = aAbcdefghiabcde[*(_DWORD *)(a1 + 4 * v4)]; 
    //'abcdefghiABCDEFGHIJKLMNjklmn0123456789opqrstuvwxyzOPQRSTUVWXYZ'
    ++v4;
  }
  Str1[v4] = 0;
  if ( !strcmp(Str1, "KanXueCTF2019JustForhappy") )
    result = sub_401770();
  else
    result = sub_4017B0();
  return result;
}
```

该函数能判断传入的参数是否与字符串`KanXueCTF2019JustForhappy`相等，如果相等的话执行`sub_401770()`函数，不相等的话执行`sub_4017B0()`函数。

```c
BOOL sub_401770()
{
  HANDLE hProcess; // [esp+4Ch] [ebp-4h]

  MessageBoxA(0, "pass!", "恭喜!", 0);
  hProcess = GetCurrentProcess();
  return TerminateProcess(hProcess, 0);
}

BOOL sub_4017B0()
{
  HANDLE hProcess; // [esp+4Ch] [ebp-4h]

  MessageBoxA(0, "加油!", "错了!", 0);
  hProcess = GetCurrentProcess();
  return TerminateProcess(hProcess, 0);
}
```

编写`Python`代码逆推回去，即可得到`flag{j0rXI4bTeustBiIGHeCF70DDM}`。

```python
src = 'abcdefghiABCDEFGHIJKLMNjklmn0123456789opqrstuvwxyzOPQRSTUVWXYZ'
dst = 'KanXueCTF2019JustForhappy'
v5 = []
for x in dst:
    v5.append(src.index(x))
# v5 = [19, 0, 27, 59, 44, 4, 11, 55, 14, 30, 28, 29, 37, 18, 44, 42, 43, 14, 38, 41, 7, 0, 39, 39, 48]

flag = ''
for x in v5:
    t = chr(x+29)
    if 'A' <= t <= 'Z':
        flag += t
    t = chr(x+87)
    if 'a' <= t <= 'z':
        flag += t
    t = chr(x+48)
    if '0' <= t <= '9':
        flag += t
print(f'flag{{{flag}}}') # flag{j0rXI4bTeustBiIGHeCF70DDM}
```

------

### [666](https://adworld.xctf.org.cn/task/answer?type=reverse&number=4&grade=1&id=5573)

用 `file`查看附件`666`，可以看到信息`./666: ELF 64-bit LSB pie executable, x86-64`，用`IDA Pro 64bit`打开文件后，按`F5`反编译可以看到主函数的`C`语言代码如下：

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char s[240]; // [rsp+0h] [rbp-1E0h] BYREF
  char v5[240]; // [rsp+F0h] [rbp-F0h] BYREF

  memset(s, 0, 0x1EuLL);
  printf("Please Input Key: ");
  __isoc99_scanf("%s", v5);
  encode(v5, s);
  if ( strlen(v5) == key )
  {
    if ( !strcmp(s, enflag) )
      puts("You are Right");
    else
      puts("flag{This_1s_f4cker_flag}");
  }
  return 0;
}
```

双击`encode()`函数可以看到以下源码：

```c
int __fastcall encode(const char *a1, __int64 a2)  // a1 = v5, a2 = s
{
  char v3[104]; // [rsp+10h] [rbp-70h]
  int v4; // [rsp+78h] [rbp-8h]
  int i; // [rsp+7Ch] [rbp-4h]

  i = 0;
  v4 = 0;
  if ( strlen(a1) != key )
    return puts("Your Length is Wrong");
  for ( i = 0; i < key; i += 3 )
  {
    v3[i + 64] = key ^ (a1[i] + 6);
    v3[i + 33] = (a1[i + 1] - 6) ^ key;
    v3[i + 2] = a1[i + 2] ^ 6 ^ key;
    *(_BYTE *)(a2 + i) = v3[i + 64];
    *(_BYTE *)(a2 + i + 1LL) = v3[i + 33];
    *(_BYTE *)(a2 + i + 2LL) = v3[i + 2];
  }
  return a2;  // s,且s=enflag
}
```

编写`Python`代码逆推回去，即可得到`flag`:`unctf{b66_6b6_66b}`。

```python
enflag = 'izwhroz""w"v.K".Ni'
key = len(enflag)
flag = ''
for i in range(0, key, 3):
    flag += chr((key^ord(enflag[i]))-6)
    flag += chr((key^ord(enflag[i+1]))+6)
    flag += chr(key^ord(enflag[i+2])^6)
print(flag) # unctf{b66_6b6_66b}
```

------

### [Reversing-x64Elf-100](https://adworld.xctf.org.cn/task/answer?type=reverse&number=4&grade=1&id=4826)

用 `file`查看附件`Reversing-x64Elf-100.re`，可以看到`./Reversing-x64Elf-100.re: ELF 64-bit LSB executable, x86-64`，用`IDA Pro 64bit`打开文件后，按`F5`反编译可以看到主函数的`C`语言代码如下：

```c
__int64 __fastcall main(int a1, char **a2, char **a3)
{
  __int64 result; // rax
  char s[264]; // [rsp+0h] [rbp-110h] BYREF
  unsigned __int64 v5; // [rsp+108h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  printf("Enter the password: ");
  if ( !fgets(s, 255, stdin) )
    return 0LL;
  if ( (unsigned int)sub_4006FD(s) )
  {
    puts("Incorrect password!");
    result = 1LL;
  }
  else
  {
    puts("Nice!");
    result = 0LL;
  }
  return result;
}
```

注意到字符串`"Incorrect password!"`，双击进入`sub_4006FD()`函数可以看到以下源代码：

```c
__int64 __fastcall sub_4006FD(__int64 a1)
{
  int i; // [rsp+14h] [rbp-24h]
  __int64 v3[4]; // [rsp+18h] [rbp-20h]

  v3[0] = (__int64)"Dufhbmf";
  v3[1] = (__int64)"pG`imos";
  v3[2] = (__int64)"ewUglpt";
  for ( i = 0; i <= 11; ++i )
  {
    if ( *(char *)(v3[i % 3] + 2 * (i / 3)) - *(char *)(i + a1) != 1 )
      return 1LL;
  }
  return 0LL;
}
```

根据代码逻辑，编写`Python`代码可以得到`flag`: `Code_Talkers`。

```python
s = ['Dufhbmf', 'pG`imos', 'ewUglpt']
flag = ''
for i in range(12):
    flag += chr(ord(s[i%3][2*int(i/3)])-1)
print(flag) # Code_Talkers
```

------

### [Guess-the-Number](https://adworld.xctf.org.cn/task/answer?type=reverse&number=4&grade=1&id=4908)

将附件`Guess-the-Number.jar`解压后可以得到`guess.class`，使用`Java`反编译工具`jd-gui`打开后可以看到以下源代码：

```java
import java.io.PrintStream;
import java.math.BigInteger;

public class guess
{
  static String XOR(String _str_one, String _str_two)
  {
    BigInteger i1 = new BigInteger(_str_one, 16);
    BigInteger i2 = new BigInteger(_str_two, 16);
    BigInteger res = i1.xor(i2);
    String result = res.toString(16);
    return result;
  }
  
  public static void main(String[] args)
  {
    int guess_number = 0;
    int my_num = 349763335;
    int my_number = 1545686892;
    int flag = 345736730;
    if (args.length > 0)
    {
      try
      {
        guess_number = Integer.parseInt(args[0]);
        if (my_number / 5 == guess_number)
        {
          String str_one = "4b64ca12ace755516c178f72d05d7061";
          String str_two = "ecd44646cfe5994ebeb35bf922e25dba";
          my_num += flag;
          String answer = XOR(str_one, str_two);
          
          System.out.println("your flag is: " + answer);
        }
        else
        {
          System.err.println("wrong guess!");
          System.exit(1);
        }
      }
      catch (NumberFormatException e)
      {
        System.err.println("please enter an integer \nexample: java -jar guess 12");
        System.exit(1);
      }
    }
    else
    {
      System.err.println("wrong guess!");
      int num = 1000000;
      num++;
      System.exit(1);
    }
  }
}
```

代码审计完后，根据代码逻辑编写`guess.java`，`java guess.java`运行后即可得到`flag`: `a7b08c546302cc1fd2a4d48bf2bf2ddb`。

```java
import java.io.PrintStream;
import java.math.BigInteger;

public class guess
{  
  static String XOR(String _str_one, String _str_two)
  {
    BigInteger i1 = new BigInteger(_str_one, 16);
    BigInteger i2 = new BigInteger(_str_two, 16);
    BigInteger res = i1.xor(i2);
    String result = res.toString(16);
    return result;
  }
  public static void main(String[] args)
  {
    String str_one = "4b64ca12ace755516c178f72d05d7061";
    String str_two = "ecd44646cfe5994ebeb35bf922e25dba";
    String answer = XOR(str_one, str_two);
    System.out.println("your flag is: " + answer);
  }
}
```

------

### [BABYRE](https://adworld.xctf.org.cn/task/answer?type=reverse&number=4&grade=1&id=4662)

用 `file`查看附件`BABYRE`，可以看到信息`./BABYRE: ELF 64-bit LSB executable, x86-64`，用`IDA Pro 32bit`打开文件后，按`F5`反编译可以看到主函数的`C`语言代码如下：

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char s[24]; // [rsp+0h] [rbp-20h] BYREF
  int v5; // [rsp+18h] [rbp-8h]
  int i; // [rsp+1Ch] [rbp-4h]

  for ( i = 0; i <= 181; ++i )
    judge[i] ^= 0xCu;
  printf("Please input flag:");
  __isoc99_scanf("%20s", s);
  v5 = strlen(s);
  if ( v5 == 14 && (*(unsigned int (__fastcall **)(char *))judge)(s) )
    puts("Right!");
  else
    puts("Wrong!");
  return 0;
}
```

双击`judge`查看不了`C`语言源码，只能跳转到`.data`数据区，审计主函数后发现原来是因为这个函数在内存中的数据被异或操作加密啦。

```assembly
.data:0000000000600B00                 public judge
.data:0000000000600B00 ; char judge[182]
.data:0000000000600B00 judge           db 59h                  ; CODE XREF: main+80↑p
.data:0000000000600B00                                         ; DATA XREF: main+16↑r ...
.data:0000000000600B01                 db  44h ; D
.data:0000000000600B02                 db  85h
.data:0000000000600B03                 db 0E9h
.data:0000000000600B04                 db  44h ; D
.data:0000000000600B05                 db  85h
.data:0000000000600B06                 db  71h ; q
.data:0000000000600B07                 db 0D4h
.data:0000000000600B08                 db 0CAh
.data:0000000000600B09                 db  49h ; I
.data:0000000000600B0A                 db 0ECh
.data:0000000000600B0B                 db  6Ah ; j
.data:0000000000600B0C                 db 0CAh
.data:0000000000600B0D                 db  49h ; I
.data:0000000000600B0E                 db 0EDh
.data:0000000000600B0F                 db  61h ; a
.data:0000000000600B10                 db 0CAh
.data:0000000000600B11                 db  49h ; I
.data:0000000000600B12                 db 0EEh
.data:0000000000600B13                 db  6Fh ; o
.data:0000000000600B14                 db 0CAh
.data:0000000000600B15                 db  49h ; I
.data:0000000000600B16                 db 0EFh
.data:0000000000600B17                 db  68h ; h
.data:0000000000600B18                 db 0CAh
.data:0000000000600B19                 db  49h ; I
.data:0000000000600B1A                 db 0E8h
.data:0000000000600B1B                 db  73h ; s
.data:0000000000600B1C                 db 0CAh
.data:0000000000600B1D                 db  49h ; I
.data:0000000000600B1E                 db 0E9h
.data:0000000000600B1F                 db  67h ; g
.data:0000000000600B20                 db 0CAh
.data:0000000000600B21                 db  49h ; I
.data:0000000000600B22                 db 0EAh
.data:0000000000600B23                 db  3Bh ; ;
.data:0000000000600B24                 db 0CAh
.data:0000000000600B25                 db  49h ; I
.data:0000000000600B26                 db 0EBh
.data:0000000000600B27                 db  68h ; h
.data:0000000000600B28                 db 0CAh
.data:0000000000600B29                 db  49h ; I
.data:0000000000600B2A                 db 0E4h
.data:0000000000600B2B                 db  37h ; 7
.data:0000000000600B2C                 db 0CAh
.data:0000000000600B2D                 db  49h ; I
.data:0000000000600B2E                 db 0E5h
.data:0000000000600B2F                 db  5Ah ; Z
.data:0000000000600B30                 db 0CAh
.data:0000000000600B31                 db  49h ; I
.data:0000000000600B32                 db 0E6h
.data:0000000000600B33                 db  6Ch ; l
.data:0000000000600B34                 db 0CAh
.data:0000000000600B35                 db  49h ; I
.data:0000000000600B36                 db 0E7h
.data:0000000000600B37                 db  37h ; 7
.data:0000000000600B38                 db 0CAh
.data:0000000000600B39                 db  49h ; I
.data:0000000000600B3A                 db 0E0h
.data:0000000000600B3B                 db  62h ; b
.data:0000000000600B3C                 db 0CAh
.data:0000000000600B3D                 db  49h ; I
.data:0000000000600B3E                 db 0E1h
.data:0000000000600B3F                 db  7Ch ; |
.data:0000000000600B40                 db 0CBh
.data:0000000000600B41                 db  49h ; I
.data:0000000000600B42                 db 0F0h
.data:0000000000600B43                 db  0Ch
.data:0000000000600B44                 db  0Ch
.data:0000000000600B45                 db  0Ch
.data:0000000000600B46                 db  0Ch
.data:0000000000600B47                 db 0E7h
.data:0000000000600B48                 db  24h ; $
.data:0000000000600B49                 db  87h
.data:0000000000600B4A                 db  49h ; I
.data:0000000000600B4B                 db 0F0h
.data:0000000000600B4C                 db  44h ; D
.data:0000000000600B4D                 db  6Fh ; o
.data:0000000000600B4E                 db 0DCh
.data:0000000000600B4F                 db  44h ; D
.data:0000000000600B50                 db  87h
.data:0000000000600B51                 db  49h ; I
.data:0000000000600B52                 db 0D4h
.data:0000000000600B53                 db  44h ; D
.data:0000000000600B54                 db  0Dh
.data:0000000000600B55                 db 0DCh
.data:0000000000600B56                 db  87h
.data:0000000000600B57                 db  59h ; Y
.data:0000000000600B58                 db 0F0h
.data:0000000000600B59                 db  44h ; D
.data:0000000000600B5A                 db  6Fh ; o
.data:0000000000600B5B                 db 0C6h
.data:0000000000600B5C                 db  44h ; D
.data:0000000000600B5D                 db  87h
.data:0000000000600B5E                 db  59h ; Y
.data:0000000000600B5F                 db 0D4h
.data:0000000000600B60                 db  44h ; D
.data:0000000000600B61                 db  0Dh
.data:0000000000600B62                 db 0C6h
.data:0000000000600B63                 db    3
.data:0000000000600B64                 db 0BAh
.data:0000000000600B65                 db  1Eh
.data:0000000000600B66                 db  87h
.data:0000000000600B67                 db  41h ; A
.data:0000000000600B68                 db 0F0h
.data:0000000000600B69                 db  3Dh ; =
.data:0000000000600B6A                 db 0C6h
.data:0000000000600B6B                 db  84h
.data:0000000000600B6C                 db  1Ch
.data:0000000000600B6D                 db  8Fh
.data:0000000000600B6E                 db  49h ; I
.data:0000000000600B6F                 db 0F0h
.data:0000000000600B70                 db  0Dh
.data:0000000000600B71                 db  8Fh
.data:0000000000600B72                 db  71h ; q
.data:0000000000600B73                 db 0F0h
.data:0000000000600B74                 db    1
.data:0000000000600B75                 db  72h ; r
.data:0000000000600B76                 db 0DEh
.data:0000000000600B77                 db 0CBh
.data:0000000000600B78                 db  49h ; I
.data:0000000000600B79                 db 0F0h
.data:0000000000600B7A                 db  0Ch
.data:0000000000600B7B                 db  0Ch
.data:0000000000600B7C                 db  0Ch
.data:0000000000600B7D                 db  0Ch
.data:0000000000600B7E                 db 0E7h
.data:0000000000600B7F                 db  25h ; %
.data:0000000000600B80                 db  87h
.data:0000000000600B81                 db  49h ; I
.data:0000000000600B82                 db 0F0h
.data:0000000000600B83                 db  44h ; D
.data:0000000000600B84                 db  6Fh ; o
.data:0000000000600B85                 db 0DCh
.data:0000000000600B86                 db  44h ; D
.data:0000000000600B87                 db  87h
.data:0000000000600B88                 db  49h ; I
.data:0000000000600B89                 db 0D4h
.data:0000000000600B8A                 db  44h ; D
.data:0000000000600B8B                 db  0Dh
.data:0000000000600B8C                 db 0DCh
.data:0000000000600B8D                 db    3
.data:0000000000600B8E                 db 0BAh
.data:0000000000600B8F                 db  1Ch
.data:0000000000600B90                 db  87h
.data:0000000000600B91                 db  49h ; I
.data:0000000000600B92                 db 0F0h
.data:0000000000600B93                 db  44h ; D
.data:0000000000600B94                 db  94h
.data:0000000000600B95                 db    3
.data:0000000000600B96                 db 0BAh
.data:0000000000600B97                 db  48h ; H
.data:0000000000600B98                 db    9
.data:0000000000600B99                 db 0ECh
.data:0000000000600B9A                 db  34h ; 4
.data:0000000000600B9B                 db 0CEh
.data:0000000000600B9C                 db  78h ; x
.data:0000000000600B9D                 db  0Bh
.data:0000000000600B9E                 db 0B4h
.data:0000000000600B9F                 db  0Ch
.data:0000000000600BA0                 db  0Ch
.data:0000000000600BA1                 db  0Ch
.data:0000000000600BA2                 db  0Ch
.data:0000000000600BA3                 db 0E7h
.data:0000000000600BA4                 db    3
.data:0000000000600BA5                 db  8Fh
.data:0000000000600BA6                 db  49h ; I
.data:0000000000600BA7                 db 0F0h
.data:0000000000600BA8                 db  0Dh
.data:0000000000600BA9                 db  8Fh
.data:0000000000600BAA                 db  71h ; q
.data:0000000000600BAB                 db 0F0h
.data:0000000000600BAC                 db    1
.data:0000000000600BAD                 db  72h ; r
.data:0000000000600BAE                 db 0DDh
.data:0000000000600BAF                 db 0B4h
.data:0000000000600BB0                 db  0Dh
.data:0000000000600BB1                 db  0Ch
.data:0000000000600BB2                 db  0Ch
.data:0000000000600BB3                 db  0Ch
.data:0000000000600BB4                 db  51h ; Q
.data:0000000000600BB5                 db 0CFh
.data:0000000000600BB5 _data           ends
```

我们可以用`IDA Pro`中的`IDC`工具编写脚本对这段汇编语言数据进行解密，编写以下代码保存为`patchDecrypt.idc`。

```c
#include <idc.idc>
// from 是起始地址
// size 是偏移地址
// key 是操作
static decrypt(from, size, key) {
auto i;
  for (i = 0; i < size; i++) {
    PatchByte(from + i, Byte(from + i) ^ key);
  }
}
```

在`IDA Pro`的菜单栏`File → Script File`导入脚本`patchDecrypt.idc`，在最下面的`Output window`中选择`IDC`输入以下命令：

```c
decrypt(0x600B00,182,0xC);
```

`IDA Pro`执行后，可以看到`0x600B00`到`0x600BB5`的`.data`数据发生了改变，具体数据如下：

```assembly
.data:0000000000600B00                 public judge
.data:0000000000600B00 ; char judge[182]
.data:0000000000600B00 judge           db 55h                  ; CODE XREF: main+80↑p
.data:0000000000600B00                                         ; DATA XREF: main+16↑r ...
.data:0000000000600B01                 db  48h ; H
.data:0000000000600B02                 db  89h
.data:0000000000600B03                 db 0E5h
.data:0000000000600B04                 db  48h ; H
.data:0000000000600B05                 db  89h
.data:0000000000600B06                 db  7Dh ; }
.data:0000000000600B07                 db 0D8h
.data:0000000000600B08                 db 0C6h
.data:0000000000600B09                 db  45h ; E
.data:0000000000600B0A                 db 0E0h
.data:0000000000600B0B                 db  66h ; f
.data:0000000000600B0C                 db 0C6h
.data:0000000000600B0D                 db  45h ; E
.data:0000000000600B0E                 db 0E1h
.data:0000000000600B0F                 db  6Dh ; m
.data:0000000000600B10                 db 0C6h
.data:0000000000600B11                 db  45h ; E
.data:0000000000600B12                 db 0E2h
.data:0000000000600B13                 db  63h ; c
.data:0000000000600B14                 db 0C6h
.data:0000000000600B15                 db  45h ; E
.data:0000000000600B16                 db 0E3h
.data:0000000000600B17                 db  64h ; d
.data:0000000000600B18                 db 0C6h
.data:0000000000600B19                 db  45h ; E
.data:0000000000600B1A                 db 0E4h
.data:0000000000600B1B                 db  7Fh ; 
.data:0000000000600B1C                 db 0C6h
.data:0000000000600B1D                 db  45h ; E
.data:0000000000600B1E                 db 0E5h
.data:0000000000600B1F                 db  6Bh ; k
.data:0000000000600B20                 db 0C6h
.data:0000000000600B21                 db  45h ; E
.data:0000000000600B22                 db 0E6h
.data:0000000000600B23                 db  37h ; 7
.data:0000000000600B24                 db 0C6h
.data:0000000000600B25                 db  45h ; E
.data:0000000000600B26                 db 0E7h
.data:0000000000600B27                 db  64h ; d
.data:0000000000600B28                 db 0C6h
.data:0000000000600B29                 db  45h ; E
.data:0000000000600B2A                 db 0E8h
.data:0000000000600B2B                 db  3Bh ; ;
.data:0000000000600B2C                 db 0C6h
.data:0000000000600B2D                 db  45h ; E
.data:0000000000600B2E                 db 0E9h
.data:0000000000600B2F                 db  56h ; V
.data:0000000000600B30                 db 0C6h
.data:0000000000600B31                 db  45h ; E
.data:0000000000600B32                 db 0EAh
.data:0000000000600B33                 db  60h ; `
.data:0000000000600B34                 db 0C6h
.data:0000000000600B35                 db  45h ; E
.data:0000000000600B36                 db 0EBh
.data:0000000000600B37                 db  3Bh ; ;
.data:0000000000600B38                 db 0C6h
.data:0000000000600B39                 db  45h ; E
.data:0000000000600B3A                 db 0ECh
.data:0000000000600B3B                 db  6Eh ; n
.data:0000000000600B3C                 db 0C6h
.data:0000000000600B3D                 db  45h ; E
.data:0000000000600B3E                 db 0EDh
.data:0000000000600B3F                 db  70h ; p
.data:0000000000600B40                 db 0C7h
.data:0000000000600B41                 db  45h ; E
.data:0000000000600B42                 db 0FCh
.data:0000000000600B43                 db    0
.data:0000000000600B44                 db    0
.data:0000000000600B45                 db    0
.data:0000000000600B46                 db    0
.data:0000000000600B47                 db 0EBh
.data:0000000000600B48                 db  28h ; (
.data:0000000000600B49                 db  8Bh
.data:0000000000600B4A                 db  45h ; E
.data:0000000000600B4B                 db 0FCh
.data:0000000000600B4C                 db  48h ; H
.data:0000000000600B4D                 db  63h ; c
.data:0000000000600B4E                 db 0D0h
.data:0000000000600B4F                 db  48h ; H
.data:0000000000600B50                 db  8Bh
.data:0000000000600B51                 db  45h ; E
.data:0000000000600B52                 db 0D8h
.data:0000000000600B53                 db  48h ; H
.data:0000000000600B54                 db    1
.data:0000000000600B55                 db 0D0h
.data:0000000000600B56                 db  8Bh
.data:0000000000600B57                 db  55h ; U
.data:0000000000600B58                 db 0FCh
.data:0000000000600B59                 db  48h ; H
.data:0000000000600B5A                 db  63h ; c
.data:0000000000600B5B                 db 0CAh
.data:0000000000600B5C                 db  48h ; H
.data:0000000000600B5D                 db  8Bh
.data:0000000000600B5E                 db  55h ; U
.data:0000000000600B5F                 db 0D8h
.data:0000000000600B60                 db  48h ; H
.data:0000000000600B61                 db    1
.data:0000000000600B62                 db 0CAh
.data:0000000000600B63                 db  0Fh
.data:0000000000600B64                 db 0B6h
.data:0000000000600B65                 db  12h
.data:0000000000600B66                 db  8Bh
.data:0000000000600B67                 db  4Dh ; M
.data:0000000000600B68                 db 0FCh
.data:0000000000600B69                 db  31h ; 1
.data:0000000000600B6A                 db 0CAh
.data:0000000000600B6B                 db  88h
.data:0000000000600B6C                 db  10h
.data:0000000000600B6D                 db  83h
.data:0000000000600B6E                 db  45h ; E
.data:0000000000600B6F                 db 0FCh
.data:0000000000600B70                 db    1
.data:0000000000600B71                 db  83h
.data:0000000000600B72                 db  7Dh ; }
.data:0000000000600B73                 db 0FCh
.data:0000000000600B74                 db  0Dh
.data:0000000000600B75                 db  7Eh ; ~
.data:0000000000600B76                 db 0D2h
.data:0000000000600B77                 db 0C7h
.data:0000000000600B78                 db  45h ; E
.data:0000000000600B79                 db 0FCh
.data:0000000000600B7A                 db    0
.data:0000000000600B7B                 db    0
.data:0000000000600B7C                 db    0
.data:0000000000600B7D                 db    0
.data:0000000000600B7E                 db 0EBh
.data:0000000000600B7F                 db  29h ; )
.data:0000000000600B80                 db  8Bh
.data:0000000000600B81                 db  45h ; E
.data:0000000000600B82                 db 0FCh
.data:0000000000600B83                 db  48h ; H
.data:0000000000600B84                 db  63h ; c
.data:0000000000600B85                 db 0D0h
.data:0000000000600B86                 db  48h ; H
.data:0000000000600B87                 db  8Bh
.data:0000000000600B88                 db  45h ; E
.data:0000000000600B89                 db 0D8h
.data:0000000000600B8A                 db  48h ; H
.data:0000000000600B8B                 db    1
.data:0000000000600B8C                 db 0D0h
.data:0000000000600B8D                 db  0Fh
.data:0000000000600B8E                 db 0B6h
.data:0000000000600B8F                 db  10h
.data:0000000000600B90                 db  8Bh
.data:0000000000600B91                 db  45h ; E
.data:0000000000600B92                 db 0FCh
.data:0000000000600B93                 db  48h ; H
.data:0000000000600B94                 db  98h
.data:0000000000600B95                 db  0Fh
.data:0000000000600B96                 db 0B6h
.data:0000000000600B97                 db  44h ; D
.data:0000000000600B98                 db    5
.data:0000000000600B99                 db 0E0h
.data:0000000000600B9A                 db  38h ; 8
.data:0000000000600B9B                 db 0C2h
.data:0000000000600B9C                 db  74h ; t
.data:0000000000600B9D                 db    7
.data:0000000000600B9E                 db 0B8h
.data:0000000000600B9F                 db    0
.data:0000000000600BA0                 db    0
.data:0000000000600BA1                 db    0
.data:0000000000600BA2                 db    0
.data:0000000000600BA3                 db 0EBh
.data:0000000000600BA4                 db  0Fh
.data:0000000000600BA5                 db  83h
.data:0000000000600BA6                 db  45h ; E
.data:0000000000600BA7                 db 0FCh
.data:0000000000600BA8                 db    1
.data:0000000000600BA9                 db  83h
.data:0000000000600BAA                 db  7Dh ; }
.data:0000000000600BAB                 db 0FCh
.data:0000000000600BAC                 db  0Dh
.data:0000000000600BAD                 db  7Eh ; ~
.data:0000000000600BAE                 db 0D1h
.data:0000000000600BAF                 db 0B8h
.data:0000000000600BB0                 db    1
.data:0000000000600BB1                 db    0
.data:0000000000600BB2                 db    0
.data:0000000000600BB3                 db    0
.data:0000000000600BB4                 db  5Dh ; ]
.data:0000000000600BB5                 db 0C3h
.data:0000000000600BB5 _data           ends
```

鼠标选中`public judge`处，再按`C`生成新的汇编语言代码：

```assembly
.data:0000000000600B00 ; char judge[182]
.data:0000000000600B00                 public judge
.data:0000000000600B00 judge:                                  ; CODE XREF: main+80↑p
.data:0000000000600B00                                         ; DATA XREF: main+16↑r ...
.data:0000000000600B00                 push    rbp
.data:0000000000600B01                 mov     rbp, rsp
.data:0000000000600B04                 mov     [rbp-28h], rdi
.data:0000000000600B08                 mov     byte ptr [rbp-20h], 66h ; 'f'
.data:0000000000600B0C                 mov     byte ptr [rbp-1Fh], 6Dh ; 'm'
.data:0000000000600B10                 mov     byte ptr [rbp-1Eh], 63h ; 'c'
.data:0000000000600B14                 mov     byte ptr [rbp-1Dh], 64h ; 'd'
.data:0000000000600B18                 mov     byte ptr [rbp-1Ch], 7Fh
.data:0000000000600B1C                 mov     byte ptr [rbp-1Bh], 6Bh ; 'k'
.data:0000000000600B20                 mov     byte ptr [rbp-1Ah], 37h ; '7'
.data:0000000000600B24                 mov     byte ptr [rbp-19h], 64h ; 'd'
.data:0000000000600B28                 mov     byte ptr [rbp-18h], 3Bh ; ';'
.data:0000000000600B2C                 mov     byte ptr [rbp-17h], 56h ; 'V'
.data:0000000000600B30                 mov     byte ptr [rbp-16h], 60h ; '`'
.data:0000000000600B34                 mov     byte ptr [rbp-15h], 3Bh ; ';'
.data:0000000000600B38                 mov     byte ptr [rbp-14h], 6Eh ; 'n'
.data:0000000000600B3C                 mov     byte ptr [rbp-13h], 70h ; 'p'
.data:0000000000600B40                 mov     dword ptr [rbp-4], 0
.data:0000000000600B47                 jmp     short loc_600B71
.data:0000000000600B49 ; ---------------------------------------------------------------------------
.data:0000000000600B49
.data:0000000000600B49 loc_600B49:                             ; CODE XREF: .data:0000000000600B75↓j
.data:0000000000600B49                 mov     eax, [rbp-4]
.data:0000000000600B4C                 movsxd  rdx, eax
.data:0000000000600B4F                 mov     rax, [rbp-28h]
.data:0000000000600B53                 add     rax, rdx
.data:0000000000600B56                 mov     edx, [rbp-4]
.data:0000000000600B59                 movsxd  rcx, edx
.data:0000000000600B5C                 mov     rdx, [rbp-28h]
.data:0000000000600B60                 add     rdx, rcx
.data:0000000000600B63                 movzx   edx, byte ptr [rdx]
.data:0000000000600B66                 mov     ecx, [rbp-4]
.data:0000000000600B69                 xor     edx, ecx
.data:0000000000600B6B                 mov     [rax], dl
.data:0000000000600B6D                 add     dword ptr [rbp-4], 1
.data:0000000000600B71
.data:0000000000600B71 loc_600B71:                             ; CODE XREF: .data:0000000000600B47↑j
.data:0000000000600B71                 cmp     dword ptr [rbp-4], 0Dh
.data:0000000000600B75                 jle     short loc_600B49
.data:0000000000600B77                 mov     dword ptr [rbp-4], 0
.data:0000000000600B7E                 jmp     short loc_600BA9
.data:0000000000600B80 ; ---------------------------------------------------------------------------
.data:0000000000600B80
.data:0000000000600B80 loc_600B80:                             ; CODE XREF: .data:0000000000600BAD↓j
.data:0000000000600B80                 mov     eax, [rbp-4]
.data:0000000000600B83                 movsxd  rdx, eax
.data:0000000000600B86                 mov     rax, [rbp-28h]
.data:0000000000600B8A                 add     rax, rdx
.data:0000000000600B8D                 movzx   edx, byte ptr [rax]
.data:0000000000600B90                 mov     eax, [rbp-4]
.data:0000000000600B93                 cdqe
.data:0000000000600B95                 movzx   eax, byte ptr [rbp+rax-20h]
.data:0000000000600B9A                 cmp     dl, al
.data:0000000000600B9C                 jz      short loc_600BA5
.data:0000000000600B9E                 mov     eax, 0
.data:0000000000600BA3                 jmp     short loc_600BB4
.data:0000000000600BA5 ; ---------------------------------------------------------------------------
.data:0000000000600BA5
.data:0000000000600BA5 loc_600BA5:                             ; CODE XREF: .data:0000000000600B9C↑j
.data:0000000000600BA5                 add     dword ptr [rbp-4], 1
.data:0000000000600BA9
.data:0000000000600BA9 loc_600BA9:                             ; CODE XREF: .data:0000000000600B7E↑j
.data:0000000000600BA9                 cmp     dword ptr [rbp-4], 0Dh
.data:0000000000600BAD                 jle     short loc_600B80
.data:0000000000600BAF                 mov     eax, 1
.data:0000000000600BB4
.data:0000000000600BB4 loc_600BB4:                             ; CODE XREF: .data:0000000000600BA3↑j
.data:0000000000600BB4                 pop     rbp
.data:0000000000600BB5                 retn
.data:0000000000600BB5 _data           ends
```

框选`0x600B00`到`0x600BB5`的`.data`数据，按`P`生成新的`judge`函数，在`Function window`点击`judge`函数，按`F5`反编译查看代码：

```c
__int64 __fastcall judge(__int64 a1)
{
  char v2[5]; // [rsp+8h] [rbp-20h] BYREF
  char v3[9]; // [rsp+Dh] [rbp-1Bh] BYREF
  int i; // [rsp+24h] [rbp-4h]

  qmemcpy(v2, "fmcd", 4);
  v2[4] = 127;
  qmemcpy(v3, "k7d;V`;np", sizeof(v3));
  for ( i = 0; i <= 13; ++i )
    *(_BYTE *)(i + a1) ^= i;
  for ( i = 0; i <= 13; ++i )
  {
    if ( *(_BYTE *)(i + a1) != v2[i] )
      return 0LL;
  }
  return 1LL;
}
```

了解代码逻辑后，编写`Python`代码即可得到`flag`，提交`flag{n1c3_j0b}`即可。

```python
s = 'fmcd' + chr(127) + 'k7d;V`;np'
flag = ''
for i in range(14):
    flag += chr(ord(s[i])^i)
print(flag) # flag{n1c3_j0b}
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

