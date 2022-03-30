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

### [EasyRE](https://adworld.xctf.org.cn/task/answer?type=reverse&number=4&grade=1&id=5446)

用 `file`查看附件`EasyRE.exe`，可以看到信息`./EasyRE.exe: PE32 executable (console) Intel 80386, for MS Windows`，用`IDA Pro 32bit`打开文件后，按`F5`反编译可以看到主函数的`C`语言代码如下：

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  unsigned int v3; // kr00_4
  int v4; // edx
  char *v5; // esi
  char v6; // al
  unsigned int i; // edx
  int v8; // eax
  char Arglist[16]; // [esp+2h] [ebp-24h] BYREF
  __int64 v11; // [esp+12h] [ebp-14h] BYREF
  int v12; // [esp+1Ah] [ebp-Ch]
  __int16 v13; // [esp+1Eh] [ebp-8h]

  sub_401020(Format, Arglist[0]);
  v12 = 0;
  v13 = 0;
  *(_OWORD *)Arglist = 0i64;
  v11 = 0i64;
  sub_401050("%s", (char)Arglist);
  v3 = strlen(Arglist);
  if ( v3 >= 0x10 && v3 == 24 )
  {
    v4 = 0;
    v5 = (char *)&v11 + 7;
    do
    {
      v6 = *v5--;
      byte_40336C[v4++] = v6;
    }
    while ( v4 < 24 );
    for ( i = 0; i < 0x18; ++i )
      byte_40336C[i] = (byte_40336C[i] + 1) ^ 6;
    v8 = strcmp(byte_40336C, aXircjR2twsv3pt);
    if ( v8 )
      v8 = v8 < 0 ? -1 : 1;
    if ( !v8 )
    {
      sub_401020("right\n", Arglist[0]);
      system("pause");
    }
  }
  return 0;
}
```

注意到变量`aXircjR2twsv3pt`，双击发现是特殊字符串。根据代码逻辑编写`Python`代码，即可得到`flag{xNqU4otPq3ys9wkDsN}`。

```python
s = 'xIrCj~<r|2tWsv3PtI' 
flag = ''
for i in range(len(s)):
    flag = chr((ord(s[i])^6)-1) + flag
data = [0x7F, 0x7A, 0x6E, 0x64, 0x6B, 0x61]
for i in range(len(data)):
    flag = chr((data[i]^6)-1) + flag
print(flag) # flag{xNqU4otPq3ys9wkDsN}
```

------

### [re-for-50-plz-50](https://adworld.xctf.org.cn/task/answer?type=reverse&number=4&grade=1&id=4952)

用 `file`查看附件`re-for-50-plz-50`，可以看到信息`./re-for-50-plz-50: ELF 32-bit LSB executable, MIPS`，用`IDA Pro 32bit`打开文件后，按`F5`反编译可以看到主函数的`C`语言代码如下：

```c
int __cdecl __noreturn main(int argc, const char **argv, const char **envp)
{
  int i; // [sp+18h] [+18h]

  for ( i = 0; i < 31; ++i )
  {
    if ( meow[i] != (char)(argv[1][i] ^ 0x37) )
    {
      print("NOOOOOOOOOOOOOOOOOO\n");
      exit_funct();
    }
  }
  puts("C0ngr4ssulations!! U did it.", argv, envp);
  exit_funct();
}
```

双击 `meow` 发现特殊字符串`cbtcqLUBChERV[[Nh@_X^D]X_YPV[CJ`。编写`Python`代码可以得到`TUCTF{but_really_whoisjohngalt}`。

```python
s = 'cbtcqLUBChERV[[Nh@_X^D]X_YPV[CJ'
flag = ''
for i in range(len(s)):
    flag += chr(ord(s[i])^0x37) 
print(flag)
```

------

### dmd-50

用 `file`查看附件`re-for-50-plz-50`，可以看到信息`./dmd-50: ELF 64-bit LSB executable, x86-64`，用`IDA Pro 64bit`打开文件后，按`F5`反编译后，再对所有的`ASCII`数值按`R`转换为`ASCII`字符，可以看到主函数的`C`语言代码如下：

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  __int64 v3; // rax
  __int64 v4; // rax
  __int64 v5; // rax
  __int64 v6; // rax
  __int64 v7; // rax
  __int64 v8; // rax
  __int64 v9; // rax
  __int64 v10; // rax
  __int64 v11; // rax
  __int64 v12; // rax
  __int64 v13; // rax
  __int64 v14; // rax
  __int64 v15; // rax
  __int64 v16; // rax
  __int64 v17; // rax
  __int64 v18; // rax
  __int64 v19; // rax
  __int64 v20; // rax
  __int64 v21; // rax
  int result; // eax
  __int64 v23; // rax
  __int64 v24; // rax
  __int64 v25; // rax
  __int64 v26; // rax
  __int64 v27; // rax
  __int64 v28; // rax
  __int64 v29; // rax
  __int64 v30; // rax
  __int64 v31; // rax
  __int64 v32; // rax
  __int64 v33; // rax
  __int64 v34; // rax
  __int64 v35; // rax
  __int64 v36; // rax
  __int64 v37; // rax
  char v38; // [rsp+Fh] [rbp-71h] BYREF
  char v39[16]; // [rsp+10h] [rbp-70h] BYREF
  char v40[8]; // [rsp+20h] [rbp-60h] BYREF
  __int64 v41; // [rsp+28h] [rbp-58h]
  char v42[56]; // [rsp+30h] [rbp-50h] BYREF
  unsigned __int64 v43; // [rsp+68h] [rbp-18h]

  v43 = __readfsqword(0x28u);
  std::operator<<<std::char_traits<char>>(&std::cout, "Enter the valid key!\n", envp);
  std::operator>><char,std::char_traits<char>>(&edata, v42);
  std::allocator<char>::allocator(&v38);
  std::string::string(v39, v42, &v38);
  md5(v40, v39);
  v41 = std::string::c_str((std::string *)v40);
  std::string::~string((std::string *)v40);
  std::string::~string((std::string *)v39);
  std::allocator<char>::~allocator(&v38);
  if ( *(_WORD *)v41 == '87'
    && *(_BYTE *)(v41 + 2) == '0'
    && *(_BYTE *)(v41 + 3) == '4'
    && *(_BYTE *)(v41 + 4) == '3'
    && *(_BYTE *)(v41 + 5) == '8'
    && *(_BYTE *)(v41 + 6) == 'd'
    && *(_BYTE *)(v41 + 7) == '5'
    && *(_BYTE *)(v41 + 8) == 'b'
    && *(_BYTE *)(v41 + 9) == '6'
    && *(_BYTE *)(v41 + 10) == 'e'
    && *(_BYTE *)(v41 + 11) == '2'
    && *(_BYTE *)(v41 + 12) == '9'
    && *(_BYTE *)(v41 + 13) == 'd'
    && *(_BYTE *)(v41 + 14) == 'b'
    && *(_BYTE *)(v41 + 15) == '0'
    && *(_BYTE *)(v41 + 16) == '8'
    && *(_BYTE *)(v41 + 17) == '9'
    && *(_BYTE *)(v41 + 18) == '8'
    && *(_BYTE *)(v41 + 19) == 'b'
    && *(_BYTE *)(v41 + 20) == 'c'
    && *(_BYTE *)(v41 + 21) == '4'
    && *(_BYTE *)(v41 + 22) == 'f'
    && *(_BYTE *)(v41 + 23) == '0'
    && *(_BYTE *)(v41 + 24) == '2'
    && *(_BYTE *)(v41 + 25) == '2'
    && *(_BYTE *)(v41 + 26) == '5'
    && *(_BYTE *)(v41 + 27) == '9'
    && *(_BYTE *)(v41 + 28) == '3'
    && *(_BYTE *)(v41 + 29) == '5'
    && *(_BYTE *)(v41 + 30) == 'c'
    && *(_BYTE *)(v41 + 31) == '0' )
  {
    v3 = std::operator<<<std::char_traits<char>>(&std::cout, 'T');
    v4 = std::operator<<<std::char_traits<char>>(v3, 'h');
    v5 = std::operator<<<std::char_traits<char>>(v4, 'e');
    v6 = std::operator<<<std::char_traits<char>>(v5, ' ');
    v7 = std::operator<<<std::char_traits<char>>(v6, 'k');
    v8 = std::operator<<<std::char_traits<char>>(v7, 'e');
    v9 = std::operator<<<std::char_traits<char>>(v8, 'y');
    v10 = std::operator<<<std::char_traits<char>>(v9, ' ');
    v11 = std::operator<<<std::char_traits<char>>(v10, 'i');
    v12 = std::operator<<<std::char_traits<char>>(v11, 's');
    v13 = std::operator<<<std::char_traits<char>>(v12, ' ');
    v14 = std::operator<<<std::char_traits<char>>(v13, 'v');
    v15 = std::operator<<<std::char_traits<char>>(v14, 'a');
    v16 = std::operator<<<std::char_traits<char>>(v15, 'l');
    v17 = std::operator<<<std::char_traits<char>>(v16, 'i');
    v18 = std::operator<<<std::char_traits<char>>(v17, 'd');
    v19 = std::operator<<<std::char_traits<char>>(v18, ' ');
    v20 = std::operator<<<std::char_traits<char>>(v19, ':');
    v21 = std::operator<<<std::char_traits<char>>(v20, ')');
    std::ostream::operator<<(v21, &std::endl<char,std::char_traits<char>>);
    result = 0;
  }
  else
  {
    v23 = std::operator<<<std::char_traits<char>>(&std::cout, 'I');
    v24 = std::operator<<<std::char_traits<char>>(v23, 'n');
    v25 = std::operator<<<std::char_traits<char>>(v24, 'v');
    v26 = std::operator<<<std::char_traits<char>>(v25, 'a');
    v27 = std::operator<<<std::char_traits<char>>(v26, 'l');
    v28 = std::operator<<<std::char_traits<char>>(v27, 'i');
    v29 = std::operator<<<std::char_traits<char>>(v28, 'd');
    v30 = std::operator<<<std::char_traits<char>>(v29, ' ');
    v31 = std::operator<<<std::char_traits<char>>(v30, 'K');
    v32 = std::operator<<<std::char_traits<char>>(v31, 'e');
    v33 = std::operator<<<std::char_traits<char>>(v32, 'y');
    v34 = std::operator<<<std::char_traits<char>>(v33, '!');
    v35 = std::operator<<<std::char_traits<char>>(v34, ' ');
    v36 = std::operator<<<std::char_traits<char>>(v35, ':');
    v37 = std::operator<<<std::char_traits<char>>(v36, '(');
    std::ostream::operator<<(v37, &std::endl<char,std::char_traits<char>>);
    result = 0;
  }
  return result;
}
```

将字符串`870438d5b6e29db0898bc4f0225935c0`进行`md5`解密后得到`grape`。

![](https://paper.tanyaodan.com/ADWorld/reverse/4959/1.png)

我们看到密文类型为`md5(md5($pass))`，也就是这个字符串是经过了两次`md5`解密，所以我们需要将`grape`再进行一次加密，最终得到的`flag`为`b781cbb29054db12f88f08c6e161c199`。

![](https://paper.tanyaodan.com/ADWorld/reverse/4959/2.png)

------

### [parallel-comparator-200](https://adworld.xctf.org.cn/task/answer?type=reverse&number=4&grade=1&id=4706)

这道题附件是一个 ` .c` 文件，打开后源码如下：

```c
#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>

#define FLAG_LEN 20

void * checking(void *arg) {
    char *result = malloc(sizeof(char));
    char *argument = (char *)arg;
    *result = (argument[0]+argument[1]) ^ argument[2];
    return result;
}

int highly_optimized_parallel_comparsion(char *user_string)
{
    int initialization_number;
    int i;
    char generated_string[FLAG_LEN + 1];
    generated_string[FLAG_LEN] = '\0';

    while ((initialization_number = random()) >= 64);
    
    int first_letter;
    first_letter = (initialization_number % 26) + 97;

    pthread_t thread[FLAG_LEN];
    char differences[FLAG_LEN] = {0, 9, -9, -1, 13, -13, -4, -11, -9, -1, -7, 6, -13, 13, 3, 9, -13, -11, 6, -7};
    char *arguments[20];
    for (i = 0; i < FLAG_LEN; i++) {
        arguments[i] = (char *)malloc(3*sizeof(char));
        arguments[i][0] = first_letter;
        arguments[i][1] = differences[i];
        arguments[i][2] = user_string[i];

        pthread_create((pthread_t*)(thread+i), NULL, checking, arguments[i]);
    }

    void *result;
    int just_a_string[FLAG_LEN] = {115, 116, 114, 97, 110, 103, 101, 95, 115, 116, 114, 105, 110, 103, 95, 105, 116, 95, 105, 115};
    for (i = 0; i < FLAG_LEN; i++) {
        pthread_join(*(thread+i), &result);
        generated_string[i] = *(char *)result + just_a_string[i];
        free(result);
        free(arguments[i]);
    }

    int is_ok = 1;
    for (i = 0; i < FLAG_LEN; i++) {
        if (generated_string[i] != just_a_string[i])
            return 0;
    }

    return 1;
}

int main()
{
    char *user_string = (char *)calloc(FLAG_LEN+1, sizeof(char));
    fgets(user_string, FLAG_LEN+1, stdin);
    int is_ok = highly_optimized_parallel_comparsion(user_string);
    if (is_ok)
        printf("You win!\n");
    else
        printf("Wrong!\n");
    return 0;
}

```

注意到`highly_optimized_parallel_comparsion()`函数中有关键代码段，我们可以推断出`result = 0`。

```c
for (i = 0; i < FLAG_LEN; i++) {
    pthread_join(*(thread+i), &result);
    generated_string[i] = *(char *)result + just_a_string[i];
    free(result);
    free(arguments[i]);
}
```

所以由`result = 0`又能推断出异或结果为`0`，即`argument[2] = argument[0]+argument[1]`。

```c
void * checking(void *arg) {
    char *result = malloc(sizeof(char));
    char *argument = (char *)arg;
    *result = (argument[0]+argument[1]) ^ argument[2];
    return result;
}
```

而根据以下代码又能知道`user_string[i] = differences[i] + first_letter`，其中`first_letter = 97 + x; 0<=x<=25`。

```c
int first_letter;
first_letter = (initialization_number % 26) + 97;
char differences[FLAG_LEN] = {0, 9, -9, -1, 13, -13, -4, -11, -9, -1, -7, 6, -13, 13, 3, 9, -13, -11, 6, -7};
char *arguments[20];
for (i = 0; i < FLAG_LEN; i++) {
    arguments[i] = (char *)malloc(3*sizeof(char));
    arguments[i][0] = first_letter;
    arguments[i][1] = differences[i];
    arguments[i][2] = user_string[i];

    pthread_create((pthread_t*)(thread+i), NULL, checking, arguments[i]);
}
```

根据代码逻辑编写`Python`代码，运行后可以在结果中看到一行`lucky_hacker_you_are`，这就是`flag`。

```python
differences = [0, 9, -9, -1, 13, -13, -4, -11, -9, -1, -7, 6, -13, 13, 3, 9, -13, -11, 6, -7]
for i in range(26):
    first_letter = 97 + i
    flag = ''.join([chr(first_letter+differences[i]) for i in range(len(differences))])
    print(flag) # first_letter = 108, flag is lucky_hacker_you_are
```

------

### [secret-galaxy-300](https://adworld.xctf.org.cn/task/answer?type=reverse&number=4&grade=1&id=4707)

这题附件是一个压缩包，解压缩后可以得到三个文件：`task10_x86_secret-galaxy-300.exe`，`task10_x86_secret-galaxy-300`，`task10_x86_64_secret-galaxy-300`，那就随机挑选一个运行吧。`./task10_x86_64_secret-galaxy-300`运行结果如下：

![](https://paper.tanyaodan.com/ADWorld/reverse/4707/1.png)

用`IDA Pro 64bit`打开文件`task10_x86_64_secret-galaxy-300`后，按`F5`反编译后，可以看到主函数的`C`语言代码如下：

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  fill_starbase((__int64)&starbase);
  print_starbase(&starbase);
  return 0;
}
```

双击`fill_starbase()`函数可以看到以下源代码：

```c
void __fastcall fill_starbase(__int64 a1)
{
  int i; // [rsp+14h] [rbp-1Ch]
  __int64 v2; // [rsp+18h] [rbp-18h]

  v2 = 0LL;
  for ( i = 0; i <= 4; ++i )
  {
    *(_QWORD *)(a1 + 40LL * i) = (&galaxy_name)[i];
    *(_DWORD *)(40LL * i + a1 + 8) = random();
    *(_DWORD *)(40LL * i + a1 + 12) = 0;
    *(_QWORD *)(40LL * i + a1 + 16) = 0LL;
    *(_QWORD *)(40LL * i + a1 + 24) = 40 * (i + 1LL) + a1;
    *(_QWORD *)(a1 + 40LL * i + 32) = v2;
    v2 = 40LL * i + a1;
  }
}
```

双击变量名`galaxy_name`跳转到汇编语言代码，发现`public galaxy_name`中除了`"DARK SECRET GALAXY"`外 其它的星球名都输出过。

![](https://paper.tanyaodan.com/ADWorld/reverse/4707/2.png)

盲猜`"DARK SECRET GALAXY"`不对劲，点击`DATA XREF: __libc_csu_gala+C↑r`的`↑`跳转到相应`.text`段，按`F5`反编译得到新函数：

```c
__int64 _libc_csu_gala()
{
  __int64 result; // rax

  sc = off_601288;
  *((_QWORD *)&sc + 2) = &byte_601384;
  *((_DWORD *)&sc + 2) = 31337;
  *((_DWORD *)&sc + 3) = 1;
  byte_601384 = off_601268[8];
  byte_601385 = off_601280[7];
  byte_601386 = off_601270[4];
  byte_601387 = off_601268[6];
  byte_601388 = off_601268[1];
  byte_601389 = off_601270[2];
  byte_60138A = 95;
  byte_60138B = off_601268[8];
  byte_60138C = off_601268[3];
  byte_60138D = off_601278[5];
  byte_60138E = 95;
  byte_60138F = off_601268[8];
  byte_601390 = off_601268[3];
  byte_601391 = off_601268[4];
  byte_601392 = off_601280[6];
  byte_601393 = off_601280[4];
  byte_601394 = off_601268[2];
  byte_601395 = 95;
  byte_601396 = off_601280[6];
  result = (unsigned __int8)off_601270[3];
  byte_601397 = off_601270[3];
  byte_601398 = 0;
  return result;
}
```

根据该函数的代码逻辑，编写`Python`代码即可得到`flag`，提交`aliens_are_around_us`即可。

```python
flag = ''
off_601268 = 'Andromeda'
off_601270 = 'Messier'
off_601278 = 'Sombrero'
off_601280 = 'Triangulum'
flag += off_601268[8]
flag += off_601280[7]
flag += off_601270[4]
flag += off_601268[6]
flag += off_601268[1]
flag += off_601270[2]
flag += chr(95)
flag += off_601268[8]
flag += off_601268[3]
flag += off_601278[5]
flag += chr(95)
flag += off_601268[8]
flag += off_601268[3]
flag += off_601268[4]
flag += off_601280[6]
flag += off_601280[4]
flag += off_601268[2]
flag += chr(95)
flag += off_601280[6]
flag += off_601270[3]
print(flag)
```

------

### [secret-string-400](https://adworld.xctf.org.cn/task/answer?type=reverse&number=4&grade=1&id=4708)

这题附件是一个压缩包，解压缩后可以得到两个文件：`Task.html`和`Machine.js`。其中`Task.html`的源代码如下：

```html
<html>
	<head>
		<title>JSMachine</title>
		<meta charset="UTF-8">
		<script type='text/javascript' src='Machine.js'></script>
	</head>
	<body>
		<h1>Secret key</h1><br/>
		<h2>Test your luck! Enter valid string and you will know flag!</h2><br/>
		<input type='text'></input><br/>
		<br/>
		<input type='button' onclick="check()" value='Проверить'></button>
	</body>
</html>
```

`Machine.js`的源代码如下：

```javascript
function createRegisters(obj){
	obj.registers = [];
	for(i=0; i < 256; ++i){
		obj.registers.push(0);
	}
};

function Machine() {
	createRegisters(this);
	this.code = [0]
	this.PC = 0;
	this.callstack = [];
	this.pow = Math.pow(2,32)
};

Machine.prototype = {
	opcodesCount: 16,
	run: run,
	loadcode: function(code){this.code = code},
	end: function(){this.code=[]}
};


function run(){
	while(this.PC < this.code.length){
		var command = parseCommand.call(this)
		command.execute(this);
	}
	//this.end()
}

function getOpcodeObject(){
	var opNum = (this.code[this.PC] % this.opcodesCount);
	this.PC += 1;
	return eval('new Opcode'+opNum);
}

function parseCommand(){
	var opcode = getOpcodeObject.call(this);
	opcode.consumeArgs(this);
	return opcode;
}

var opcCreate = "";
for(i=0;i<16;++i){
	opcCreate += "function Opcode"+i+"(){this.args=[]}\n";
}


eval(opcCreate);


function makeFromImm(obj) {
	var res = obj.code[obj.PC + 2];
	res <<=8;
	res += obj.code[obj.PC + 1];
	res <<=8;
	res += obj.code[obj.PC];
	res <<=8;
	res += obj.code[obj.PC+3];
	res = res >>> 0;
	return res;
}

function getRegImm(obj){
	this.args[0] = obj.code[obj.PC];
	obj.PC += 1;
	this.args[1] = makeFromImm(obj);
	obj.PC += 4;
}

function getImm(obj){
	this.args[0] = makeFromImm(obj);
	obj.PC += 4;	
}

function getTwoRegs(obj){
	this.args[0] = obj.code[obj.PC];
	obj.PC += 1;
	this.args[1] = obj.code[obj.PC];
	obj.PC += 1;
}

function getThreeRegs(obj){
	this.args[0] = obj.code[obj.PC];
	obj.PC += 1;
	this.args[1] = obj.code[obj.PC];
	obj.PC += 1;
	this.args[2] = obj.code[obj.PC];
	obj.PC += 1;
}

function getRegString(obj){
	this.args[0] = obj.code[obj.PC];
	obj.PC += 1;
	this.args[1] = getString(obj);
}

function getRegRegString(obj){
	this.args[0] = obj.code[obj.PC];
	obj.PC += 1;
	this.args[1] = obj.code[obj.PC];
	obj.PC += 1;
	this.args[2] = getString(obj);
}

function getRegTwoString(obj){
	this.args[0] = obj.code[obj.PC];
	obj.PC += 1;
	this.args[1] = getString(obj);
	this.args[2] = getString(obj);
}

function getString(obj){
	var res = "";
	while(obj.code[obj.PC] != 0) {
		res += String.fromCharCode(obj.code[obj.PC]);
		obj.PC += 1;
	}
	obj.PC += 1;
	return res;
}

Opcode0.prototype = {
	consumeArgs : function(obj){},
	execute: function(){}
};

Opcode1.prototype = {
	consumeArgs: getRegImm,
	execute: function(obj){
		obj.registers[this.args[0]] = (obj.registers[this.args[0]] +  this.args[1]) % 0x100000000;
	}
}


Opcode2.prototype = {
	consumeArgs: getTwoRegs,	
	execute: function(obj){
		obj.registers[this.args[0]] = (obj.registers[this.args[0]] + obj.registers[this.args[1]]) % 0x100000000;
	}
}

Opcode3.prototype = {
	consumeArgs: getRegImm,
	execute: function(obj){
		obj.registers[this.args[0]] = ((obj.registers[this.args[0]] -  this.args[1]) % 0x100000000) >>> 0;
	}
}

Opcode4.prototype = {
	consumeArgs: getTwoRegs,
	execute: function(obj){
		obj.regsiters[this.args[0]] = ((obj.registers[this.args[0]] - this.registers[this.args[1]])%100000000) >>> 0
	}
}

Opcode5.prototype = {
	consumeArgs: getThreeRegs,
	execute: function(obj){
		var mult = obj.registers[this.args[0]] * obj.registers[this.args[1]];
		console.log(mult.toString(16));
		obj.registers[this.args[2]] = (mult / obj.pow) >>> 0;
		obj.registers[this.args[2]+1] = (mult & 0xffffffff) >>> 0;
	}
}

Opcode6.prototype = {
	consumeArgs: getThreeRegs,
	execute: function(obj){
		var divs = obj.registers[this.args[0]] * obj.pow + obj.registers[this.args[0]+1];
		obj.registers[this.args[2]]  = (divs / obj.registers[this.args[1]]) >>> 0;
		obj.registers[this.args[2]+1]= (divs % obj.registers[this.args[1]]) >>> 0;
	}
}

Opcode7.prototype = {
	consumeArgs: getRegImm,
	execute: function(obj) {
		obj.registers[this.args[0]] = this.args[1];
	}	
}

Opcode8.prototype = {
	consumeArgs: getImm,
	execute: function(obj){
		obj.callstack.push(obj.PC);
		obj.PC = this.args[0];
	}
}

Opcode9.prototype = {
	consumeArgs: getImm,
	execute: function(obj){
		obj.PC = (obj.PC +  this.args[0]) % obj.code.length;
	}
}

Opcode10.prototype = {
	consumeArgs: function(){},
	execute: function(obj){
		obj.PC = obj.callstack.pop();
	}
}

Opcode11.prototype = {
	consumeArgs: getRegString,
	execute: function(obj){
		obj.registers[this.args[0]] = eval('new '+this.args[1]);
	}
}

Opcode12.prototype = {
	consumeArgs: getRegTwoString,
	execute: function(obj){
		obj.registers[this.args[0]][this.args[1]] = Function(this.args[2]);
	}
}

Opcode13.prototype = {
	consumeArgs: getRegRegString,
	execute: function(obj){
		obj.registers[this.args[0]] = obj.registers[this.args[1]][this.args[2]];
	}
}

Opcode14.prototype = {
	consumeArgs: getRegRegString,
	execute: function(obj){
		obj.registers[this.args[1]][this.args[2]] = obj.registers[this.args[0]];
	}
}

Opcode15.prototype = {
	consumeArgs: getRegRegString,
	execute: function(obj){
		obj.registers[this.args[0]] = obj.registers[this.args[1]][this.args[2]]();
	}
}
function check(){
machine = new Machine;
machine.loadcode([11, 1, 79, 98, 106, 101, 99, 116, 0, 12, 1, 120, 0, 114, 101, 116, 117, 114, 110, 32, 100, 111, 99, 117, 109, 101, 110, 116, 46, 103, 101, 116, 69, 108, 101, 109, 101, 110, 116, 115, 66, 121, 84, 97, 103, 78, 97, 109, 101, 40, 39, 105, 110, 112, 117, 116, 39, 41, 91, 48, 93, 46, 118, 97, 108, 117, 101, 47, 47, 0, 15, 3, 1, 120, 0, 14, 3, 1, 117, 115, 101, 114, 105, 110, 112, 117, 116, 0, 12, 1, 121, 0, 119, 105, 110, 100, 111, 119, 46, 109, 97, 99, 104, 105, 110, 101, 46, 101, 110, 100, 32, 61, 32, 102, 117, 110, 99, 116, 105, 111, 110, 40, 41, 123, 116, 104, 105, 115, 46, 99, 111, 100, 101, 61, 91, 93, 59, 116, 104, 105, 115, 46, 80, 67, 61, 49, 55, 51, 125, 47, 47, 0, 15, 3, 1, 121, 0, 12, 1, 122, 0, 97, 108, 101, 114, 116, 40, 49, 41, 59, 47, 47, 11, 234, 79, 98, 106, 101, 99, 116, 255, 9, 255, 255, 255, 12, 10, 97, 108, 101, 114, 116, 40, 50, 41, 59, 47, 47, 12, 234, 120, 255, 118, 97, 114, 32, 102, 61, 119, 105, 110, 100, 111, 119, 46, 109, 97, 99, 104, 105, 110, 101, 46, 114, 101, 103, 105, 115, 116, 101, 114, 115, 91, 49, 93, 46, 117, 115, 101, 114, 105, 110, 112, 117, 116, 47, 47, 10, 118, 97, 114, 32, 105, 32, 61, 32, 102, 46, 108, 101, 110, 103, 116, 104, 47, 47, 10, 118, 97, 114, 32, 110, 111, 110, 99, 101, 32, 61, 32, 39, 103, 114, 111, 107, 101, 39, 59, 47, 47, 10, 118, 97, 114, 32, 106, 32, 61, 32, 48, 59, 47, 47, 10, 118, 97, 114, 32, 111, 117, 116, 32, 61, 32, 91, 93, 59, 47, 47, 10, 118, 97, 114, 32, 101, 113, 32, 61, 32, 116, 114, 117, 101, 59, 47, 47, 10, 119, 104, 105, 108, 101, 40, 106, 32, 60, 32, 105, 41, 123, 47, 47, 10, 111, 117, 116, 46, 112, 117, 115, 104, 40, 102, 46, 99, 104, 97, 114, 67, 111, 100, 101, 65, 116, 40, 106, 41, 32, 94, 32, 110, 111, 110, 99, 101, 46, 99, 104, 97, 114, 67, 111, 100, 101, 65, 116, 40, 106, 37, 53, 41, 41, 47, 47, 10, 106, 43, 43, 59, 47, 47, 10, 125, 47, 47, 10, 118, 97, 114, 32, 101, 120, 32, 61, 32, 32, 91, 49, 44, 32, 51, 48, 44, 32, 49, 52, 44, 32, 49, 50, 44, 32, 54, 57, 44, 32, 49, 52, 44, 32, 49, 44, 32, 56, 53, 44, 32, 55, 53, 44, 32, 53, 48, 44, 32, 52, 48, 44, 32, 51, 55, 44, 32, 52, 56, 44, 32, 50, 52, 44, 32, 49, 48, 44, 32, 53, 54, 44, 32, 53, 53, 44, 32, 52, 54, 44, 32, 53, 54, 44, 32, 54, 48, 93, 59, 47, 47, 10, 105, 102, 32, 40, 101, 120, 46, 108, 101, 110, 103, 116, 104, 32, 61, 61, 32, 111, 117, 116, 46, 108, 101, 110, 103, 116, 104, 41, 32, 123, 47, 47, 10, 106, 32, 61, 32, 48, 59, 47, 47, 10, 119, 104, 105, 108, 101, 40, 106, 32, 60, 32, 101, 120, 46, 108, 101, 110, 103, 116, 104, 41, 123, 47, 47, 10, 105, 102, 40, 101, 120, 91, 106, 93, 32, 33, 61, 32, 111, 117, 116, 91, 106, 93, 41, 47, 47, 10, 101, 113, 32, 61, 32, 102, 97, 108, 115, 101, 59, 47, 47, 10, 106, 32, 43, 61, 32, 49, 59, 47, 47, 10, 125, 47, 47, 10, 105, 102, 40, 101, 113, 41, 123, 47, 47, 10, 97, 108, 101, 114, 116, 40, 39, 89, 79, 85, 32, 87, 73, 78, 33, 39, 41, 59, 47, 47, 10, 125, 101, 108, 115, 101, 123, 10, 97, 108, 101, 114, 116, 40, 39, 78, 79, 80, 69, 33, 39, 41, 59, 10, 125, 125, 101, 108, 115, 101, 123, 97, 108, 101, 114, 116, 40, 39, 78, 79, 80, 69, 33, 39, 41, 59, 125, 47, 47, 255, 9, 255, 255, 255, 12, 10, 97, 108, 101, 114, 116, 40, 51, 41, 59, 47, 47, 15, 1, 234, 120, 255, 9, 255, 255, 255, 12, 10, 97, 108, 101, 114, 116, 40, 52, 41, 59, 47, 47, 10, 97, 108, 101, 114, 116, 40, 53, 41, 59, 47, 47, 10, 97, 108, 101, 114, 116, 40, 54, 41, 59, 47, 47, 10, 97, 108, 101, 114, 116, 40, 55, 41, 59, 47, 47, 0, 12, 1, 103, 0, 118, 97, 114, 32, 105, 32, 61, 48, 59, 119, 104, 105, 108, 101, 40, 105, 60, 119, 105, 110, 100, 111, 119, 46, 109, 97, 99, 104, 105, 110, 101, 46, 99, 111, 100, 101, 46, 108, 101, 110, 103, 116, 104, 41, 123, 105, 102, 40, 119, 105, 110, 100, 111, 119, 46, 109, 97, 99, 104, 105, 110, 101, 46, 99, 111, 100, 101, 91, 105, 93, 32, 61, 61, 32, 50, 53, 53, 32, 41, 32, 119, 105, 110, 100, 111, 119, 46, 109, 97, 99, 104, 105, 110, 101, 46, 99, 111, 100, 101, 91, 105, 93, 32, 61, 32, 48, 59, 105, 43, 43, 125, 47, 47, 0, 12, 1, 104, 0, 119, 105, 110, 100, 111, 119, 46, 109, 97, 99, 104, 105, 110, 101, 46, 80, 67, 61, 49, 55, 50, 47, 47, 0, 15, 0, 1, 103, 0, 15, 0, 1, 104, 0])
machine.run();
}
```

随便输入几个字符，网页弹出提示框显示`NOPE!`，但是在`js`代码中并不能直接搜索到`NOPE!`。审计`js`代码，并对`run()`函数进行修改：

```javascript
function run(){
	while(this.PC < this.code.length){
		var command = parseCommand.call(this)
		console.log('command args:' + this.command.args)
		command.execute(this);
	}
	//this.end()
}
```

在浏览器按`F12`进行调试，继续随便输入几个字符，网页弹出提示框显示`NOPE!`，但是我们能在`Console`控制台中看到以下`js`代码：

```javascript
f=window.machine.registers[1].userinput//
var i = f.length//
var nonce = 'groke';//
var j = 0;//
var out = [];//
var eq = true;//
while(j < i){//
out.push(f.charCodeAt(j) ^ nonce.charCodeAt(j%5))//
j++;//
}//
var ex =  [1, 30, 14, 12, 69, 14, 1, 85, 75, 50, 40, 37, 48, 24, 10, 56, 55, 46, 56, 60];//
if (ex.length == out.length) {//
j = 0;//
while(j < ex.length){//
if(ex[j] != out[j])//
eq = false;//
j += 1;//
}//
if(eq){//
alert('YOU WIN!');//
}else{
alert('NOPE!');
}}else{alert('NOPE!');}//
```

根据以上代码逻辑，编写`Python`代码，运行得到`flag is: WOW_so_EASY`，提交`WOW_so_EASY`即可。

```python
nonce = 'groke'
ex = [1, 30, 14, 12, 69, 14, 1, 85, 75, 50, 40, 37, 48, 24, 10, 56, 55, 46, 56, 60]
flag = ''
for i in range(len(ex)):
    flag += chr(ex[i]^ord(nonce[i%5]))
print(flag)  # flag is: WOW_so_EASY
```

------

### [testre](https://adworld.xctf.org.cn/task/answer?type=reverse&number=4&grade=1&id=5476)

用 `file`查看附件`testre`，可以看到信息`./testre: ELF 64-bit LSB executable, x86-64`，用`IDA Pro 64bit`打开文件后，按`F5`反编译后，再对所有的`ASCII`数值按`R`转换为`ASCII`字符，可以看到主函数的`C`语言代码如下：

```c
__int64 __fastcall main(int a1, char **a2, char **a3)
{
  void *ptr; // [rsp+10h] [rbp-30h]
  __int64 v5; // [rsp+18h] [rbp-28h] BYREF
  char v6[28]; // [rsp+20h] [rbp-20h] BYREF
  int v7; // [rsp+3Ch] [rbp-4h]

  v7 = 0;
  v5 = 256LL;
  sub_400D00(v6, 17LL, a3);
  ptr = malloc(0x100uLL);
  sub_400700(ptr, &v5, v6, 16LL);
  free(ptr);
  return 0LL;
}
```

双击`sub_400D00()`函数查看详情：

```c
__int64 __fastcall sub_400D00(__int64 a1, unsigned __int64 a2)
{
  char buf; // [rsp+17h] [rbp-19h] BYREF
  unsigned __int64 i; // [rsp+18h] [rbp-18h]
  unsigned __int64 v5; // [rsp+20h] [rbp-10h]
  __int64 v6; // [rsp+28h] [rbp-8h]

  v6 = a1;
  v5 = a2;
  for ( i = 0LL; i < v5; ++i )
  {
    read(0, &buf, 1uLL);
    *(_BYTE *)(v6 + i) = buf;
  }
  *(_BYTE *)(v6 + v5 - 1) = 0;
  fflush(stdout);
  return (unsigned int)i;
}
```

这个函数的作用是用来读取用户输入的，返回主函数双击`sub_400700()`函数查看详情：

```c
__int64 __fastcall sub_400700(void *a1, _QWORD *a2, __int64 a3, size_t a4)
{
  unsigned __int8 *v4; // rcx
  _DWORD v6[2]; // [rsp+0h] [rbp-C0h] BYREF
  int c; // [rsp+8h] [rbp-B8h]
  char v8; // [rsp+Fh] [rbp-B1h]
  int v9; // [rsp+10h] [rbp-B0h]
  bool v10; // [rsp+17h] [rbp-A9h]
  unsigned __int8 *v11; // [rsp+18h] [rbp-A8h]
  char v12; // [rsp+27h] [rbp-99h]
  int v13; // [rsp+28h] [rbp-98h]
  int v14; // [rsp+2Ch] [rbp-94h]
  unsigned __int64 i; // [rsp+30h] [rbp-90h]
  size_t n; // [rsp+38h] [rbp-88h]
  size_t v17; // [rsp+40h] [rbp-80h]
  size_t v18; // [rsp+48h] [rbp-78h]
  size_t j; // [rsp+50h] [rbp-70h]
  size_t v20; // [rsp+58h] [rbp-68h]
  int v21; // [rsp+64h] [rbp-5Ch]
  unsigned __int64 v22; // [rsp+68h] [rbp-58h]
  int v23; // [rsp+74h] [rbp-4Ch]
  _DWORD *v24; // [rsp+78h] [rbp-48h]
  __int64 v25; // [rsp+80h] [rbp-40h]
  void *v26; // [rsp+88h] [rbp-38h]
  int v27; // [rsp+94h] [rbp-2Ch]
  size_t v28; // [rsp+98h] [rbp-28h]
  __int64 v29; // [rsp+A0h] [rbp-20h]
  _QWORD *v30; // [rsp+A8h] [rbp-18h]
  void *s; // [rsp+B0h] [rbp-10h]
  char v32; // [rsp+BFh] [rbp-1h]

  s = a1;
  v30 = a2;
  v29 = a3;
  v28 = a4;
  v27 = -559038737;
  v26 = malloc(0x100uLL);
  v25 = v29;
  v24 = v6;
  v22 = 0LL;
  v17 = 0LL;
  for ( i = 0LL; i < v28; ++i )
  {
    v13 = *(unsigned __int8 *)(v25 + i);
    *((_BYTE *)v26 + i) = byte_400E90[i % 0x1D] ^ v13;
    *((_BYTE *)v26 + i) += *(_BYTE *)(v25 + i);
  }
  while ( 1 )
  {
    v12 = 0;
    if ( v17 < v28 )
      v12 = ~(*(_BYTE *)(v25 + v17) != 0);
    if ( (v12 & 1) == 0 )
      break;
    ++v17;
  }
  n = 138 * (v28 - v17) / 0x64 + 1;
  v23 = ((v17 + v28) << 6) / 0x30 - 1;
  v11 = (unsigned __int8 *)v6 - ((138 * (v28 - v17) / 0x64 + 16) & 0xFFFFFFFFFFFFFFF0LL);
  memset(v11, 0, n);
  v20 = v17;
  v18 = n - 1;
  while ( v20 < v28 )  // 这个while循环进行了base58加密
  {
    v21 = *(unsigned __int8 *)(v25 + v20);
    for ( j = n - 1; ; --j )
    {
      v10 = 1;
      if ( j <= v18 )
        v10 = v21 != 0;
      if ( !v10 )
        break;
      v22 = v11[j] << 6;
      v21 += v11[j] << 8;
      v9 = 64;
      v11[j] = v21 % 58;
      *((_BYTE *)v26 + j) = v22 & 0x3F;
      v22 >>= 6;
      v21 /= 58;
      v27 /= v9;
      if ( !j )
        break;
    }
    ++v20;
    v18 = j;
  }
  for ( j = 0LL; ; ++j )
  {
    v8 = 0;
    if ( j < n )
      v8 = ~(v11[j] != 0);
    if ( (v8 & 1) == 0 )
      break;
  }
  if ( *v30 > n + v17 - j )  // 
  {
    if ( v17 )
    {
      c = 61;
      memset(s, 49, v17);
      memset(v26, c, v17);
    }
    v20 = v17;
    while ( j < n )
    {
      v4 = v11;
      *((_BYTE *)s + v20) = byte_400EB0[v11[j]];   // base58编码表代换
      *((_BYTE *)v26 + v20++) = byte_400EF0[v4[j++]];  // 这个base64编码表并没有参与编码计算,v26是干扰项
    }
    *((_BYTE *)s + v20) = 0;
    *v30 = v20 + 1;
    if ( !strncmp((const char *)s, "D9", 2uLL)  // 结果比较
      && !strncmp((const char *)s + 20, "Mp", 2uLL)
      && !strncmp((const char *)s + 18, "MR", 2uLL)
      && !strncmp((const char *)s + 2, "cS9N", 4uLL)
      && !strncmp((const char *)s + 6, "9iHjM", 5uLL)
      && !strncmp((const char *)s + 11, "LTdA8YS", 7uLL) )
    {
      v6[1] = puts("correct!");
    }
    v32 = 1;
    v14 = 1;
  }
  else
  {
    *v30 = n + v17 - j + 1;
    v32 = 0;
    v14 = 1;
  }
  return v32 & 1;
}
```

编写`Python`代码进行`base58`解码，运行得到`flag`，提交`base58_is_boring`即可。

```python
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

flag = b58decode('D9cS9N9iHjMLTdA8YSMRMp')
print(flag) # base58_is_boring
```

------

### [re1-100](https://adworld.xctf.org.cn/task/answer?type=reverse&number=4&grade=1&id=4720)

用 `file`查看附件`RE100`，可以看到信息`./RE100: ELF 64-bit LSB executable, x86-64`，用`IDA Pro 64bit`打开文件后，按`F5`反编译，可以看到主函数的`C`语言代码如下：

```c
int __cdecl __noreturn main(int argc, const char **argv, const char **envp)
{
  __pid_t v3; // eax
  size_t v4; // rax
  ssize_t v5; // rbx
  bool v6; // al
  bool bCheckPtrace; // [rsp+13h] [rbp-1BDh]
  ssize_t numRead; // [rsp+18h] [rbp-1B8h]
  ssize_t numReada; // [rsp+18h] [rbp-1B8h]
  char bufWrite[200]; // [rsp+20h] [rbp-1B0h] BYREF
  char bufParentRead[200]; // [rsp+F0h] [rbp-E0h] BYREF
  unsigned __int64 v12; // [rsp+1B8h] [rbp-18h]

  v12 = __readfsqword(0x28u);
  bCheckPtrace = detectDebugging();
  if ( pipe(pParentWrite) == -1 )
    exit(1);
  if ( pipe(pParentRead) == -1 )
    exit(1);
  v3 = fork();
  if ( v3 != -1 )
  {
    if ( v3 )
    {
      close(pParentWrite[0]);
      close(pParentRead[1]);
      while ( 1 )
      {
        printf("Input key : ");
        memset(bufWrite, 0, sizeof(bufWrite));
        gets(bufWrite);
        v4 = strlen(bufWrite);
        v5 = write(pParentWrite[1], bufWrite, v4);
        if ( v5 != strlen(bufWrite) )
          printf("parent - partial/failed write");
        do
        {
          memset(bufParentRead, 0, sizeof(bufParentRead));
          numReada = read(pParentRead[0], bufParentRead, 0xC8uLL);
          v6 = bCheckPtrace || checkDebuggerProcessRunning();
          if ( !v6 && checkStringIsNumber(bufParentRead) && atoi(bufParentRead) )
          {
            puts("True");
            if ( close(pParentWrite[1]) == -1 )
              exit(1);
            exit(0);
          }
          puts("Wrong !!!\n");
        }
        while ( numReada == -1 );
      }
    }
    close(pParentWrite[1]);
    close(pParentRead[0]);
    while ( 1 )
    {
      memset(bufParentRead, 0, sizeof(bufParentRead));
      numRead = read(pParentWrite[0], bufParentRead, 0xC8uLL);
      if ( numRead == -1 )
        break;
      if ( numRead )
      {
        if ( !childCheckDebugResult()
          && bufParentRead[0] == 123   // 判断第一位是不是 {
          && strlen(bufParentRead) == 42   // 字符串长度是否为42
          && !strncmp(&bufParentRead[1], "53fc275d81", 0xAuLL)
          && bufParentRead[strlen(bufParentRead) - 1] == 125
          && !strncmp(&bufParentRead[31], "4938ae4efd", 0xAuLL)
          && confuseKey(bufParentRead, 42)
          && !strncmp(bufParentRead, "{daf29f59034938ae4efd53fc275d81053ed5be8c}", 0x2AuLL) )
        {
          responseTrue();
        }
        else
        {
          responseFalse();
        }
      }
    }
    exit(1);
  }
  exit(1);
}
```

双击`confuseKey()`函数可以看到以下源代码：

```c
bool __cdecl confuseKey(char *szKey, int iKeyLength)
{
  char szPart1[15]; // [rsp+10h] [rbp-50h] BYREF
  char szPart2[15]; // [rsp+20h] [rbp-40h] BYREF
  char szPart3[15]; // [rsp+30h] [rbp-30h] BYREF
  char szPart4[15]; // [rsp+40h] [rbp-20h] BYREF
  unsigned __int64 v7; // [rsp+58h] [rbp-8h]

  v7 = __readfsqword(0x28u);
  *(_QWORD *)szPart1 = 0LL;
  *(_DWORD *)&szPart1[8] = 0;
  *(_WORD *)&szPart1[12] = 0;
  szPart1[14] = 0;
  *(_QWORD *)szPart2 = 0LL;
  *(_DWORD *)&szPart2[8] = 0;
  *(_WORD *)&szPart2[12] = 0;
  szPart2[14] = 0;
  *(_QWORD *)szPart3 = 0LL;
  *(_DWORD *)&szPart3[8] = 0;
  *(_WORD *)&szPart3[12] = 0;
  szPart3[14] = 0;
  *(_QWORD *)szPart4 = 0LL;
  *(_DWORD *)&szPart4[8] = 0;
  *(_WORD *)&szPart4[12] = 0;
  szPart4[14] = 0;
  if ( iKeyLength != 42 )
    return 0;
  if ( !szKey )
    return 0;
  if ( strlen(szKey) != 42 )
    return 0;
  if ( *szKey != 123 )
    return 0;
  strncpy(szPart1, szKey + 1, 0xAuLL);
  strncpy(szPart2, szKey + 11, 0xAuLL);
  strncpy(szPart3, szKey + 21, 0xAuLL);
  strncpy(szPart4, szKey + 31, 0xAuLL);
  memset(szKey, 0, 0x2AuLL);
  *szKey = 123;
  strcat(szKey, szPart3);
  strcat(szKey, szPart4);
  strcat(szKey, szPart1);
  strcat(szKey, szPart2);
  szKey[41] = 125;
  return 1;
}
```

根据代码逻辑，编写`Python`代码即可得到`flag`，提交`53fc275d81053ed5be8cdaf29f59034938ae4efd`即可。

```python
s = 'daf29f59034938ae4efd53fc275d81053ed5be8c'
szPart1 = s[0:10]
szPart2 = s[10:20]
szPart3 = s[20:30]
szPart4 = s[30:]
flag = szPart3 + szPart4 +szPart1 + szPart2
print(flag)
```

------

### [simple-check-100](https://adworld.xctf.org.cn/task/answer?type=reverse&number=4&grade=1&id=4709)

这题附件是一个压缩包，解压缩后可以得到三个文件：`task9_x86_simple-check-100.exe`，`task9_x86_simple-check-100`，`task9_x86_64_simple-check-100`，那就随机挑选一个吧。用`IDA Pro 64bit`打开文件`./task9_x86_64_simple-check-100`后，按`F5`反编译后，可以看到主函数的`C`语言代码如下：

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  void *v3; // rsp
  const char **v5; // [rsp+0h] [rbp-60h] BYREF
  int v6; // [rsp+Ch] [rbp-54h]
  char v7[28]; // [rsp+1Ch] [rbp-44h] BYREF
  __int64 v8; // [rsp+38h] [rbp-28h]
  const char ***v9; // [rsp+40h] [rbp-20h]
  unsigned __int64 v10; // [rsp+48h] [rbp-18h]

  v6 = argc;
  v5 = argv;
  v10 = __readfsqword(0x28u);
  v7[0] = 84;
  v7[1] = -56;
  v7[2] = 126;
  v7[3] = -29;
  v7[4] = 100;
  v7[5] = -57;
  v7[6] = 22;
  v7[7] = -102;
  v7[8] = -51;
  v7[9] = 17;
  v7[10] = 101;
  v7[11] = 50;
  v7[12] = 45;
  v7[13] = -29;
  v7[14] = -45;
  v7[15] = 67;
  v7[16] = -110;
  v7[17] = -87;
  v7[18] = -99;
  v7[19] = -46;
  v7[20] = -26;
  v7[21] = 109;
  v7[22] = 44;
  v7[23] = -45;
  v7[24] = -74;
  v7[25] = -67;
  v7[26] = -2;
  v7[27] = 106;
  v8 = 19LL;
  v3 = alloca(32LL);
  v9 = &v5;
  printf("Key: ");
  __isoc99_scanf("%s", v9);
  if ( (unsigned int)check_key(v9) )
    interesting_function(v7);
  else
    puts("Wrong");
  return 0;
}
```

双击`check_key()`函数，查看源代码：

```c
_BOOL8 __fastcall check_key(__int64 a1)
{
  int v2; // [rsp+8h] [rbp-10h]
  int i; // [rsp+Ch] [rbp-Ch]

  v2 = 0;
  for ( i = 0; i <= 4; ++i )
    v2 += *(_DWORD *)(4LL * i + a1);
  return v2 == -559038737;
}
```

双击`interesting_function()`函数，查看源代码：

```c
int __fastcall interesting_function(__int64 a1)
{
  int *v1; // rax
  unsigned int v3; // [rsp+1Ch] [rbp-24h] BYREF
  int i; // [rsp+20h] [rbp-20h]
  int j; // [rsp+24h] [rbp-1Ch]
  __int64 v6; // [rsp+28h] [rbp-18h]
  int *v7; // [rsp+30h] [rbp-10h]
  unsigned __int64 v8; // [rsp+38h] [rbp-8h]

  v8 = __readfsqword(0x28u);
  LODWORD(v1) = a1;
  v6 = a1;
  for ( i = 0; i <= 6; ++i )
  {
    v3 = *(_DWORD *)(4LL * i + v6) ^ 0xDEADBEEF;
    v1 = (int *)&v3;
    v7 = (int *)&v3;
    for ( j = 3; j >= 0; --j )
      LODWORD(v1) = putchar((char)(*((_BYTE *)v7 + j) ^ flag_data[4 * i + j]));
  }
  return (int)v1;
}
```

用`pwndbg`进行动态调试，`b *0x4008e2`设置断点，修改`$eax`寄存器的值后按`c`继续运行可以得到`flag_is_you_know_cracking!!!`。

```bash
┌──(tyd㉿kali-linux)-[~/ctf/reverse/adworld/simple-check-100]
└─$ gdb ./task9_x86_64_simple-check-100 -q
pwndbg: loaded 198 commands. Type pwndbg [filter] for a list.
pwndbg: created $rebase, $ida gdb functions (can be used with print/break)
Reading symbols from ./task9_x86_64_simple-check-100...
(No debugging symbols found in ./task9_x86_64_simple-check-100)
pwndbg> b *0x4008e2
Breakpoint 1 at 0x4008e2
pwndbg> r
Starting program: /home/tyd/ctf/reverse/adworld/simple-check-100/task9_x86_64_simple-check-100 
Key: 123456

Breakpoint 1, 0x00000000004008e2 in main ()
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA                                                                                                
───────────────────────────────────────────────[ REGISTERS ]──────────────────────────────────────────────── 
 RAX  0x0
 RBX  0x7fffffffde70 —▸ 0x7fffffffdfc8 —▸ 0x7fffffffe2ff ◂— '/home/tyd/ctf/reverse/adworld/simple-check-100/task9_x86_64_simple-check-100'
 RCX  0x0
 RDX  0x10
 RDI  0x7fffffffde50 ◂— 0x363534333231 /* '123456' */
 RSI  0xa
 R8   0x0
 R9   0xffffffffffffff80
 R10  0x7ffff7f603c0 (_nl_C_LC_CTYPE_class+256) ◂— 0x2000200020002
 R11  0x246
 R12  0x4005b0 (_start) ◂— xor    ebp, ebp
 R13  0x0
 R14  0x0
 R15  0x0
 RBP  0x7fffffffded0 —▸ 0x400920 (__libc_csu_init) ◂— push   r15
 RSP  0x7fffffffde50 ◂— 0x363534333231 /* '123456' */
 RIP  0x4008e2 (main+294) ◂— test   eax, eax
───────────────────────────────────────────────[ DISASM ]───────────────────────────────────────────────────
 ► 0x4008e2 <main+294>    test   eax, eax
   0x4008e4 <main+296>    je     main+312                      <main+312>
    ↓
   0x4008f4 <main+312>    mov    edi, 0x4009f5
   0x4008f9 <main+317>    call   puts@plt                      <puts@plt>
 
   0x4008fe <main+322>    mov    eax, 0
   0x400903 <main+327>    mov    rsp, rbx
   0x400906 <main+330>    mov    rcx, qword ptr [rbp - 0x18]
   0x40090a <main+334>    xor    rcx, qword ptr fs:[0x28]
   0x400913 <main+343>    je     main+350                      <main+350>
 
   0x400915 <main+345>    call   __stack_chk_fail@plt                      <__stack_chk_fail@plt>
 
   0x40091a <main+350>    mov    rbx, qword ptr [rbp - 8]
─────────────────────────────────────────────[ STACK ]──────────────────────────────────────────────────────
00:0000│ rdi rsp 0x7fffffffde50 ◂— 0x363534333231 /* '123456' */
01:0008│         0x7fffffffde58 ◂— 0x0
... ↓            2 skipped
04:0020│ rbx     0x7fffffffde70 —▸ 0x7fffffffdfc8 —▸ 0x7fffffffe2ff ◂— '/home/tyd/ctf/reverse/adworld/simple-check-100/task9_x86_64_simple-check-100'
05:0028│         0x7fffffffde78 ◂— 0x100000000
06:0030│         0x7fffffffde80 ◂— 0xf0b5ff
07:0038│         0x7fffffffde88 ◂— 0xe37ec854000000c2
───────────────────────────────────────────────[ BACKTRACE ]────────────────────────────────────────────────
 ► f 0         0x4008e2 main+294
   f 1   0x7ffff7e14d0a __libc_start_main+234
────────────────────────────────────────────────────────────────────────────────────────────────────────────
pwndbg> set $rax = 1
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
───────────────────────────────────────────────[ REGISTERS ]──────────────────────────────────────────────── 
*RAX  0x1
 RBX  0x7fffffffde70 —▸ 0x7fffffffdfc8 —▸ 0x7fffffffe2ff ◂— '/home/tyd/ctf/reverse/adworld/simple-check-100/task9_x86_64_simple-check-100'
 RCX  0x0
 RDX  0x10
 RDI  0x7fffffffde50 ◂— 0x363534333231 /* '123456' */
 RSI  0xa
 R8   0x0
 R9   0xffffffffffffff80
 R10  0x7ffff7f603c0 (_nl_C_LC_CTYPE_class+256) ◂— 0x2000200020002
 R11  0x246
 R12  0x4005b0 (_start) ◂— xor    ebp, ebp
 R13  0x0
 R14  0x0
 R15  0x0
 RBP  0x7fffffffded0 —▸ 0x400920 (__libc_csu_init) ◂— push   r15
 RSP  0x7fffffffde50 ◂— 0x363534333231 /* '123456' */
 RIP  0x4008e2 (main+294) ◂— test   eax, eax
───────────────────────────────────────────────[ DISASM ]───────────────────────────────────────────────────
 ► 0x4008e2 <main+294>    test   eax, eax
   0x4008e4 <main+296>    je     main+312                      <main+312>
 
   0x4008e6 <main+298>    lea    rax, [rbp - 0x44]
   0x4008ea <main+302>    mov    rdi, rax
   0x4008ed <main+305>    call   interesting_function                      <interesting_function>
 
   0x4008f2 <main+310>    jmp    main+322                      <main+322>
 
   0x4008f4 <main+312>    mov    edi, 0x4009f5
   0x4008f9 <main+317>    call   puts@plt                      <puts@plt>
 
   0x4008fe <main+322>    mov    eax, 0
   0x400903 <main+327>    mov    rsp, rbx
   0x400906 <main+330>    mov    rcx, qword ptr [rbp - 0x18]
─────────────────────────────────────────────[ STACK ]──────────────────────────────────────────────────────
00:0000│ rdi rsp 0x7fffffffde50 ◂— 0x363534333231 /* '123456' */
01:0008│         0x7fffffffde58 ◂— 0x0
... ↓            2 skipped
04:0020│ rbx     0x7fffffffde70 —▸ 0x7fffffffdfc8 —▸ 0x7fffffffe2ff ◂— '/home/tyd/ctf/reverse/adworld/simple-check-100/task9_x86_64_simple-check-100'
05:0028│         0x7fffffffde78 ◂— 0x100000000
06:0030│         0x7fffffffde80 ◂— 0xf0b5ff
07:0038│         0x7fffffffde88 ◂— 0xe37ec854000000c2
───────────────────────────────────────────────[ BACKTRACE ]────────────────────────────────────────────────
 ► f 0         0x4008e2 main+294
   f 1   0x7ffff7e14d0a __libc_start_main+234
────────────────────────────────────────────────────────────────────────────────────────────────────────────
pwndbg> c
Continuing.
flag_is_you_know_cracking!!![Inferior 1 (process 408560) exited normally]
```

------

### [answer_to_everything](https://adworld.xctf.org.cn/task/answer?type=reverse&number=4&grade=1&id=5511)

用 `file`查看附件`main.exe`，可以看到信息`./main.exe: ELF 64-bit LSB executable, x86-64`，用`IDA Pro 64bit`打开文件后，按`F5`反编译可以看到主函数的`C`语言代码如下：

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  unsigned int v4; // [rsp+Ch] [rbp-4h] BYREF

  printf("Gimme: ");
  __isoc99_scanf("%d", &v4);
  not_the_flag(v4);
  return 0;
}
```

双击`not_the_flag()`函数查看详情：

```c
__int64 __fastcall not_the_flag(int a1)
{
  if ( a1 == 42 )
    puts("Cipher from Bill \nSubmit without any tags\n#kdudpeh");
  else
    puts("YOUSUCK");
  return 0LL;
}
```

根据题目描述的`sha1`，编写`Python`代码对`kdudpeh`进行`sha1`加密，得到`flag{80ee2a3fe31da904c596d993f7f1de4827c1450a}`。

```python
from hashlib import sha1

flag = sha1('kdudpeh'.encode('utf-8')).hexdigest()
print(f'flag{{{flag}}}')
```

------

## PwnTheBox

### [签到](https://ce.pwnthebox.com/challenges?type=2&id=86)

用 `file`查看附件`qiandao.exe`，可以看到信息`./qiandao.exe: PE32 executable (console) Intel 80386, for MS Windows`，用`IDA Pro 32bit`打开文件后，按`F5`反编译看到主函数的`C`语言代码中有`flag{12ab82cd686a42850ab562ff2f9f2416}`，提交即可。

------

### [The Flag Vault](https://ce.pwnthebox.com/challenges?keynote=84&id=1894)

用 `file`查看附件`The_Flag_Vault`，可以看到信息`./The_Flag_Vault: ELF 64-bit LSB pie executable, x86-64`，用`IDA Pro 64bit`打开文件后，按`F5`反编译可以看到主函数的`C`语言代码如下：

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  __int16 v4; // [rsp+6h] [rbp-6Ah] BYREF
  __int16 v5; // [rsp+8h] [rbp-68h] BYREF
  __int16 v6; // [rsp+Ah] [rbp-66h] BYREF
  __int16 v7; // [rsp+Ch] [rbp-64h] BYREF
  __int16 v8; // [rsp+Eh] [rbp-62h] BYREF
  __int16 v9; // [rsp+10h] [rbp-60h] BYREF
  __int16 v10; // [rsp+12h] [rbp-5Eh] BYREF
  __int16 v11; // [rsp+14h] [rbp-5Ch] BYREF
  __int16 v12; // [rsp+16h] [rbp-5Ah] BYREF
  __int16 v13; // [rsp+18h] [rbp-58h] BYREF
  __int16 v14; // [rsp+1Ah] [rbp-56h] BYREF
  __int16 v15; // [rsp+1Ch] [rbp-54h] BYREF
  __int16 v16; // [rsp+1Eh] [rbp-52h] BYREF
  __int16 v17; // [rsp+20h] [rbp-50h] BYREF
  __int16 v18; // [rsp+22h] [rbp-4Eh] BYREF
  __int16 v19; // [rsp+24h] [rbp-4Ch] BYREF
  __int16 v20; // [rsp+26h] [rbp-4Ah] BYREF
  __int16 v21; // [rsp+28h] [rbp-48h] BYREF
  __int16 v22; // [rsp+2Ah] [rbp-46h] BYREF
  __int16 v23; // [rsp+2Ch] [rbp-44h] BYREF
  __int16 v24; // [rsp+2Eh] [rbp-42h] BYREF
  char s2[32]; // [rsp+30h] [rbp-40h] BYREF
  char s1[24]; // [rsp+50h] [rbp-20h] BYREF
  unsigned __int64 v27; // [rsp+68h] [rbp-8h]

  v27 = __readfsqword(0x28u);
  v4 = 75;
  v5 = 125;
  v6 = 119;
  v7 = 99;
  v8 = 48;
  v9 = 84;
  v10 = 70;
  v11 = 67;
  v12 = 95;
  v13 = 109;
  v14 = 116;
  v15 = 114;
  v16 = 118;
  v17 = 115;
  v18 = 123;
  v19 = 110;
  v20 = 51;
  v21 = 101;
  v22 = 103;
  v23 = 108;
  v24 = 105;
  strcpy(s1, "abracadabrahahaha");
  printf("\nHi there!\n\nPlease enter the password to unlock the flag vault: ");
  __isoc99_scanf("%s", s2);
  if ( !strcmp(s1, s2) )
  {
    puts("\nCongratulations! Here is your flag:\n");
    printf(
      "%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s\n\n",
      (const char *)&v4,
      (const char *)&v11,
      (const char *)&v9,
      (const char *)&v10,
      (const char *)&v18,
      (const char *)&v6,
      (const char *)&v21,
      (const char *)&v23,
      (const char *)&v7,
      (const char *)&v8,
      (const char *)&v13,
      (const char *)&v21,
      (const char *)&v12,
      (const char *)&v14,
      (const char *)&v8,
      (const char *)&v12,
      (const char *)&v15,
      (const char *)&v21,
      (const char *)&v16,
      (const char *)&v21,
      (const char *)&v15,
      (const char *)&v17,
      (const char *)&v21,
      (const char *)&v12,
      (const char *)&v20,
      (const char *)&v19,
      (const char *)&v22,
      (const char *)&v24,
      (const char *)&v19,
      (const char *)&v21,
      (const char *)&v21,
      (const char *)&v15,
      (const char *)&v24,
      (const char *)&v19,
      (const char *)&v22,
      (const char *)&v5);
  }
  else
  {
    puts(
      "\n"
      "Sorry!\n"
      "\n"
      "You have entered a wrong password! \n"
      "\n"
      "Please try with a valid one!\n"
      "\n"
      "If you don't have the password, you can buy that here at https://knightsquad.org");
  }
  return 0;
}
```

注意到当用户输入和字符串`abracadabrahahaha`相等时就会直接输出`flag`，提交`KCTF{welc0me_t0_reverse_3ngineering}`即可。

```bash
┌──(tyd㉿kali-linux)-[~/ctf/reverse/pwnthebox]
└─$ ./The_Flag_Vault

Hi there!

Please enter the password to unlock the flag vault: abracadabrahahaha

Congratulations! Here is your flag:

KCTF{welc0me_t0_reverse_3ngineering}
```

------

### [Baby Shark](https://ce.pwnthebox.com/challenges?keynote=84&id=1889)

根据题目描述，使用`JD-GUI`打开`.jar`附件进行反编译，可以看到`Flag.class`中有`KCTF{this_is_not_the_flag}`，但是它是假的，真正的`flag`被`base64`加密后存放在`Strings.class`中。

在`Strings.class`中可以看到`_0xflag = "S0NURns3SDE1X1dANV8zNDVZX1IxNkg3P30=";`，编写`Python`代码进行`base64`解码即可得到`flag`，提交`KCTF{7H15_W@5_345Y_R16H7?}`即可。

```python
from base64 import *

flag = b64decode('S0NURns3SDE1X1dANV8zNDVZX1IxNkg3P30=').decode('utf-8')
print(flag) # KCTF{7H15_W@5_345Y_R16H7?}
```

------

### [The Encoder](https://ce.pwnthebox.com/challenges?keynote=84&id=1893)

用 `file`查看附件`flag_checker`，可以看到信息`./the_encoder.out: ELF 64-bit LSB executable, x86-64`，用`IDA Pro 64bit`打开文件后，按`F5`反编译可以看到主函数的`C`语言代码如下：

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int v3; // eax
  char s[52]; // [rsp+0h] [rbp-40h] BYREF
  int v6; // [rsp+34h] [rbp-Ch]
  int v7; // [rsp+38h] [rbp-8h]
  int i; // [rsp+3Ch] [rbp-4h]

  v7 = 1337;
  v6 = 0;
  puts("Welcome to the encoder");
  puts("Please give me a plain text of max 40 characters");
  fgets(s, 40, _bss_start);
  for ( i = 0; ; ++i )
  {
    v3 = countChar(s);
    if ( i >= v3 )
      break;
    v6 = s[i];
    printf("%d ", (unsigned int)(v6 + v7));
  }
  return 0;
}
```

根据`C`语言代码逻辑和题目描述中给出的二进制码，编写`Python`代码运行得到`flag`，提交`KCTF{s1Mpl3_3Nc0D3r_1337}`即可。

```python
s = "1412 1404 1421 1407 1460 1452 1386 1414 1449 1445 1388 1432 1388 1415 1436 1385 1405 1388 1451 1432 1386 1388 1388 1392 1462"

def convert2char(i):
    return chr(int(i)-1337)

flag = ''.join(list(map(convert2char, s.split())))
print(flag) # KCTF{s1Mpl3_3Nc0D3r_1337}
```

------

### [Flag Checker](https://ce.pwnthebox.com/challenges?keynote=84&id=1890)

用 `file`查看附件`flag_checker`，可以看到信息`./flag_checker: ELF 64-bit LSB executable, x86-64`，用`IDA Pro 64bit`打开文件后，按`F5`反编译可以看到主函数的`C`语言代码如下：

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char v4[512]; // [rsp+0h] [rbp-240h] BYREF
  char v5[51]; // [rsp+200h] [rbp-40h] BYREF
  char v6; // [rsp+233h] [rbp-Dh]
  int v7; // [rsp+234h] [rbp-Ch]
  int j; // [rsp+238h] [rbp-8h]
  int i; // [rsp+23Ch] [rbp-4h]

  strcpy(v5, "08'5[Z'Y:H3?X2K3V)?D2G3?H,N6?G$R(G]");
  printf("Give me a flag : ");
  __isoc99_scanf("%s", v4);
  for ( i = 0; v4[i]; ++i )
  {
    if ( v4[i] <= 64 || v4[i] > 90 )   
    {
      if ( v4[i] <= 96 || v4[i] > 122 )   
        v4[i] = v4[i];
      else // a <= v4[i] <= z
        v4[i] = -37 - v4[i];
    }
    else // A <= v4[i] <= Z
    {
      v4[i] = -101 - v4[i];
    }
  }
  for ( j = 0; v4[j]; ++j )
    v4[j] -= 32;
  v7 = 0;
  v6 = 0;
  while ( v5[v7] )
  {
    if ( v5[v7] != v4[v7] )
    {
      v6 = 0;
      break;
    }
    v6 = 1;
    ++v7;
  }
  if ( v6 )
    puts("You have entered the right flag.");
  else
    puts("Sorry ! Its wrong flag.");
  return 0;
}
```

根据`C`语言代码逻辑编写`Python`代码运行得到`flag`，提交`KCTF{aTbAsH_cIpHeR_wItH_sOmE_tWiSt}`即可。

```python
s = "08'5[Z'Y:H3?X2K3V)?D2G3?H,N6?G$R(G]"
flag = ''
for i in range(len(s)):
    t = ord(s[i]) + 32
    if 65 <= t <= 90:  # 'A'~'Z'
        flag += chr(256-101-t)
    elif 97 <= t <= 122:  # 'a'~'z'
        flag += chr(256-37-t)
    else:
        flag += chr(t)
print(flag) # KCTF{aTbAsH_cIpHeR_wItH_sOmE_tWiSt}
```

------

### [Gifted](https://ce.pwnthebox.com/challenges?type=2&id=68)

用 `file`查看附件`gifted`，可以看到信息`./gifted: ELF 32-bit LSB executable, Intel 80386`，用`IDA Pro 32bit`打开文件后，按`F5`反编译可以看到主函数的`C`语言代码如下：

```c
void __cdecl __noreturn main()
{
  char *s2; // [esp+Ch] [ebp-Ch]

  printf("Enter the flag: ");
  s2 = (char *)malloc(0x3E8u);
  __isoc99_scanf("%s", s2);
  if ( !strcmp("AlexCTF{Y0u_h4v3_45t0n15h1ng_futur3_1n_r3v3r5ing}", s2) )
  {
    puts("You got it right dude!");
    exit(0);
  }
  puts("Try harder!");
  exit(0);
}
```

可以看到一串特殊的字符串，那就是本题的`flag`，提交`AlexCTF{Y0u_h4v3_45t0n15h1ng_futur3_1n_r3v3r5ing}`即可。

------

### [Re1](https://ce.pwnthebox.com/challenges?type=2&id=87)

用 `file`查看附件`re1.exe`，可以看到信息`./re1.exe: PE32 executable (console) Intel 80386, for MS Windows`，用`IDA Pro 32bit`打开文件后，可以在汇编语言代码中看到以下信息：

```c
.text:00401469                 call    ___main
.text:0040146E                 mov     dword ptr [esp], offset Format ; "Hi~ this is a babyre"
.text:00401475                 call    _printf
.text:0040147A                 mov     byte ptr [esp+2Fh], 66h ; 'f'
.text:0040147F                 mov     byte ptr [esp+2Eh], 6Ch ; 'l'
.text:00401484                 mov     byte ptr [esp+2Dh], 61h ; 'a'
.text:00401489                 mov     byte ptr [esp+2Ch], 67h ; 'g'
.text:0040148E                 mov     byte ptr [esp+2Bh], 7Bh ; '{'
.text:00401493                 mov     byte ptr [esp+2Ah], 52h ; 'R'
.text:00401498                 mov     byte ptr [esp+29h], 65h ; 'e'
.text:0040149D                 mov     byte ptr [esp+28h], 5Fh ; '_'
.text:004014A2                 mov     byte ptr [esp+27h], 31h ; '1'
.text:004014A7                 mov     byte ptr [esp+26h], 73h ; 's'
.text:004014AC                 mov     byte ptr [esp+25h], 5Fh ; '_'
.text:004014B1                 mov     byte ptr [esp+24h], 53h ; 'S'
.text:004014B6                 mov     byte ptr [esp+23h], 30h ; '0'
.text:004014BB                 mov     byte ptr [esp+22h], 5Fh ; '_'
.text:004014C0                 mov     byte ptr [esp+21h], 43h ; 'C'
.text:004014C5                 mov     byte ptr [esp+20h], 30h ; '0'
.text:004014CA                 mov     byte ptr [esp+1Fh], 4Fh ; 'O'
.text:004014CF                 mov     byte ptr [esp+1Eh], 4Ch ; 'L'
.text:004014D4                 mov     byte ptr [esp+1Dh], 7Dh ; '}'
.text:004014D9                 mov     eax, 0
```

本题的`flag`直接写在`.text`段中了，提交`flag{Re_1s_S0_C0OL}`即可。

------

### [Baby_python](https://ce.pwnthebox.com/challenges?type=2&id=112)

这道题的附件是一个`.pyc`文件，`.pyc`是一种二进制文件，是由`.py`文件经过编译后生成的文件，是一种`byte code`，`.py`文件变成`.pyc`文件后，运行加载的速度会有所提高，并且可以实现部分的源码隐藏，保证了`Python`做商业化软件时的安全性。

我们可以使用[**python-uncompyle6**](https://github.com/rocky/python-uncompyle6)来对`.pyc`文件进行反编译从而得到`.py`文件。

```bash
pip install uncompyle6
uncompyle6 -o . pyc.pyc
```

反编译后得到的`.py`文件源代码信息如下：

```python
# uncompyle6 version 3.7.4
# Python bytecode 2.7 (62211)
# Decompiled from: Python 3.8.8 (default, Apr 13 2021, 15:08:03) [MSC v.1916 64 bit (AMD64)]
# Embedded file name: flag.py
# Compiled at: 2019-02-21 14:39:31
import base64

def encode(message):
    s = ''
    for i in message:
        x = ord(i) ^ 32
        x = x + 16
        s += chr(x)

    return base64.b64encode(s)


correct = 'eYNzc2tjWV1gXFWPYGlTbQ=='
flag = ''
print 'Input flag:'
flag = raw_input()
if encode(flag) == correct:
    print 'correct'
else:
    print 'wrong'
```

编写`Python`代码运行得到`flag`，提交`ISCC{simple_pyc}`即可。

```python
from base64 import *
s = b64decode('eYNzc2tjWV1gXFWPYGlTbQ==')
flag = ''
for i in s:
    flag += chr((i-16)^32)
print(flag) # ISCC{simple_pyc}
```

------

### [assembly-0](https://ce.pwnthebox.com/challenges?type=2&id=510)

这道题的附件 [intro_asm_rev.S](https://ce.pwnthebox.com/uploads/challenge/510/intro_asm_rev.S) 打开后汇编语言代码如下：

```assembly
.intel_syntax noprefix
.bits 32
	
.global asm0

asm0:
	push	ebp    ;保存栈帧状态
	mov	ebp,esp    ;将栈顶指针的值赋给栈底指针
	mov	eax,DWORD PTR [ebp+0x8] ;表示双字指向数据位于ebp值加0x8处，即0xd8
	mov	ebx,DWORD PTR [ebp+0xc] ;表示双字指向数据位于ebp值加0xc处，即0x7a
	mov	eax,ebx  ;将ebx的值赋值给eax
	mov	esp,ebp  ;将栈底指针的值赋给栈顶指针
	pop	ebp	     ;至此栈帧已恢复
	ret          ;返回父函数
```

`asm0(0xd8,0x7a)` 将调用汇编函数`asm0`，`intel`的入栈方式是从右至左入栈，`0x7a`高地址，`0xd8`低地址，栈是从高地址向低地址生长的。因此`(eax) = 0xd8`，`(ebx) = 0x7a`，当指令`mov eax,ebx`执行完后，`(eax) = 0x7a`，将栈底指针`ebp`赋值给栈顶指针`esp`进行惰性删除恢复，接着弹出`ebp`，此时`eax`是运算值保存的寄存器，因此返回值即`0x7a`，`flag`就是`flag{0x7a}`，提交即可。

------

### [EasyRe](https://ce.pwnthebox.com/challenges?type=2&id=610)

用 `file`查看附件`EasyRe.exe`，可以看到信息`./EasyRe.exe: PE32 executable (console) Intel 80386, for MS Windows`，用`IDA Pro 32bit`打开文件后，按`shift+F12`查看`Strings window`可以看到`fc5e038d38a57032085441e7fe7010b0`，这一串特殊的字符串就是用于验证用户输入的，提交`flag{fc5e038d38a57032085441e7fe7010b0}`即可。

------

### [babyre](https://ce.pwnthebox.com/challenges?type=2&id=692)

用 `file`查看附件`baby.exe`，可以看到信息`./baby.exe: PE32 executable (console) Intel 80386, for MS Windows`，用`IDA Pro 32bit`打开文件后，可以在汇编语言代码中看到以下信息：

```assembly
call    ___main
mov     dword ptr [esp], offset Format ; "Hi~ this is a babyre"
call    _printf
mov     byte ptr [esp+2Fh], 66h ; 'f'
mov     byte ptr [esp+2Eh], 6Ch ; 'l'
mov     byte ptr [esp+2Dh], 61h ; 'a'
mov     byte ptr [esp+2Ch], 67h ; 'g'
mov     byte ptr [esp+2Bh], 7Bh ; '{'
mov     byte ptr [esp+2Ah], 52h ; 'R'
mov     byte ptr [esp+29h], 65h ; 'e'
mov     byte ptr [esp+28h], 5Fh ; '_'
mov     byte ptr [esp+27h], 31h ; '1'
mov     byte ptr [esp+26h], 73h ; 's'
mov     byte ptr [esp+25h], 5Fh ; '_'
mov     byte ptr [esp+24h], 53h ; 'S'
mov     byte ptr [esp+23h], 30h ; '0'
mov     byte ptr [esp+22h], 5Fh ; '_'
mov     byte ptr [esp+21h], 43h ; 'C'
mov     byte ptr [esp+20h], 30h ; '0'
mov     byte ptr [esp+1Fh], 4Fh ; 'O'
mov     byte ptr [esp+1Eh], 4Ch ; 'L'
mov     byte ptr [esp+1Dh], 7Dh ; '}'
mov     eax, 0
```

提交`flag{Re_1s_S0_C0OL}`即可。

------

### [JustRE](https://ce.pwnthebox.com/challenges?type=2&id=1150)

用 `file`查看附件`RE2.exe`，可以看到信息`./RE2.exe: MS-DOS executable PE32 executable (GUI) Intel 80386, for MS Windows, MZ for MS-DOS`，用`IDA Pro 32bit`打开文件后，按`F5`反编译后在`Functions window`中选择`DialogFunc`查看源码：

```c
INT_PTR __stdcall DialogFunc(HWND hWnd, UINT a2, WPARAM a3, LPARAM a4)
{
  CHAR String[100]; // [esp+0h] [ebp-64h] BYREF

  if ( a2 != 272 )
  {
    if ( a2 != 273 )
      return 0;
    if ( (_WORD)a3 != 1 && (_WORD)a3 != 2 )
    {
      sprintf(String, Format, ++dword_4099F0);
      if ( dword_4099F0 == 19999 )
      {
        sprintf(String, " BJD{%d%d2069a45792d233ac}", 19999, 0);
        SetWindowTextA(hWnd, String);
        return 0;
      }
      SetWindowTextA(hWnd, String);
      return 0;
    }
    EndDialog(hWnd, (unsigned __int16)a3);
  }
  return 1;
}
```

由`sprintf()`函数可以得到字符串`BJD{1999902069a45792d233ac}`，再根据题目描述，提交`flag{1999902069a45792d233ac}`即可。

------

### [Basics](https://ce.pwnthebox.com/challenges?type=2&id=1170)

用 `file`查看附件`calc`，可以看到信息`./calc: ELF 64-bit LSB pie executable, x86-64`，用`IDA Pro 64bit`打开文件后，按`shift+F12`查看`Strings window`可以看到`utflag{str1ngs_1s_y0ur_fr13nd}`，这一串特殊的字符串就是`flag`，但是直接提交不对，提交`flag{str1ngs_1s_y0ur_fr13nd}`即可。

------

### [babymips](https://ce.pwnthebox.com/challenges?type=2&id=1169)

用 `file`查看附件`babymips`，可以看到信息`./babymips: ELF 32-bit MSB executable, MIPS`，用`IDA Pro 32bit`打开文件后，按`F5`进行反编译可以看到主函数的源码如下：

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int v3; // $v0
  char v5[24]; // [sp+18h] [+18h] BYREF
  char v6[24]; // [sp+30h] [+30h] BYREF
  char v7[84]; // [sp+48h] [+48h] BYREF

  std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::basic_string(v5, argv, envp);
  v3 = std::operator<<<std::char_traits<char>>(&std::cout, "enter the flag");
  std::ostream::operator<<(v3, &std::endl<char,std::char_traits<char>>);
  std::operator>><char>(&std::cin, v5);
  memcpy(v7, &unk_4015F4, sizeof(v7));
  std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::basic_string(v6, v5);
  sub_401164((int)v7, (int)v6);
  std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::~basic_string(v6);
  std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::~basic_string(v5);
  return 0;
}
```

双击`unk_4015F4`变量可以在`.rodata`段看到以下信息：

```assembly
.rodata:004015F4 unk_4015F4:     .byte 0x62  # b          # DATA XREF: main+AC↑o
.rodata:004015F5                 .byte 0x6C  # l
.rodata:004015F6                 .byte 0x7F  # 
.rodata:004015F7                 .byte 0x76  # v
.rodata:004015F8                 .byte 0x7A  # z
.rodata:004015F9                 .byte 0x7B  # {
.rodata:004015FA                 .byte 0x66  # f
.rodata:004015FB                 .byte 0x73  # s
.rodata:004015FC                 .byte 0x76  # v
.rodata:004015FD                 .byte 0x50  # P
.rodata:004015FE                 .byte 0x52  # R
.rodata:004015FF                 .byte 0x7D  # }
.rodata:00401600                 .byte 0x40  # @
.rodata:00401601                 .byte 0x54  # T
.rodata:00401602                 .byte 0x55  # U
.rodata:00401603                 .byte 0x79  # y
.rodata:00401604                 .byte 0x40  # @
.rodata:00401605                 .byte 0x49  # I
.rodata:00401606                 .byte 0x47  # G
.rodata:00401607                 .byte 0x4D  # M
.rodata:00401608                 .byte 0x74  # t
.rodata:00401609                 .byte 0x19
.rodata:0040160A                 .byte 0x7B  # {
.rodata:0040160B                 .byte 0x6A  # j
.rodata:0040160C                 .byte 0x42  # B
.rodata:0040160D                 .byte  0xA
.rodata:0040160E                 .byte 0x4F  # O
.rodata:0040160F                 .byte 0x52  # R
.rodata:00401610                 .byte 0x7D  # }
.rodata:00401611                 .byte 0x69  # i
.rodata:00401612                 .byte 0x4F  # O
.rodata:00401613                 .byte 0x53  # S
.rodata:00401614                 .byte  0xC
.rodata:00401615                 .byte 0x64  # d
.rodata:00401616                 .byte 0x10
.rodata:00401617                 .byte  0xF
.rodata:00401618                 .byte 0x1E
.rodata:00401619                 .byte 0x4A  # J
.rodata:0040161A                 .byte 0x67  # g
.rodata:0040161B                 .byte    3
.rodata:0040161C                 .byte 0x7C  # |
.rodata:0040161D                 .byte 0x67  # g
.rodata:0040161E                 .byte    2
.rodata:0040161F                 .byte 0x6A  # j
.rodata:00401620                 .byte 0x31  # 1
.rodata:00401621                 .byte 0x67  # g
.rodata:00401622                 .byte 0x61  # a
.rodata:00401623                 .byte 0x37  # 7
.rodata:00401624                 .byte 0x7A  # z
.rodata:00401625                 .byte 0x62  # b
.rodata:00401626                 .byte 0x2C  # ,
.rodata:00401627                 .byte 0x2C  # ,
.rodata:00401628                 .byte  0xF
.rodata:00401629                 .byte 0x6E  # n
.rodata:0040162A                 .byte 0x17
.rodata:0040162B                 .byte    0
.rodata:0040162C                 .byte 0x16
.rodata:0040162D                 .byte  0xF
.rodata:0040162E                 .byte 0x16
.rodata:0040162F                 .byte  0xA
.rodata:00401630                 .byte 0x6D  # m
.rodata:00401631                 .byte 0x62  # b
.rodata:00401632                 .byte 0x73  # s
.rodata:00401633                 .byte 0x25  # %
.rodata:00401634                 .byte 0x39  # 9
.rodata:00401635                 .byte 0x76  # v
.rodata:00401636                 .byte 0x2E  # .
.rodata:00401637                 .byte 0x1C
.rodata:00401638                 .byte 0x63  # c
.rodata:00401639                 .byte 0x78  # x
.rodata:0040163A                 .byte 0x2B  # +
.rodata:0040163B                 .byte 0x74  # t
.rodata:0040163C                 .byte 0x32  # 2
.rodata:0040163D                 .byte 0x16
.rodata:0040163E                 .byte 0x20
.rodata:0040163F                 .byte 0x22  # "
.rodata:00401640                 .byte 0x44  # D
.rodata:00401641                 .byte 0x19
```

返回主函数双击`sub_401164()`函数可以看到以下源码：

```assembly
int __fastcall sub_401164(int a1, int a2)
{
  int v2; // $v0
  int result; // $v0
  int v4; // $v0
  unsigned int i; // [sp+1Ch] [+1Ch]

  if ( std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::size(a2) != 0x4E )
  {
LABEL_2:
    v2 = std::operator<<<std::char_traits<char>>(&std::cout, "incorrect");
    result = std::ostream::operator<<(v2, &std::endl<char,std::char_traits<char>>);
  }
  else
  {
    for ( i = 0; i < std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::size(a2); ++i )
    {
      if ( (*(char *)std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::operator[](a2, i) ^ (i + 23)) != *(char *)(a1 + i) )
        goto LABEL_2;
    }
    v4 = std::operator<<<std::char_traits<char>>(&std::cout, "correct!");
    result = std::ostream::operator<<(v4, &std::endl<char,std::char_traits<char>>);
  }
  return result;
}
```

根据该函数的逻辑，编写`Python`代码即可得到`flag`，虽然这个`flag`看起来像极了假的。

```python
l = [0x62, 0x6C, 0x7F, 0x76, 0x7A, 0x7B, 0x66, 0x73, 0x76, 0x50, 0x52, 0x7D, 0x40, 0x54, 0x55, 0x79, 0x40, 0x49, 0x47, 0x4D, 0x74, 0x19, 0x7B, 0x6A, 0x42, 0x0A, 0x4F, 0x52, 0x7D, 0x69, 0x4F, 0x53, 0x0C, 0x64, 0x10, 0x0F, 0x1E, 0x4A, 0x67, 0x03, 0x7C, 0x67, 0x02, 0x6A, 0x31, 0x67, 0x61, 0x37, 0x7A, 0x62, 0x2C, 0x2C, 0x0F, 0x6E, 0x17, 0x00, 0x16, 0x0F, 0x16, 0x0A, 0x6D, 0x62, 0x73, 0x25, 0x39, 0x76, 0x2E, 0x1C, 0x63, 0x78, 0x2B, 0x74, 0x32, 0x16, 0x20, 0x22, 0x44, 0x19]
flag = ''

for i in range(len(l)):
    flag += chr(l[i] ^ (23+i))
print(flag) # utflag{mips_cpp_gang_5VDm:~`N]ze;\)5%vZ=C'C(r#$q=*efD"ZNY_GX>6&sn.wF8$v*mvA@'}
```

------

### [pyre](https://ce.pwnthebox.com/challenges?type=2&id=1154)

这道题的附件是一个`.pyc`文件，`.pyc`是一种二进制文件，是由`.py`文件经过编译后生成的文件，是一种`byte code`，`.py`文件变成`.pyc`文件后，运行加载的速度会有所提高，并且可以实现部分的源码隐藏，保证了`Python`做商业化软件时的安全性。

我们可以使用[**python-uncompyle6**](https://github.com/rocky/python-uncompyle6)来对`.pyc`文件进行反编译从而得到`.py`文件。

```bash
pip install uncompyle6
uncompyle6 -o . encode.pyc
```

打开反编译得到的`encode.py`文件可以看到以下`Python2.x`版本的源码：

```python
# uncompyle6 version 3.7.4
# Python bytecode 2.7 (62211)
# Decompiled from: Python 3.8.8 (default, Apr 13 2021, 15:08:03) [MSC v.1916 64 bit (AMD64)]
# Embedded file name: encode.py
# Compiled at: 2019-08-19 21:01:57
print 'Welcome to Re World!'
print 'Your input1 is your flag~'
l = len(input1)
for i in range(l):
    num = ((input1[i] + i) % 128 + 128) % 128
    code += num

for i in range(l - 1):
    code[i] = code[i] ^ code[(i + 1)]

print code
code = ['\x1f', '\x12', '\x1d', '(', '0', '4', '\x01', '\x06', '\x14', '4', ',', '\x1b', 'U', '?', 'o', '6', '*', ':', '\x01', 'D', ';', '%', '\x13']
```

根据以上代码逻辑，编写`Python`代码运行得到`GWHT{Just_Re_1s_Ha66y!}`，直接提交不对，提交`flag{Just_Re_1s_Ha66y!}`正确。

```python
code = ['\x1f', '\x12', '\x1d', '(', '0', '4', '\x01', '\x06', '\x14', '4', ',', '\x1b', 'U', '?', 'o', '6', '*', ':', '\x01', 'D', ';', '%', '\x13']
flag = ''
for i in range(len(code)-1, 0, -1):
    code[i-1] = chr(ord(code[i]) ^ ord(code[i-1]))

for i in range(len(code)):
    flag += chr((ord(code[i])-i)%128)
print(flag) # GWHT{Just_Re_1s_Ha66y!}
print(flag.replace("GWHT", "flag")) # flag{Just_Re_1s_Ha66y!}
```

------

### [easy_python](https://ce.pwnthebox.com/challenges?type=2&id=111)

这道题的附件是一个`.pyc`文件，`.pyc`是一种二进制文件，是由`.py`文件经过编译后生成的文件，是一种`byte code`，`.py`文件变成`.pyc`文件后，运行加载的速度会有所提高，并且可以实现部分的源码隐藏，保证了`Python`做商业化软件时的安全性。

我们可以使用[**python-uncompyle6**](https://github.com/rocky/python-uncompyle6)来对`.pyc`文件进行反编译从而得到`.py`文件。

```bash
pip install uncompyle6
uncompyle6 -o . encode.pyc
```

打开反编译得到的`encode.py`文件可以看到以下`Python2.x`版本的源码：

```python
# uncompyle6 version 3.7.4
# Python bytecode 3.6 (3379)
# Decompiled from: Python 3.8.8 (default, Apr 13 2021, 15:08:03) [MSC v.1916 64 bit (AMD64)]
# Embedded file name: /mnt/hgfs/D/python/python-work/testCTF/内蒙网信办/easypython.py
# Compiled at: 2020-08-11 15:14:54
# Size of source mod 2**32: 332 bytes
import hashlib
flag = 'flag{this_py_is_very_?}'
print(flag)
print("answer's length is 5!")
answer = input('Please input answer:')
hash = hashlib.md5()
hash.update(answer.encode(encoding='utf8'))
result = hash.hexdigest()
if result == 'ecb7b00b736eda5dfb52db91f1cb297b':
    print('Right!')
else:
    print('Error!')
```

`hashlib.md5()`是用于`md5`加密的，`hash.update(answer.encode(encoding='utf8'))`对用户输入的字符串`answer`进行了`md5`加密，而`hash.hexdigest()` 返回十六进制数据字符串值给字符串`result`。当`result`和`ecb7b00b736eda5dfb52db91f1cb297b`相等时，说明用户输入的字符串正确。使用`md5`在线工具解密后得到字符串`e4sy_`，因此本题`flag`是`flag{this_py_is_very_e4sy_}`。

------

### [Easy_apk](https://ce.pwnthebox.com/challenges?type=2&id=115)

使用`Android Killer`打开附件解压缩后的文件`easyapk.apk`，`APK`源码反编译完成后可以在`MainActivity.smali`中看到特殊字符串`flag{a57d0c9964f0b16bd42fb7eec0468e37}`。

------

### [Baby_C#](https://ce.pwnthebox.com/challenges?type=2&id=113)

用 `file`查看附件`rev3.exe`，可以看到信息`./rev3.exe: PE32 executable (GUI) Intel 80386 Mono/.Net assembly, for MS Windows`，用`dnSpy-net-win32`打开文件后，可以看到`FirstWPFAPP (1.0.0.0)`中的信息如下：

```csharp
// C:\Users\Don\Downloads\rev3.exe
// FirstWPFApp, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null

// 入口点: FirstWPFApp.App.Main
// 时间戳: <未知> (F1861506)

using System;
using System.Diagnostics;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Windows;

[assembly: AssemblyVersion("1.0.0.0")]
[assembly: CompilationRelaxations(8)]
[assembly: RuntimeCompatibility(WrapNonExceptionThrows = true)]
[assembly: Debuggable(DebuggableAttribute.DebuggingModes.IgnoreSymbolStoreSequencePoints)]
[assembly: AssemblyTitle("FirstWPFApp")]
[assembly: AssemblyDescription("")]
[assembly: AssemblyConfiguration("")]
[assembly: AssemblyCompany("")]
[assembly: AssemblyProduct("FirstWPFApp")]
[assembly: AssemblyCopyright("Copyright ©  2018")]
[assembly: AssemblyTrademark("")]
[assembly: ComVisible(false)]
[assembly: ThemeInfo(ResourceDictionaryLocation.None, ResourceDictionaryLocation.SourceAssembly)]
[assembly: AssemblyFileVersion("1.0.0.0")]
[assembly: TargetFramework(".NETFramework,Version=v4.6.1", FrameworkDisplayName = ".NET Framework 4.6.1")]

```

在程序集资源管理器中查看`FirstWPFAPP`的`MainWindow.cs`可以看到以下源码：

```csharp
using System;
using System.CodeDom.Compiler;
using System.ComponentModel;
using System.Diagnostics;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Markup;

namespace FirstWPFApp
{
	// Token: 0x02000003 RID: 3
	public class MainWindow : Window, IComponentConnector
	{
		// Token: 0x06000004 RID: 4 RVA: 0x0000207E File Offset: 0x0000027E
		public MainWindow()
		{
			this.InitializeComponent();
		}

		// Token: 0x06000005 RID: 5 RVA: 0x0000209C File Offset: 0x0000029C
		private void Button_Click(object sender, RoutedEventArgs e)
		{
			string value = new string(new char[]
			{
				this.Letters[5],
				this.Letters[14],
				this.Letters[13],
				this.Letters[25],
				this.Letters[24]
			});
			if (this.TextBox1.Text.Equals(value))
			{
				MessageBox.Show(new string(new char[]
				{
					this.Letters[5],
					this.Letters[11],
					this.Letters[0],
					this.Letters[6],
					this.Letters[26],
					this.Letters[8],
					this.Letters[28],
					this.Letters[11],
					this.Letters[14],
					this.Letters[21],
					this.Letters[4],
					this.Letters[28],
					this.Letters[5],
					this.Letters[14],
					this.Letters[13],
					this.Letters[25],
					this.Letters[24],
					this.Letters[27]
				}));
			}
		}

		// Token: 0x06000006 RID: 6 RVA: 0x000021F4 File Offset: 0x000003F4
		[DebuggerNonUserCode]
		[GeneratedCode("PresentationBuildTasks", "4.0.0.0")]
		public void InitializeComponent()
		{
			if (this._contentLoaded)
			{
				return;
			}
			this._contentLoaded = true;
			Uri resourceLocator = new Uri("/FirstWPFApp;component/mainwindow.xaml", UriKind.Relative);
			Application.LoadComponent(this, resourceLocator);
		}

		// Token: 0x06000007 RID: 7 RVA: 0x00002224 File Offset: 0x00000424
		[DebuggerNonUserCode]
		[GeneratedCode("PresentationBuildTasks", "4.0.0.0")]
		[EditorBrowsable(EditorBrowsableState.Never)]
		void IComponentConnector.Connect(int connectionId, object target)
		{
			if (connectionId == 1)
			{
				this.TextBox1 = (TextBox)target;
				return;
			}
			if (connectionId != 2)
			{
				this._contentLoaded = true;
				return;
			}
			this.Button1 = (Button)target;
			this.Button1.Click += this.Button_Click;
		}

		// Token: 0x04000001 RID: 1
		public char[] Letters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ{}_".ToCharArray();

		// Token: 0x04000002 RID: 2
		internal TextBox TextBox1;

		// Token: 0x04000003 RID: 3
		internal Button Button1;

		// Token: 0x04000004 RID: 4
		private bool _contentLoaded;
	}
}
```

根据`Button_Click()`函数中的代码逻辑，编写`Python`代码运行即可得到`FLAG{I_LOVE_FONZY}`，这就是本题需要提交的`flag`。

```python
Letters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ{}_'
l = [5, 11, 0, 6, 26, 8, 28, 11, 14, 21, 4, 28, 5, 14, 13, 25, 24, 27]
flag = ''
for i in l:
    flag += Letters[i]
print(flag) # FLAG{I_LOVE_FONZY}
```

------

### [Base_re](https://ce.pwnthebox.com/challenges?type=2&id=105)

用 `file`查看附件`base_re`，可以看到信息`./base_re: ELF 32-bit LSB pie executable, Intel 80386`，用`IDA Pro 32bit`打开文件后，按`Shift + F12`查看`Strings window`，发现关键字符串`you flag is %s\n`，双击可以跳转到以下汇编语言代码：

```assembly
.rodata:00002000 ; ===========================================================================
.rodata:00002000
.rodata:00002000 ; Segment type: Pure data
.rodata:00002000 ; Segment permissions: Read
.rodata:00002000 _rodata         segment dword public 'CONST' use32
.rodata:00002000                 assume cs:_rodata
.rodata:00002000                 ;org 2000h
.rodata:00002000 unk_2000        db    3                 ; DATA XREF: LOAD:000000BC↑o
.rodata:00002001                 db    0
.rodata:00002002                 db    0
.rodata:00002003                 db    0
.rodata:00002004                 public _IO_stdin_used
.rodata:00002004 _IO_stdin_used  db    1                 ; DATA XREF: LOAD:000002DC↑o
.rodata:00002005                 db    0
.rodata:00002006                 db    2
.rodata:00002007                 db    0
.rodata:00002008 aZmxhz3tintljnj db 'ZmxhZ3tiNTljNjdiZjE5NmE0NzU4MTkxZTQyZjc2NjcwY2ViYX0=',0
.rodata:00002008                                         ; DATA XREF: .data:off_4034↓o
.rodata:0000203D                 align 10h
.rodata:00002040 aAbcdefghijklmn db 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/',0
.rodata:00002040                                         ; DATA XREF: sub_11F9+12↑o
.rodata:00002081                 align 4
.rodata:00002084 unk_2084        db  77h ; w             ; DATA XREF: sub_1404+7A↑o
.rodata:00002085                 db  65h ; e
.rodata:00002086                 db  6Ch ; l
.rodata:00002087                 db  63h ; c
.rodata:00002088                 db  6Fh ; o
.rodata:00002089                 db  6Dh ; m
.rodata:0000208A                 db  65h ; e
.rodata:0000208B                 db 0E2h
.rodata:0000208C                 db  80h
.rodata:0000208D                 db  94h
.rodata:0000208E                 db  58h ; X
.rodata:0000208F                 db  69h ; i
.rodata:00002090                 db  6Eh ; n
.rodata:00002091                 db  6Ah ; j
.rodata:00002092                 db  69h ; i
.rodata:00002093                 db  61h ; a
.rodata:00002094                 db  6Eh ; n
.rodata:00002095                 db  67h ; g
.rodata:00002096                 db  20h
.rodata:00002097                 db  74h ; t
.rodata:00002098                 db  72h ; r
.rodata:00002099                 db  61h ; a
.rodata:0000209A                 db  69h ; i
.rodata:0000209B                 db  6Eh ; n
.rodata:0000209C                 db  69h ; i
.rodata:0000209D                 db  6Eh ; n
.rodata:0000209E                 db  67h ; g
.rodata:0000209F                 db 0EFh
.rodata:000020A0                 db 0BCh
.rodata:000020A1                 db  81h
.rodata:000020A2                 db    0
.rodata:000020A3 aPleasGiveMeYou db 'pleas give me you key:',0
.rodata:000020A3                                         ; DATA XREF: sub_1404+8C↑o
.rodata:000020BA aS              db '%s',0               ; DATA XREF: sub_1404+A2↑o
.rodata:000020BD aYouKeyIsWrong  db 'you key is wrong!',0
.rodata:000020BD                                         ; DATA XREF: sub_1404+C8↑o
.rodata:000020BD                                         ; sub_1404+136↑o
.rodata:000020CF aYouFlagIsS     db 'you flag is %s',0Ah,0
.rodata:000020CF                                         ; DATA XREF: sub_1404+11A↑o
.rodata:000020CF _rodata         ends
```

编写`Python`代码来对特殊字符串`ZmxhZ3tiNTljNjdiZjE5NmE0NzU4MTkxZTQyZjc2NjcwY2ViYX0=`进行`base64`解码：

```python
from base64 import *

flag = b64decode('ZmxhZ3tiNTljNjdiZjE5NmE0NzU4MTkxZTQyZjc2NjcwY2ViYX0=').decode('utf-8')
print(flag) # flag{b59c67bf196a4758191e42f76670ceba}
```

提交`flag{b59c67bf196a4758191e42f76670ceba}`即可。

------

## BUUCTF

### [easyre](https://buuoj.cn/challenges#easyre)

用`file`查看附件`easyre.exe`，可以看到信息`./easyre.exe: PE32+ executable (console) x86-64, for MS Windows`，用`IDA Pro 64bit`打开文件后，按`F5`反编译可以看到主函数的`C`语言代码如下：

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int b; // [rsp+28h] [rbp-8h] BYREF
  int a; // [rsp+2Ch] [rbp-4h] BYREF

  _main();
  scanf("%d%d", &a, &b);
  if ( a == b )
    printf("flag{this_Is_a_EaSyRe}");
  else
    printf("sorry,you can't get flag");
  return 0;
}
```

当用户输入两个相等的`int`型数值时，程序会给出本题的`flag`，提交`flag{this_Is_a_EaSyRe}`即可。

------

### [reverse1](https://buuoj.cn/challenges#reverse1)

用`file`查看附件`reverse_1.exe`，可以看到信息`./reverse_1.exe: PE32+ executable (console) x86-64, for MS Windows`，用`IDA Pro 64bit`打开文件后，按`shift+F12`查看`Strings window`，发现特殊字符串`this is the right flag!\n`，双击跳转到以下汇编语言`.rdata`段：

```assembly
.rdata:0000000140019C90 aThisIsTheRight db 'this is the right flag!',0Ah,0
.rdata:0000000140019C90                                         ; DATA XREF: sub_1400118C0:loc_140011996↑o
```

双击注释中的`sub_1400118C0`跳转到相应的汇编语言代码，按`F5`反编译可以看到该函数的`C`语言代码如下：

```c
__int64 sub_1400118C0()
{
  char *v0; // rdi
  __int64 i; // rcx
  size_t v2; // rax
  size_t v3; // rax
  char v5[36]; // [rsp+0h] [rbp-20h] BYREF
  int j; // [rsp+24h] [rbp+4h]
  char Str1[224]; // [rsp+48h] [rbp+28h] BYREF
  unsigned __int64 v8; // [rsp+128h] [rbp+108h]

  v0 = v5;
  for ( i = 82i64; i; --i )
  {
    *(_DWORD *)v0 = -858993460;
    v0 += 4;
  }
  for ( j = 0; ; ++j )
  {
    v8 = j;
    v2 = j_strlen(Str2);
    if ( v8 > v2 )
      break;
    if ( Str2[j] == 111 )  // 'o'
      Str2[j] = 48;   // '0'
  }
  sub_1400111D1("input the flag:");
  sub_14001128F("%20s", Str1);
  v3 = j_strlen(Str2);
  if ( !strncmp(Str1, Str2, v3) )
    sub_1400111D1("this is the right flag!\n");
  else
    sub_1400111D1("wrong flag\n");
  sub_14001113B(v5, &unk_140019D00);
  return 0i64;
}
```

当用户输入的字符串和字符串`Str2`相等时说明`flag`正确，双击`Str2`发现该字符串是`{hello_world}`，并且程序把该字符串中的小写字母`o`全部替换为数字`0`，提交`flag{hell0_w0rld}`即可。

------

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

------

### [内涵的软件](https://buuoj.cn/challenges#%E5%86%85%E6%B6%B5%E7%9A%84%E8%BD%AF%E4%BB%B6)

用 `file`查看附件`内涵的软件.exe`，可以看到信息`./内涵的软件.exe: PE32 executable (console) Intel 80386, for MS Windows`，用`IDA Pro 32bit`打开文件后，按`F5`反编译可以看到主函数的`C`语言代码如下：

```c
int __cdecl main_0(int argc, const char **argv, const char **envp)
{
  int result; // eax
  char v4[4]; // [esp+4Ch] [ebp-Ch] BYREF
  const char *v5; // [esp+50h] [ebp-8h]
  int v6; // [esp+54h] [ebp-4h]

  v6 = 5;
  v5 = "DBAPP{49d3c93df25caad81232130f3d2ebfad}";
  while ( v6 >= 0 )
  {
    printf(aD, v6);
    sub_40100A();
    --v6;
  }
  printf(
    "\n"
    "\n"
    "\n"
    "这里本来应该是答案的,但是粗心的程序员忘记把变量写进来了,你要不逆向试试看:(Y/N)\n");
  v4[0] = 1;
  scanf("%c", v4);
  if ( v4[0] == 89 )
  {
    printf(aOdIda);
    result = sub_40100A();
  }
  else
  {
    if ( v4[0] == 78 )
      printf(asc_425034);
    else
      printf("输入错误,没有提示.");
    result = sub_40100A();
  }
  return result;
}
```

好家伙，这题的`flag`就是`flag{49d3c93df25caad81232130f3d2ebfad}`。

------

### [新年快乐](https://buuoj.cn/challenges#%E6%96%B0%E5%B9%B4%E5%BF%AB%E4%B9%90)

用 `file`查看附件`新年快乐.exe`，可以看到信息`./新年快乐.exe: PE32 executable (console) Intel 80386, for MS Windows, UPX compressed`，使用命令行`upx -d 新年快乐.exe`进行脱壳，接着用`IDA Pro 32bit`打开文件后，按`F5`反编译可以看到主函数的`C`语言代码如下：

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int result; // eax
  char Str2[14]; // [esp+12h] [ebp-3Ah] BYREF
  __int16 Str1; // [esp+20h] [ebp-2Ch] BYREF
  _BYTE v6[30]; // [esp+22h] [ebp-2Ah] BYREF

  __main();
  strcpy(Str2, "HappyNewYear!");
  Str1 = 0;
  memset(v6, 0, sizeof(v6));
  printf("please input the true flag:");
  scanf("%s", &Str1);
  if ( !strncmp((const char *)&Str1, Str2, strlen(Str2)) )
    result = puts("this is true flag!");
  else
    result = puts("wrong!");
  return result;
}
```

当用户输入`HappyNewYear!`时程序会输出`this is true flag!`。根据题目描述，本题的`flag`就是`flag{HappyNewYear!}`，提交即可。

------

### [xor](https://buuoj.cn/challenges#xor)

用 `file`查看附件`xor`，可看到信息`./xor: Mach-O 64-bit x86_64 executable, flags:<NOUNDEFS|DYLDLINK|TWOLEVEL|PIE>`，用`IDA Pro 64bit`打开文件后，按`F5`反编译可以看到主函数的`C`语言代码如下：

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int i; // [rsp+2Ch] [rbp-124h]
  char __b[264]; // [rsp+40h] [rbp-110h] BYREF

  memset(__b, 0, 0x100uLL);
  printf("Input your flag:\n");
  get_line(__b, 256LL);
  if ( strlen(__b) != 33 )  // flag长度为33
    goto LABEL_7;
  for ( i = 1; i < 33; ++i )  // 异或操作
    __b[i] ^= __b[i - 1];
  if ( !strncmp(__b, global, 0x21uLL) )
    printf("Success");
  else
LABEL_7:
    printf("Failed");
  return 0;
}
```

双击`global`变量可以看到一串字符串，但是这串字符串并没有`33`个。

```assembly
__data:0000000100001050 _global         dq offset aFKWOXZUPFVMDGH
__data:0000000100001050                                  ; DATA XREF: _main+10D↑r
__data:0000000100001050 __data          ends             ; "f\nk\fw&O.@\x11x\rZ;U\x11p\x19F\x1Fv\"M"...
```

双击注释中的`"f\nk\fw&O.@\x11x\rZ;U\x11p\x19F\x1Fv\"M"...`可以精确定位到以下信息：

```assembly
__cstring:0000000100000F6E aFKWOXZUPFVMDGH db 'f',0Ah              ; DATA XREF: __data:_global↓o
__cstring:0000000100000F6E                 db 'k',0Ch,'w&O.@',11h,'x',0Dh,'Z;U',11h,'p',19h,'F',1Fh,'v"M#D',0Eh,'g'
__cstring:0000000100000F6E                 db 6,'h',0Fh,'G2O',0
```

根据程序逻辑，编写`Python`代码运行后得到`flag{QianQiuWanDai_YiTongJiangHu}`，提交即可。

```python
l = ['f',0xA,'k',0xC,'w','&','O','.','@',0x11,'x',0xD,'Z',';','U',0x11,'p',0x19,'F',0x1F,'v','"','M','#','D',0xE,'g',6,'h',0xF,'G','2','O']
for i in range(1, len(l)):
    if(isinstance(l[i], int)):
        l[i] = chr(l[i])
flag = 'f'
for i in range(1, len(l)):
    flag += chr(ord(l[i]) ^ ord(l[i-1]))
print(flag) # flag{QianQiuWanDai_YiTongJiangHu}
```

------

